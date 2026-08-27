/* ================================================================
   EA — Serveur d'abonnement
   Zéro dépendance externe (aucun `npm install` requis — le client
   Supabase est fait maison avec `fetch`, disponible nativement
   depuis Node 18).

   STOCKAGE : deux modes, choisis automatiquement selon la config —
     - Supabase (Postgres gratuit, externe à Render) si SUPABASE_URL
       et SUPABASE_SERVICE_KEY sont définis : les données survivent
       à TOUS les redéploiements, recommandé pour la production.
     - Fichier JSON local sinon (mode dev/test uniquement — ne
       survit PAS à un redéploiement sur le plan gratuit Render).

   DÉMARRAGE : node server.js
   Variables d'environnement :
     - ADMIN_PASSWORD : mot de passe du panneau d'admin (à changer !)
     - SUPABASE_URL, SUPABASE_SERVICE_KEY : voir README.md
     - PORT : imposé automatiquement par la plupart des hébergeurs
================================================================= */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-moi-absolument';
const PORT = process.env.PORT || 3000;
const TRIAL_DAYS = 7;
const PLAN_DURATIONS = { monthly: 30, semestrial: 180, annual: 365 }; // en jours
const FORMULAS = ['simple', 'complet', 'prive']; // du plus petit au plus grand

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const USE_SUPABASE = !!(SUPABASE_URL && SUPABASE_KEY);

/* ================================================================
   NOTIFICATIONS PUSH (Web Push / VAPID) — zéro dépendance, comme le
   reste du serveur. Implémentation "maison" du protocole standard
   (RFC 8291 aes128gcm + VAPID) avec le seul module natif `crypto`.

   Une seule clé à retenir : VAPID_PRIVATE_KEY (scalaire privé P-256,
   32 octets en base64url). La clé publique s'en déduit à chaque
   démarrage. Si elle n'est pas définie, une paire est générée au
   hasard à chaque démarrage — pratique pour tester tout de suite,
   mais ATTENTION : ça invalide tous les abonnements existants à
   chaque redéploiement. Pour la production, générez-en une une fois
   (le message au démarrage en propose une) et fixez-la en variable
   d'environnement pour qu'elle ne bouge plus jamais.
================================================================= */
function b64uToBuf(s) { s = (s || '').replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }
function bufToB64u(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

let VAPID_PRIVATE_SCALAR, VAPID_PUBLIC_RAW;
(function initVapid() {
  const fromEnv = process.env.VAPID_PRIVATE_KEY;
  let scalar;
  if (fromEnv) {
    scalar = b64uToBuf(fromEnv);
  } else {
    scalar = crypto.randomBytes(32);
    console.warn('[push] VAPID_PRIVATE_KEY absente — clé générée aléatoirement pour cette session uniquement.');
    console.warn('[push] Les abonnements aux notifications seront perdus à chaque redémarrage tant que ce n\'est pas fixé.');
    console.warn(`[push] Ajoutez cette variable d'environnement pour la rendre permanente : VAPID_PRIVATE_KEY=${bufToB64u(scalar)}`);
  }
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(scalar);
  VAPID_PRIVATE_SCALAR = scalar;
  VAPID_PUBLIC_RAW = ecdh.getPublicKey(); // 65 octets, format non-compressé (0x04 || X || Y)
})();
const VAPID_PUBLIC_KEY_B64U = bufToB64u(VAPID_PUBLIC_RAW);
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:contact@example.com';

function getVapidPrivateKeyObject() {
  const x = VAPID_PUBLIC_RAW.slice(1, 33), y = VAPID_PUBLIC_RAW.slice(33, 65);
  return crypto.createPrivateKey({
    key: { kty: 'EC', crv: 'P-256', d: bufToB64u(VAPID_PRIVATE_SCALAR), x: bufToB64u(x), y: bufToB64u(y) },
    format: 'jwk',
  });
}
function buildVapidAuthHeader(endpointUrl) {
  const origin = new URL(endpointUrl).origin;
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud: origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT };
  const signingInput = `${bufToB64u(Buffer.from(JSON.stringify(header)))}.${bufToB64u(Buffer.from(JSON.stringify(payload)))}`;
  const sig = crypto.sign('sha256', Buffer.from(signingInput), { key: getVapidPrivateKeyObject(), dsaEncoding: 'ieee-p1363' });
  return `vapid t=${signingInput}.${bufToB64u(sig)}, k=${VAPID_PUBLIC_KEY_B64U}`;
}

// HKDF-Expand (RFC 5869) à un seul bloc — suffisant ici, on ne dérive jamais plus de 32 octets.
function hkdfExpand(prk, info, length) {
  return crypto.createHmac('sha256', prk).update(Buffer.concat([info, Buffer.from([1])])).digest().slice(0, length);
}

// Chiffrement du payload selon RFC 8291 (aes128gcm) — c'est ce que fait la lib `web-push`
// en interne ; on le refait à la main pour rester sans dépendance npm.
function encryptPushPayload(sub, payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const uaPublic = b64uToBuf(sub.p256dh);
  const authSecret = b64uToBuf(sub.auth);

  const localEcdh = crypto.createECDH('prime256v1');
  localEcdh.generateKeys();
  const asPublic = localEcdh.getPublicKey();
  const ecdhSecret = localEcdh.computeSecret(uaPublic);

  const prkKey = crypto.createHmac('sha256', authSecret).update(ecdhSecret).digest();
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0', 'utf8'), uaPublic, asPublic]);
  const ikm = hkdfExpand(prkKey, keyInfo, 32);

  const salt = crypto.randomBytes(16);
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const cek = hkdfExpand(prk, Buffer.from('Content-Encoding: aes128gcm\0', 'utf8'), 16);
  const nonce = hkdfExpand(prk, Buffer.from('Content-Encoding: nonce\0', 'utf8'), 12);

  const plaintext = Buffer.concat([payload, Buffer.from([0x02])]); // 0x02 = dernier (et unique) enregistrement
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const recordSize = Buffer.alloc(4); recordSize.writeUInt32BE(4096, 0);
  const header = Buffer.concat([salt, recordSize, Buffer.from([asPublic.length]), asPublic]);
  return Buffer.concat([header, body]);
}

async function sendWebPush(sub, payloadObj, ttlSeconds = 3600) {
  const body = encryptPushPayload(sub, payloadObj);
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream',
      'Content-Length': String(body.length), 'TTL': String(ttlSeconds),
      'Authorization': buildVapidAuthHeader(sub.endpoint), 'Urgency': 'normal',
    },
    body,
  });
}

// Prévient tous les abonnés (sauf l'auteur) qu'un nouveau pari vient d'être publié —
// SANS révéler le pari lui-même, juste que quelque chose est disponible, pour donner
// envie d'ouvrir l'appli. Best-effort : une notification qui échoue (abonnement expiré,
// navigateur fermé pour de bon...) ne doit jamais faire échouer la publication elle-même.
async function notifyCommunityPublish(nameA, nameB, excludePhone) {
  try {
    const subs = await pushStore.listSubscriptions();
    const payload = {
      title: '🌐 Nouveau pari disponible',
      body: `${nameA} vs ${nameB} — un pari vient d'être publié dans Communauté`,
      tag: 'ea-community-publish', url: './',
    };
    await Promise.allSettled(subs.filter(s => s.phone !== excludePhone).map(s =>
      sendWebPush(s, payload).then(async (r) => {
        if (r.status === 404 || r.status === 410) await pushStore.deleteSubscription(s.endpoint);
      }).catch(() => {})
    ));
  } catch (e) { console.error('[push] notifyCommunityPublish a échoué :', e.message); }
}

// Prévient l'AUTEUR (uniquement lui, sur tous ses appareils) que le résultat réel de son
// analyse vient d'être enregistré — comme SofaScore notifie un score final. On donne le
// score et le nombre de paris gagnés tout de suite, pas besoin d'ouvrir l'appli pour savoir.
async function notifyAnalysisVerified(authorPhone, nameA, nameB, finalScore, correctBets, totalBets, exactScoreHit) {
  try {
    const subs = await pushStore.listSubscriptions();
    const mine = subs.filter(s => s.phone === authorPhone);
    if (!mine.length) return;
    const scoreLabel = (finalScore && finalScore.a != null && finalScore.b != null) ? `${finalScore.a}-${finalScore.b}` : '';
    const bits = [`Score final ${scoreLabel}`, `${correctBets}/${totalBets} pari(s) gagné(s)`];
    if (exactScoreHit) bits.push('score exact trouvé 🎯');
    const payload = {
      title: '✅ Résultat confirmé', body: `${nameA} vs ${nameB} — ${bits.join(' · ')}`,
      tag: 'ea-analysis-verified', url: './',
    };
    await Promise.allSettled(mine.map(s =>
      sendWebPush(s, payload).then(async (r) => {
        if (r.status === 404 || r.status === 410) await pushStore.deleteSubscription(s.endpoint);
      }).catch(() => {})
    ));
  } catch (e) { console.error('[push] notifyAnalysisVerified a échoué :', e.message); }
}

/* ================================================================
   COUCHE DE STOCKAGE — même interface (getUser/insertUser/updateUser/
   listUsers) quel que soit le backend, pour que le reste du code
   n'ait jamais à savoir lequel est actif.
================================================================= */
let store;
let trackStore;
let communityStore;
let pushStore;

if (USE_SUPABASE) {
  console.log('[DB] Mode Supabase actif — les données sont persistantes.');
  const REST = `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1`;
  const HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type': 'application/json',
  };
  // Conversion snake_case (colonnes Postgres) <-> camelCase (reste du code)
  function rowToUser(r) {
    if (!r) return null;
    return {
      phone: r.phone, name: r.name, salt: r.salt, pinHash: r.pin_hash,
      token: r.token, createdAt: Number(r.created_at), trialEndsAt: Number(r.trial_ends_at),
      subscription: r.subscription || null, pendingRequest: r.pending_request || null,
      pseudo: r.pseudo || null, xp: r.xp || 0, analysesCount: r.analyses_count || 0,
    };
  }
  function userToRow(u) {
    return {
      phone: u.phone, name: u.name, salt: u.salt, pin_hash: u.pinHash,
      token: u.token, created_at: u.createdAt, trial_ends_at: u.trialEndsAt,
      subscription: u.subscription, pending_request: u.pendingRequest || null,
      pseudo: u.pseudo || null, xp: u.xp || 0, analyses_count: u.analysesCount || 0,
    };
  }
  store = {
    async getUser(phone) {
      const r = await fetch(`${REST}/users?phone=eq.${encodeURIComponent(phone)}&select=*`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase getUser: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rowToUser(rows[0]);
    },
    async insertUser(user) {
      const r = await fetch(`${REST}/users`, {
        method: 'POST', headers: { ...HEADERS, 'Prefer': 'return=representation' },
        body: JSON.stringify(userToRow(user)),
      });
      if (!r.ok) throw new Error(`Supabase insertUser: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rowToUser(rows[0]);
    },
    async updateUser(phone, patch) {
      const row = {};
      if ('subscription' in patch) row.subscription = patch.subscription;
      if ('pendingRequest' in patch) row.pending_request = patch.pendingRequest;
      if ('token' in patch) row.token = patch.token;
      if ('pseudo' in patch) row.pseudo = patch.pseudo;
      const r = await fetch(`${REST}/users?phone=eq.${encodeURIComponent(phone)}`, {
        method: 'PATCH', headers: { ...HEADERS, 'Prefer': 'return=representation' },
        body: JSON.stringify(row),
      });
      if (!r.ok) throw new Error(`Supabase updateUser: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rowToUser(rows[0]);
    },
    async listUsers() {
      const r = await fetch(`${REST}/users?select=*&order=created_at.desc`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase listUsers: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(rowToUser);
    },
    // Incrément atomique côté Postgres (RPC) pour éviter les pertes de points en cas
    // d'appels concurrents ; si la fonction RPC n'est pas installée, on retombe sur un
    // read-then-write classique (rare en pratique, largement suffisant pour ce volume).
    async incrementUserStats(phone, { xpDelta = 0, analysesDelta = 0 }) {
      const rpc = await fetch(`${REST}/rpc/increment_user_stats`, {
        method: 'POST', headers: HEADERS,
        body: JSON.stringify({ p_phone: phone, p_xp_delta: xpDelta, p_analyses_delta: analysesDelta }),
      });
      if (rpc.ok) return;
      // Repli si la fonction RPC n'est pas installée côté Supabase (voir supabase-setup.sql)
      const u = await this.getUser(phone); if (!u) return;
      const row = { xp: (u.xp || 0) + xpDelta, analyses_count: (u.analysesCount || 0) + analysesDelta };
      await fetch(`${REST}/users?phone=eq.${encodeURIComponent(phone)}`, { method: 'PATCH', headers: HEADERS, body: JSON.stringify(row) });
    },
    async topUsers(limit = 50) {
      const r = await fetch(`${REST}/users?select=phone,name,pseudo,xp,analyses_count&order=xp.desc&limit=${limit}`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase topUsers: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(r2 => ({ phone: r2.phone, pseudo: r2.pseudo || r2.name || 'Anonyme', xp: r2.xp || 0, analysesCount: r2.analyses_count || 0 }));
    },
  };

  // Entrées de match partagées (moteur de calibration commun à tous les utilisateurs)
  trackStore = {
    async pushEntry(entry) {
      const row = {
        sport: entry.sport, league: entry.league || '', name_a: entry.nameA, name_b: entry.nameB,
        timestamp: entry.timestamp, evaluations: entry.evaluations, lambda_a: entry.lambdaA, lambda_b: entry.lambdaB,
        final_score: entry.finalScore, final_stats: entry.finalStats || null, stage: entry.stage || null,
        leg: entry.leg || null, tension_used: entry.tensionUsed, agg_factor_used: entry.aggFactorUsed || null,
        agg_diff: entry.aggDiff || 0, components: entry.components || null,
      };
      const r = await fetch(`${REST}/track_entries`, { method: 'POST', headers: HEADERS, body: JSON.stringify(row) });
      if (!r.ok) throw new Error(`Supabase pushEntry: ${r.status} ${await r.text()}`);
    },
    async listEntries(sport) {
      const r = await fetch(`${REST}/track_entries?sport=eq.${encodeURIComponent(sport)}&select=*`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase listEntries: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(row => ({
        league: row.league, nameA: row.name_a, nameB: row.name_b, timestamp: row.timestamp,
        evaluations: row.evaluations, lambdaA: row.lambda_a, lambdaB: row.lambda_b, finalScore: row.final_score,
        finalStats: row.final_stats, stage: row.stage, leg: row.leg, tensionUsed: row.tension_used,
        aggFactorUsed: row.agg_factor_used, aggDiff: row.agg_diff, components: row.components,
      }));
    },
  };

  function rowToAnalysis(r) {
    return {
      id: r.id, authorPhone: r.author_phone, authorPseudo: r.author_pseudo, sport: r.sport, league: r.league,
      nameA: r.name_a, nameB: r.name_b, stage: r.stage, leg: r.leg, lambdaA: r.lambda_a, lambdaB: r.lambda_b,
      topScores: r.top_scores, bets: r.bets, contextSentence: r.context_sentence, convictionIdx: r.conviction_idx || 0, timestamp: r.timestamp,
      finalScore: r.final_score, evaluations: r.evaluations, verifiedAt: r.verified_at,
    };
  }
  communityStore = {
    async publish(entry) {
      const row = {
        author_phone: entry.authorPhone, author_pseudo: entry.authorPseudo, sport: entry.sport, league: entry.league || '',
        name_a: entry.nameA, name_b: entry.nameB, slug_a: entry.slugA, slug_b: entry.slugB,
        stage: entry.stage || null, leg: entry.leg || null, lambda_a: entry.lambdaA, lambda_b: entry.lambdaB,
        top_scores: entry.topScores, bets: entry.bets, context_sentence: entry.contextSentence || '',
        conviction_idx: entry.convictionIdx || 0, timestamp: entry.timestamp,
      };
      const r = await fetch(`${REST}/community_analyses`, { method: 'POST', headers: { ...HEADERS, 'Prefer': 'return=representation' }, body: JSON.stringify(row) });
      if (!r.ok) throw new Error(`Supabase publish: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rowToAnalysis(rows[0]);
    },
    async search(slugA, slugB, sport, page, perPage) {
      const offset = page * perPage;
      // Ordre indifférent : A-vs-B publié par quelqu'un OU B-vs-A publié par quelqu'un d'autre doivent tous deux remonter.
      // IMPORTANT : PostgREST exige le préfixe "and=" pour un filtre logique composé — sans lui,
      // Supabase ignorait silencieusement le filtre entier et renvoyait TOUTE la table (bug corrigé ici).
      const filter = `and=(sport.eq.${sport},or(and(slug_a.eq.${slugA},slug_b.eq.${slugB}),and(slug_a.eq.${slugB},slug_b.eq.${slugA})))`;
      const r = await fetch(`${REST}/community_analyses?${filter}&order=timestamp.desc&limit=${perPage}&offset=${offset}`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase search: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(rowToAnalysis);
    },
    async feed(sport, page, perPage) {
      const r = await fetch(`${REST}/community_analyses?sport=eq.${encodeURIComponent(sport)}&order=timestamp.desc&limit=${perPage}&offset=${page * perPage}`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase feed: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(rowToAnalysis);
    },
    async markVerified(id, finalScore, evaluations) {
      const r = await fetch(`${REST}/community_analyses?id=eq.${id}`, {
        method: 'PATCH', headers: { ...HEADERS, 'Prefer': 'return=representation' },
        body: JSON.stringify({ final_score: finalScore, evaluations, verified_at: Date.now() }),
      });
      if (!r.ok) throw new Error(`Supabase markVerified: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rowToAnalysis(rows[0]);
    },
    async getById(id) {
      const r = await fetch(`${REST}/community_analyses?id=eq.${id}&select=*`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase getById: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows[0] ? rowToAnalysis(rows[0]) : null;
    },
    async listVerified(sport, limit = 500) {
      const r = await fetch(`${REST}/community_analyses?sport=eq.${encodeURIComponent(sport)}&verified_at=not.is.null&select=evaluations&order=verified_at.desc&limit=${limit}`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase listVerified: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(row => ({ evaluations: row.evaluations || [] }));
    },
  };

  // Abonnements aux notifications push (Web Push). Une ligne par appareil/navigateur
  // abonné — un même utilisateur peut avoir plusieurs abonnements (téléphone + PC).
  pushStore = {
    async saveSubscription(phone, endpoint, p256dh, auth) {
      const row = { phone, endpoint, p256dh, auth, created_at: Date.now() };
      const r = await fetch(`${REST}/push_subscriptions?on_conflict=endpoint`, {
        method: 'POST', headers: { ...HEADERS, 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify(row),
      });
      if (!r.ok) throw new Error(`Supabase saveSubscription: ${r.status} ${await r.text()}`);
    },
    async deleteSubscription(endpoint) {
      const r = await fetch(`${REST}/push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, { method: 'DELETE', headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase deleteSubscription: ${r.status} ${await r.text()}`);
    },
    async listSubscriptions() {
      const r = await fetch(`${REST}/push_subscriptions?select=*`, { headers: HEADERS });
      if (!r.ok) throw new Error(`Supabase listSubscriptions: ${r.status} ${await r.text()}`);
      const rows = await r.json();
      return rows.map(row => ({ phone: row.phone, endpoint: row.endpoint, p256dh: row.p256dh, auth: row.auth }));
    },
  };
} else {
  console.warn('[DB] Mode fichier local (SUPABASE_URL/SUPABASE_SERVICE_KEY non configurés).');
  console.warn('[DB] ATTENTION : sur le plan gratuit Render, ces données seront PERDUES au prochain redéploiement. Voir README.md.');
  const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'db.json');
  let db = { users: {}, track: { football: [], basketball: [] }, community: [], nextCommunityId: 1 };
  if (fs.existsSync(DB_FILE)) {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error('DB illisible, démarrage à vide :', e.message); }
    if (!db.track) db.track = { football: [], basketball: [] };
    if (!db.community) db.community = [];
    if (!db.nextCommunityId) db.nextCommunityId = 1;
  }
  let writeQueue = Promise.resolve();
  function saveDB() {
    writeQueue = writeQueue.then(() => new Promise((resolve) => {
      const tmpFile = DB_FILE + '.tmp';
      fs.writeFile(tmpFile, JSON.stringify(db, null, 2), (err) => {
        if (err) { console.error('Erreur écriture DB :', err.message); return resolve(); }
        fs.rename(tmpFile, DB_FILE, (err2) => { if (err2) console.error('Erreur renommage DB :', err2.message); resolve(); });
      });
    }));
    return writeQueue;
  }
  store = {
    async getUser(phone) { return db.users[phone] || null; },
    async insertUser(user) { db.users[user.phone] = { xp: 0, analysesCount: 0, pseudo: null, ...user }; await saveDB(); return db.users[user.phone]; },
    async updateUser(phone, patch) {
      const u = db.users[phone]; if (!u) return null;
      Object.assign(u, patch); await saveDB(); return u;
    },
    async listUsers() { return Object.values(db.users); },
    async incrementUserStats(phone, { xpDelta = 0, analysesDelta = 0 }) {
      const u = db.users[phone]; if (!u) return;
      u.xp = (u.xp || 0) + xpDelta;
      u.analysesCount = (u.analysesCount || 0) + analysesDelta;
      await saveDB();
    },
    async topUsers(limit = 50) {
      return Object.values(db.users)
        .map(u => ({ phone: u.phone, pseudo: u.pseudo || u.name || 'Anonyme', xp: u.xp || 0, analysesCount: u.analysesCount || 0 }))
        .sort((a, b) => b.xp - a.xp)
        .slice(0, limit);
    },
  };
  trackStore = {
    async pushEntry(entry) {
      if (!db.track[entry.sport]) db.track[entry.sport] = [];
      db.track[entry.sport].push(entry);
      await saveDB();
    },
    async listEntries(sport) { return db.track[sport] || []; },
  };
  communityStore = {
    async publish(entry) {
      const row = { id: db.nextCommunityId++, finalScore: null, evaluations: null, verifiedAt: null, ...entry };
      db.community.push(row);
      await saveDB();
      return row;
    },
    async search(slugA, slugB, sport, page, perPage) {
      const matches = db.community.filter(r => r.sport === sport &&
        ((r.slugA === slugA && r.slugB === slugB) || (r.slugA === slugB && r.slugB === slugA)));
      matches.sort((a, b) => b.timestamp - a.timestamp);
      return matches.slice(page * perPage, page * perPage + perPage);
    },
    async feed(sport, page, perPage) {
      const matches = db.community.filter(r => r.sport === sport).sort((a, b) => b.timestamp - a.timestamp);
      return matches.slice(page * perPage, page * perPage + perPage);
    },
    async markVerified(id, finalScore, evaluations) {
      const row = db.community.find(r => r.id === id); if (!row) return null;
      row.finalScore = finalScore; row.evaluations = evaluations; row.verifiedAt = Date.now();
      await saveDB();
      return row;
    },
    async getById(id) { return db.community.find(r => r.id === id) || null; },
    async listVerified(sport, limit = 500) {
      return db.community.filter(r => r.sport === sport && r.verifiedAt).slice(-limit).map(r => ({ evaluations: r.evaluations || [] }));
    },
  };

  if (!db.pushSubscriptions) db.pushSubscriptions = [];
  pushStore = {
    async saveSubscription(phone, endpoint, p256dh, auth) {
      const existing = db.pushSubscriptions.find(s => s.endpoint === endpoint);
      if (existing) { existing.phone = phone; existing.p256dh = p256dh; existing.auth = auth; }
      else db.pushSubscriptions.push({ phone, endpoint, p256dh, auth, createdAt: Date.now() });
      await saveDB();
    },
    async deleteSubscription(endpoint) {
      db.pushSubscriptions = db.pushSubscriptions.filter(s => s.endpoint !== endpoint);
      await saveDB();
    },
    async listSubscriptions() { return db.pushSubscriptions; },
  };
}

/* ---------- Utilitaires ---------- */
function normalizePhone(p) { return (p || '').toString().replace(/[^0-9+]/g, '').trim(); }
function slugifyTeam(name) {
  return (name || '').toString().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase().replace(/[^a-z0-9]+/g, '').trim();
}
function hashPin(pin, salt) { return crypto.scryptSync(pin, salt, 64).toString('hex'); }
function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function now() { return Date.now(); }
function daysMs(n) { return n * 24 * 60 * 60 * 1000; }

function computeStatus(user) {
  const t = now();
  if (user.subscription && user.subscription.expiresAt > t) {
    return {
      status: 'active', plan: user.subscription.plan,
      formula: user.subscription.formula || 'complet', // rétro-compat comptes activés avant l'ajout des formules
      sport: user.subscription.formula === 'simple' ? (user.subscription.sport || 'ge') : null,
      expiresAt: user.subscription.expiresAt,
    };
  }
  // Essai gratuit : accès complet aux deux disciplines + communauté, pour laisser
  // l'utilisateur découvrir tout ce que l'appli propose avant de choisir sa formule.
  if (user.trialEndsAt > t) { return { status: 'trial', formula: 'complet', sport: null, expiresAt: user.trialEndsAt }; }
  return {
    status: 'expired',
    formula: user.subscription ? (user.subscription.formula || 'complet') : 'complet',
    sport: user.subscription && user.subscription.formula === 'simple' ? (user.subscription.sport || 'ge') : null,
    expiresAt: user.subscription ? user.subscription.expiresAt : user.trialEndsAt,
  };
}

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

/* ---------- Routes ---------- */
async function handleRegister(req, res) {
  const body = await readBody(req);
  const phone = normalizePhone(body.phone);
  const pin = (body.pin || '').toString();
  const name = (body.name || '').toString().slice(0, 80);
  if (!phone || phone.length < 6) return sendJSON(res, 400, { error: 'Numéro invalide.' });
  if (!pin || pin.length < 4) return sendJSON(res, 400, { error: 'PIN trop court (4 chiffres minimum).' });
  if (await store.getUser(phone)) return sendJSON(res, 409, { error: 'Ce numéro a déjà un compte. Utilise la connexion.' });

  const salt = crypto.randomBytes(16).toString('hex');
  const user = {
    phone, name, salt, pinHash: hashPin(pin, salt),
    token: makeToken(), createdAt: now(),
    trialEndsAt: now() + daysMs(TRIAL_DAYS), subscription: null,
  };
  await store.insertUser(user);
  sendJSON(res, 200, { token: user.token, phone, ...computeStatus(user) });
}

async function handleLogin(req, res) {
  const body = await readBody(req);
  const phone = normalizePhone(body.phone);
  const pin = (body.pin || '').toString();
  const user = await store.getUser(phone);
  if (!user) return sendJSON(res, 404, { error: 'Aucun compte pour ce numéro.' });
  if (hashPin(pin, user.salt) !== user.pinHash) return sendJSON(res, 401, { error: 'PIN incorrect.' });
  sendJSON(res, 200, { token: user.token, phone, ...computeStatus(user) });
}

async function handleStatus(req, res, query) {
  const phone = normalizePhone(query.phone);
  const token = query.token;
  const user = await store.getUser(phone);
  if (!user || user.token !== token) return sendJSON(res, 401, { error: 'Session invalide.' });
  sendJSON(res, 200, { phone, ...computeStatus(user) });
}

async function handleAdminUsers(req, res) {
  const body = await readBody(req);
  if (body.adminPassword !== ADMIN_PASSWORD) return sendJSON(res, 401, { error: 'Mot de passe admin incorrect.' });
  const users = await store.listUsers();
  const list = users.map(u => ({ phone: u.phone, name: u.name, createdAt: u.createdAt, pendingRequest: u.pendingRequest || null, ...computeStatus(u) }))
    .sort((a, b) => b.createdAt - a.createdAt);
  sendJSON(res, 200, { users: list });
}

async function handleAdminActivate(req, res) {
  const body = await readBody(req);
  if (body.adminPassword !== ADMIN_PASSWORD) return sendJSON(res, 401, { error: 'Mot de passe admin incorrect.' });
  const phone = normalizePhone(body.phone);
  const plan = body.plan;
  const formula = FORMULAS.includes(body.formula) ? body.formula : 'complet';
  const sport = (formula === 'simple' && (body.sport === 'bk')) ? 'bk' : (formula === 'simple' ? 'ge' : null);
  const user = await store.getUser(phone);
  if (!user) return sendJSON(res, 404, { error: 'Aucun compte pour ce numéro.' });
  if (!PLAN_DURATIONS[plan]) return sendJSON(res, 400, { error: 'Durée invalide (monthly, semestrial ou annual).' });

  const base = (user.subscription && user.subscription.expiresAt > now()) ? user.subscription.expiresAt : now();
  const subscription = { plan, formula, sport, activatedAt: now(), expiresAt: base + daysMs(PLAN_DURATIONS[plan]) };
  // Une fois activée, la demande d'abonnement du client (si elle existe) est satisfaite — on l'efface.
  const updated = await store.updateUser(phone, { subscription, pendingRequest: null });
  sendJSON(res, 200, { phone, ...computeStatus(updated) });
}

/* Le client déclare ici la formule + la durée qu'il s'apprête à payer, AVANT même
   d'envoyer le paiement Wave. Ça n'active rien (le paiement doit toujours être
   vérifié manuellement) mais ça évite à l'administrateur de devoir demander au
   client par message quelle formule il a choisie : elle apparaît directement,
   en attente, dans le panneau d'admin. */
async function handleSubscribeRequest(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const formula = FORMULAS.includes(body.formula) ? body.formula : 'complet';
  const sport = (formula === 'simple' && body.sport === 'bk') ? 'bk' : (formula === 'simple' ? 'ge' : null);
  const plan = body.plan;
  if (!PLAN_DURATIONS[plan]) return sendJSON(res, 400, { error: 'Durée invalide (monthly, semestrial ou annual).' });
  const pendingRequest = { formula, sport, plan, requestedAt: now() };
  const updated = await store.updateUser(user.phone, { pendingRequest });
  sendJSON(res, 200, { ok: true, pendingRequest: updated.pendingRequest });
}

/* ================================================================
   MOTEUR DE CALIBRATION PARTAGÉ — chaque match vérifié par N'IMPORTE
   QUEL utilisateur alimente ce moteur commun, dont TOUS les
   utilisateurs profitent immédiatement (au lieu d'un moteur isolé
   par téléphone qui repartait de zéro à chaque nouvel abonné).
   Logique portée depuis l'appli cliente, appliquée ici aux données
   partagées de tous les utilisateurs.
================================================================= */
const ADAPTIVE_SOURCES = ['domicile', 'serie', 'h2h', 'defense_adverse'];
const DEFAULT_SOURCE_WEIGHTS = { domicile: .35, serie: .25, h2h: .25, defense_adverse: .15 };
const STAGE_TENSION_DEFAULTS = {
  football: { poules: 1.0, '32e': 1.0, '16e': 1.02, '8e': 1.04, quart: 1.07, demi: 1.11, finale: 1.16 },
  basketball: { poules: 1.0, '16e': 1.01, '8e': 1.02, quart: 1.035, demi: 1.05, finale: 1.07 },
};
const STAGE_MIN_N = 8, STAGE_SHRINK_K = 15, AGG_MIN_N = 8, AGG_SHRINK_K = 15, RECAL_MIN_N = 20;

async function verifyAuth(phone, token) {
  const user = await store.getUser(normalizePhone(phone));
  return (user && user.token === token) ? user : null;
}

function scopedEntries(all, league) {
  if (!league) return { entries: all, scoped: false };
  const filtered = all.filter(e => (e.league || '') === league);
  return filtered.length >= STAGE_MIN_N ? { entries: filtered, scoped: true } : { entries: all, scoped: false };
}

function buildPoissonMatrix(lambdaA, lambdaB, maxGoals, rho) {
  const poisson = (k, lam) => Math.exp(-lam) * Math.pow(lam, k) / factorial(k);
  const matrix = [];
  for (let a = 0; a <= maxGoals; a++) {
    for (let b = 0; b <= maxGoals; b++) {
      let p = poisson(a, lambdaA) * poisson(b, lambdaB);
      let tau = 1;
      if (a === 0 && b === 0) tau = 1 - lambdaA * lambdaB * rho;
      else if (a === 0 && b === 1) tau = 1 + lambdaA * rho;
      else if (a === 1 && b === 0) tau = 1 + lambdaB * rho;
      else if (a === 1 && b === 1) tau = 1 - rho;
      matrix.push({ a, b, p: p * tau });
    }
  }
  return matrix;
}
function factorial(n) { let r = 1; for (let i = 2; i <= n; i++) r *= i; return r; }

function computeRho(entries) {
  const usable = entries.filter(e => e.lambdaA != null && e.lambdaB != null && e.finalScore);
  if (usable.length < 30) return { rho: -0.1, calibrated: false, n: usable.length, needed: 30 };
  let bestRho = -0.1, bestErr = Infinity;
  for (let rho = -0.25; rho <= 0.001; rho += 0.01) {
    let err = 0;
    usable.forEach(e => {
      const matrix = buildPoissonMatrix(e.lambdaA, e.lambdaB, 8, rho);
      const cell = matrix.find(c => c.a === e.finalScore.a && c.b === e.finalScore.b);
      err += Math.pow(1 - (cell ? cell.p : 0), 2);
    });
    err /= usable.length;
    if (err < bestErr) { bestErr = err; bestRho = Math.round(rho * 100) / 100; }
  }
  return { rho: bestRho, calibrated: true, n: usable.length, brier: bestErr };
}

function computeSourceWeights(entries) {
  const perf = {}; ADAPTIVE_SOURCES.forEach(k => perf[k] = { hits: 0, n: 0 });
  entries.filter(e => e.components && e.finalScore).forEach(e => {
    [{ side: 'A', target: e.finalScore.a }, { side: 'B', target: e.finalScore.b }].forEach(({ side, target }) => {
      const errs = {};
      ADAPTIVE_SOURCES.forEach(k => { const v = e.components[k + side]; if (v != null && !isNaN(v)) errs[k] = Math.abs(v - target); });
      const keys = Object.keys(errs); if (keys.length === 0) return;
      const best = keys.reduce((a, b) => errs[a] <= errs[b] ? a : b);
      keys.forEach(k => { perf[k].n++; if (k === best) perf[k].hits++; });
    });
  });
  const totalN = ADAPTIVE_SOURCES.reduce((s, k) => s + perf[k].n, 0);
  if (totalN < 40) return { weights: { ...DEFAULT_SOURCE_WEIGHTS }, totalN, calibrated: false };
  const rates = ADAPTIVE_SOURCES.map(k => perf[k].n > 0 ? perf[k].hits / perf[k].n : 0.25);
  const sum = rates.reduce((a, b) => a + b, 0) || 1;
  const w = {}; ADAPTIVE_SOURCES.forEach((k, i) => { w[k] = Math.max(0.10, Math.min(0.55, rates[i] / sum)); });
  const wsum = Object.values(w).reduce((a, b) => a + b, 0);
  ADAPTIVE_SOURCES.forEach(k => w[k] = w[k] / wsum);
  return { weights: w, totalN, calibrated: true };
}

function marketTypeFromEval(evalSpec) {
  if (!evalSpec) return 'non_classe';
  switch (evalSpec.type) {
    case 'exactScore': case 'scoreBracket': return 'score_exact';
    case 'btts': return 'btts';
    case 'resultDC': return 'double_chance';
    case 'result1x2': case 'result2way': case 'marginBracket': return '1x2';
    case 'goalsLine': return 'over_under';
    case 'statLine': return evalSpec.stat === 'corners' ? 'stat_corners' : evalSpec.stat === 'shots' ? 'stat_shots' : 'non_classe';
    default: return 'non_classe';
  }
}
function computeCalibrationByMarket(entries) {
  const all = entries.flatMap(e => (e.evaluations || []).map(x => ({ ...x, marketType: x.marketType || 'non_classe' })));
  const verifiable = all.filter(x => x.hit !== null && x.hit !== undefined);
  if (!verifiable.length) return null;
  const byMarket = {};
  verifiable.forEach(x => { (byMarket[x.marketType] = byMarket[x.marketType] || []).push(x); });
  const out = {};
  Object.keys(byMarket).forEach(mt => {
    const list = byMarket[mt];
    const hitRate = list.filter(x => x.hit).length / list.length;
    const avgP = list.reduce((s, x) => s + x.p, 0) / list.length;
    const gap = Math.abs(hitRate - avgP) * 100;
    out[mt] = { n: list.length, hitRate, avgP, gap, wellCalibrated: gap < 5 };
  });
  return out;
}
function computeMarketRecalibration(globalEntries, leagueEntries) {
  const calibGlobal = computeCalibrationByMarket(globalEntries);
  const calibLeague = leagueEntries ? computeCalibrationByMarket(leagueEntries) : null;
  const out = {};
  if (!calibGlobal && !calibLeague) return out;
  const marketTypes = new Set([...Object.keys(calibGlobal || {}), ...Object.keys(calibLeague || {})]);
  marketTypes.forEach(mt => {
    const cL = calibLeague ? calibLeague[mt] : null;
    const cG = calibGlobal ? calibGlobal[mt] : null;
    const c = (cL && cL.n >= RECAL_MIN_N) ? cL : cG;
    if (c && c.n >= RECAL_MIN_N && c.avgP > 0) {
      out[mt] = { factor: Math.max(0.65, Math.min(1.10, c.hitRate / c.avgP)), n: c.n, gap: c.gap, scopedToLeague: c === cL };
    }
  });
  return out;
}

function computeStageTensions(entries, sport) {
  const defaults = STAGE_TENSION_DEFAULTS[sport] || STAGE_TENSION_DEFAULTS.football;
  const usable = entries.filter(e => e.stage && e.tensionUsed != null && e.finalScore);
  const byStage = {}; usable.forEach(e => (byStage[e.stage] = byStage[e.stage] || []).push(e));
  const blended = {}, counts = {};
  Object.keys(defaults).forEach(stage => {
    const list = byStage[stage] || []; counts[stage] = list.length;
    if (list.length < STAGE_MIN_N) { blended[stage] = defaults[stage]; return; }
    const implied = list.map(e => {
      const actualTotal = e.finalScore.a + e.finalScore.b;
      const preTensionSum = (e.lambdaA + e.lambdaB) * e.tensionUsed;
      if (actualTotal <= 0 || preTensionSum <= 0) return null;
      return Math.max(0.7, Math.min(1.6, preTensionSum / actualTotal));
    }).filter(v => v != null);
    if (implied.length < STAGE_MIN_N) { blended[stage] = defaults[stage]; return; }
    const observedAvg = implied.reduce((a, b) => a + b, 0) / implied.length;
    blended[stage] = (STAGE_SHRINK_K * defaults[stage] + implied.length * observedAvg) / (STAGE_SHRINK_K + implied.length);
  });
  return { tensions: blended, counts };
}

function computeAggSensitivity(entries) {
  const usable = entries.filter(e => e.leg === 'retour' && e.aggDiff && e.aggFactorUsed && e.finalScore);
  if (usable.length < AGG_MIN_N) return { sensitivity: 1.0, calibrated: false, n: usable.length };
  const implied = usable.map(e => {
    const trailingIsA = e.aggFactorUsed.factorA > 1;
    const factor = trailingIsA ? e.aggFactorUsed.factorA : e.aggFactorUsed.factorB;
    const bump = factor - 1; if (bump <= 0) return null;
    const preAggLambda = (trailingIsA ? e.lambdaA : e.lambdaB) / factor;
    const actual = trailingIsA ? e.finalScore.a : e.finalScore.b;
    if (preAggLambda <= 0) return null;
    return Math.max(0.3, Math.min(2.5, ((actual - preAggLambda) / preAggLambda) / bump));
  }).filter(v => v != null);
  if (implied.length < AGG_MIN_N) return { sensitivity: 1.0, calibrated: false, n: implied.length };
  const observedAvg = implied.reduce((a, b) => a + b, 0) / implied.length;
  const blended = (AGG_SHRINK_K * 1.0 + implied.length * observedAvg) / (AGG_SHRINK_K + implied.length);
  return { sensitivity: blended, calibrated: true, n: implied.length };
}

async function handleTrackPush(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const sport = body.sport;
  if (sport !== 'football' && sport !== 'basketball') return sendJSON(res, 400, { error: 'Sport invalide.' });
  const entry = body.entry || {};
  await trackStore.pushEntry({ sport, ...entry });
  sendJSON(res, 200, { ok: true });
}

async function handleCalibration(req, res, query) {
  const user = await verifyAuth(query.phone, query.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const sport = query.sport === 'basketball' ? 'basketball' : 'football';
  const league = (query.league || '').trim();
  const all = await trackStore.listEntries(sport);
  const { entries: leagueScoped, scoped } = scopedEntries(all, league);

  const rho = sport === 'football' ? computeRho(scoped ? leagueScoped : all) : null;
  const weightsResult = computeSourceWeights(scoped ? leagueScoped : all);
  const marketCalibration = computeMarketRecalibration(all, league ? leagueScoped : null);
  const stageResult = computeStageTensions(scoped ? leagueScoped : all, sport);
  const aggResult = computeAggSensitivity(scoped ? leagueScoped : all);

  sendJSON(res, 200, {
    sport, league, scopedToLeague: scoped, totalEntries: all.length,
    rho, weights: weightsResult.weights, weightsTotalN: weightsResult.totalN, weightsCalibrated: weightsResult.calibrated,
    marketCalibration, stageTensions: stageResult.tensions, stageCounts: stageResult.counts,
    aggSensitivity: aggResult.sensitivity, aggCalibrated: aggResult.calibrated, aggN: aggResult.n,
  });
}

async function handleLeagues(req, res, query) {
  const user = await verifyAuth(query.phone, query.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const sport = query.sport === 'basketball' ? 'basketball' : 'football';
  const all = await trackStore.listEntries(sport);
  const set = new Set();
  all.forEach(e => { if (e.league && e.league.trim()) set.add(e.league.trim()); });
  sendJSON(res, 200, { leagues: [...set].sort((a, b) => a.localeCompare(b)) });
}

/* ================================================================
   COMMUNAUTÉ — publication d'analyses, recherche partagée, XP,
   classement des contributeurs. Rien de tout ça ne sort vers une API
   externe : c'est un fil manuel alimenté uniquement par les utilisateurs
   de l'app entre eux, comme demandé.
================================================================= */
const XP_PUBLISH = 5;
const XP_PER_CORRECT_BET = 10;
const XP_EXACT_SCORE = 25;
const PAGE_SIZE = 10; // "5 pages" ≈ 50 résultats max raisonnables par recherche

async function handlePushVapidKey(req, res) {
  sendJSON(res, 200, { publicKey: VAPID_PUBLIC_KEY_B64U });
}

async function handlePushSubscribe(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const { endpoint, p256dh, auth } = body;
  if (!endpoint || !p256dh || !auth) return sendJSON(res, 400, { error: 'endpoint, p256dh et auth requis.' });
  await pushStore.saveSubscription(user.phone, endpoint, p256dh, auth);
  sendJSON(res, 200, { ok: true });
}

async function handlePushUnsubscribe(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  if (!body.endpoint) return sendJSON(res, 400, { error: 'endpoint requis.' });
  await pushStore.deleteSubscription(body.endpoint);
  sendJSON(res, 200, { ok: true });
}

async function handleCommunityPublish(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const { sport, league, nameA, nameB, stage, leg, lambdaA, lambdaB, topScores, bets, contextSentence, convictionIdx } = body;
  if (!sport || !nameA || !nameB) return sendJSON(res, 400, { error: 'sport, nameA et nameB requis.' });
  const pseudo = (user.pseudo || user.name || `Analyste ${user.phone.slice(-4)}`).slice(0, 40);

  const row = await communityStore.publish({
    authorPhone: user.phone, authorPseudo: pseudo, sport, league: league || '',
    nameA, nameB, slugA: slugifyTeam(nameA), slugB: slugifyTeam(nameB),
    stage: stage || null, leg: leg || null, lambdaA: lambdaA ?? null, lambdaB: lambdaB ?? null,
    topScores: topScores || [], bets: bets || [], contextSentence: contextSentence || '',
    convictionIdx: (typeof convictionIdx === 'number' && convictionIdx >= 0 && convictionIdx <= 1) ? convictionIdx : 0,
    timestamp: Date.now(),
  });
  await store.incrementUserStats(user.phone, { xpDelta: XP_PUBLISH, analysesDelta: 1 });
  notifyCommunityPublish(nameA, nameB, user.phone); // best-effort, ne bloque pas la réponse
  sendJSON(res, 200, { ok: true, analysis: row, xpEarned: XP_PUBLISH });
}

async function handleCommunitySearch(req, res, query) {
  const user = await verifyAuth(query.phone, query.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const sport = query.sport === 'basketball' ? 'basketball' : 'football';
  const nameA = query.teamA || '', nameB = query.teamB || '';
  if (!nameA || !nameB) return sendJSON(res, 400, { error: 'teamA et teamB requis.' });
  const page = Math.max(0, parseInt(query.page, 10) || 0);
  const results = await communityStore.search(slugifyTeam(nameA), slugifyTeam(nameB), sport, page, PAGE_SIZE);
  sendJSON(res, 200, { results, page, perPage: PAGE_SIZE, hasMore: results.length === PAGE_SIZE });
}

/* -- "Meilleurs Paris" communauté : ni un seuil brut (90%+), ni juste la probabilité la
   plus haute. On pondère chaque pari par la fiabilité RÉELLE de son type de marché, mesurée
   sur tout l'historique vérifié de la communauté (plus de monde = signal plus vite fiable
   que pour un seul utilisateur), puis on impose de la diversité — pas cinq fois le même type
   de pari d'affilée, un peu comme un vrai fil "meilleurs pronostics" mélange les marchés.
   On y ajoute la "conviction contextuelle" (enjeu de classement, dynamique de forme, pression
   de phase/match retour) : un pari à pourcentage modéré mais très soutenu par le contexte peut
   dépasser un pari à pourcentage plus haut mais sans conviction contextuelle. Un plancher de
   probabilité évite malgré tout de faire remonter un pari trop incertain (un coup de pile ou
   face bien commenté reste un coup de pile ou face). */
const COMM_BEST_MIN_P = 0.55; // plancher : "modéré et plus", jamais un quasi coin-flip
const COMM_CONVICTION_WEIGHT = 0.4; // poids max de la conviction contextuelle dans le score
const COMM_RELIABILITY_MIN_N = 15;
const communityReliabilityCache = new Map(); // sport -> {at, data}
const COMM_RELIABILITY_TTL = 15 * 60 * 1000; // 15 min : assez frais, évite de recalculer à chaque requête

async function getCommunityReliability(sport) {
  const cached = communityReliabilityCache.get(sport);
  if (cached && Date.now() - cached.at < COMM_RELIABILITY_TTL) return cached.data;
  const verified = await communityStore.listVerified(sport, 1000);
  const data = computeCalibrationByMarket(verified) || {};
  communityReliabilityCache.set(sport, { at: Date.now(), data });
  return data;
}

function pickBestBet(analysis) {
  const bets = analysis.bets || [];
  // Un pari RENTABLE (cote connue + edge positif) passe toujours devant un pari juste
  // PROBABLE : une probabilité élevée ne veut rien dire côté argent si la cote du
  // bookmaker ne compense pas le risque (cote trop faible = mise immobilisée pour peu).
  const profitable = bets.filter(b => b.edge != null && b.edge > 0).sort((a, b) => b.edge - a.edge);
  if (profitable.length) return profitable[0];
  return bets.slice().sort((a, b) => b.p - a.p)[0] || null;
}

async function selectTopCommunityBets(sport, candidates, limit) {
  const reliability = await getCommunityReliability(sport);
  const scored = candidates.map(r => {
    const bet = pickBestBet(r);
    if (!bet) return null;
    const rentable = bet.edge != null && bet.edge > 0;
    if (!rentable && bet.p < COMM_BEST_MIN_P) return null; // pas assez solide en soi, quel que soit le contexte
    const mt = bet.marketType || 'non_classe';
    const c = reliability[mt];
    const trustworthy = !(c && c.n >= COMM_RELIABILITY_MIN_N && c.gap > 10); // marché encore "à corriger" : on l'écarte du haut du panier
    if (!trustworthy) return null;
    const reliabilityFactor = (c && c.n >= COMM_RELIABILITY_MIN_N) ? c.hitRate : 1; // pas assez de recul = neutre, pas pénalisé
    const convictionIdx = Math.max(0, Math.min(1, r.convictionIdx || 0));
    const convictionBonus = 1 + COMM_CONVICTION_WEIGHT * convictionIdx; // jusqu'à +40% si enjeu/dynamique/pression au maximum
    // +10 garantit qu'un pari rentable sort toujours devant un pari juste probable,
    // quelle que soit sa probabilité brute — la valeur passe avant l'apparence de sûreté.
    const score = rentable ? (10 + bet.edge) * convictionBonus : bet.p * reliabilityFactor * convictionBonus;
    return { analysis: r, bet, marketType: mt, score, reliabilityFactor, reliabilityN: c ? c.n : 0, convictionIdx, rentable };
  }).filter(Boolean).sort((a, b) => b.score - a.score);

  // Diversité : jamais plus de 2 paris consécutifs du même type de marché dans le résultat final.
  const result = [];
  const recentTypes = [];
  const leftovers = [];
  for (const item of scored) {
    const last2 = recentTypes.slice(-2);
    if (last2.length === 2 && last2[0] === item.marketType && last2[1] === item.marketType) {
      leftovers.push(item); continue;
    }
    result.push(item); recentTypes.push(item.marketType);
    if (result.length >= limit) break;
  }
  for (const item of leftovers) { if (result.length >= limit) break; result.push(item); }

  return result.map(item => ({ ...item.analysis, headlineBet: item.bet, reliabilityFactor: item.reliabilityFactor, reliabilityN: item.reliabilityN, convictionIdx: item.convictionIdx, rentable: item.rentable }));
}

async function handleCommunityFeed(req, res, query) {
  const user = await verifyAuth(query.phone, query.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const sport = query.sport === 'basketball' ? 'basketball' : 'football';
  const sub = query.sub || 'all'; // best | safe | value | score | all
  const page = Math.max(0, parseInt(query.page, 10) || 0);
  let results = await communityStore.feed(sport, page, PAGE_SIZE * 5); // sur-échantillonne puis filtre côté serveur

  if (sub === 'best') {
    results = await selectTopCommunityBets(sport, results, PAGE_SIZE);
    return sendJSON(res, 200, { results, page, perPage: PAGE_SIZE });
  }
  if (sub === 'safe') {
    results = results.filter(r => (r.bets || []).some(b => b.p >= 0.82));
  } else if (sub === 'value') {
    // La carte doit montrer LE pari qui a la meilleure valeur réelle (edge), pas le plus probable :
    // un pari à 56% avec un edge de +76% est plus intéressant qu'un pari à 90% sans edge positif.
    results = results
      .map(r => {
        const valueBets = (r.bets || []).filter(b => b.edge != null && b.edge > 0);
        if (!valueBets.length) return null;
        const bestValueBet = valueBets.slice().sort((a, b) => b.edge - a.edge)[0];
        return { ...r, headlineBet: bestValueBet };
      })
      .filter(Boolean);
  } else if (sub === 'score') {
    // Idem : on met en avant le meilleur score exact (topScores), pas un pari classique.
    results = results
      .map(r => {
        const goodScores = (r.topScores || []).filter(s => s.p >= 0.15);
        if (!goodScores.length) return null;
        const bestScore = goodScores.slice().sort((a, b) => b.p - a.p)[0];
        return { ...r, headlineBet: { label: bestScore.label, p: bestScore.p, marketType: 'score_exact' } };
      })
      .filter(Boolean);
  }
  sendJSON(res, 200, { results: results.slice(0, PAGE_SIZE), page, perPage: PAGE_SIZE });
}

async function handleCommunityVerify(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const { id, finalScore, evaluations } = body;
  if (!id || !finalScore || !evaluations) return sendJSON(res, 400, { error: 'id, finalScore et evaluations requis.' });

  const existing = await communityStore.getById(id);
  if (!existing) return sendJSON(res, 404, { error: 'Analyse introuvable.' });
  if (existing.verifiedAt) return sendJSON(res, 409, { error: 'Déjà vérifiée.' });

  const row = await communityStore.markVerified(id, finalScore, evaluations);

  // XP bonus pour l'auteur original, proportionnel à la qualité réelle de son analyse —
  // c'est ça qui fait du classement un indicateur de fiabilité, pas juste de volume.
  const correctBets = evaluations.filter(e => e.hit === true).length;
  const exactScoreHit = evaluations.some(e => e.marketType === 'score_exact' && e.hit === true);
  const bonusXP = correctBets * XP_PER_CORRECT_BET + (exactScoreHit ? XP_EXACT_SCORE : 0);
  if (bonusXP > 0) await store.incrementUserStats(existing.authorPhone, { xpDelta: bonusXP });

  notifyAnalysisVerified(existing.authorPhone, existing.nameA, existing.nameB, finalScore, correctBets, evaluations.length, exactScoreHit); // best-effort

  sendJSON(res, 200, { ok: true, analysis: row, bonusXpAwarded: bonusXP });
}

async function handleLeaderboard(req, res, query) {
  const user = await verifyAuth(query.phone, query.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const top = await store.topUsers(50);
  const ranked = top.map((u, i) => ({ rank: i + 1, pseudo: u.pseudo, xp: u.xp, analysesCount: u.analysesCount }));
  sendJSON(res, 200, { leaderboard: ranked });
}

async function handleSetPseudo(req, res) {
  const body = await readBody(req);
  const user = await verifyAuth(body.phone, body.token);
  if (!user) return sendJSON(res, 401, { error: 'Session invalide.' });
  const pseudo = (body.pseudo || '').toString().trim().slice(0, 40);
  if (!pseudo || pseudo.length < 3) return sendJSON(res, 400, { error: 'Pseudo trop court (3 caractères minimum).' });
  await store.updateUser(user.phone, { pseudo });
  sendJSON(res, 200, { ok: true, pseudo });
}

/* ---------- Panneau d'admin (page HTML servie directement) ---------- */
const ADMIN_HTML = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
const TERMS_HTML = fs.readFileSync(path.join(__dirname, 'terms.html'), 'utf8');

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const p = parsed.pathname;

  if (req.method === 'OPTIONS') { return sendJSON(res, 200, {}); }

  try {
    if (p === '/admin' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(ADMIN_HTML);
    }
    if (p === '/terms' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(TERMS_HTML);
    }
    if (p === '/api/register' && req.method === 'POST') return await handleRegister(req, res);
    if (p === '/api/login' && req.method === 'POST') return await handleLogin(req, res);
    if (p === '/api/status' && req.method === 'GET') return await handleStatus(req, res, parsed.query);
    if (p === '/api/admin/users' && req.method === 'POST') return await handleAdminUsers(req, res);
    if (p === '/api/admin/activate' && req.method === 'POST') return await handleAdminActivate(req, res);
    if (p === '/api/subscribe-request' && req.method === 'POST') return await handleSubscribeRequest(req, res);
    if (p === '/api/track/push' && req.method === 'POST') return await handleTrackPush(req, res);
    if (p === '/api/calibration' && req.method === 'GET') return await handleCalibration(req, res, parsed.query);
    if (p === '/api/leagues' && req.method === 'GET') return await handleLeagues(req, res, parsed.query);
    if (p === '/api/community/publish' && req.method === 'POST') return await handleCommunityPublish(req, res);
    if (p === '/api/push/vapid-public-key' && req.method === 'GET') return await handlePushVapidKey(req, res);
    if (p === '/api/push/subscribe' && req.method === 'POST') return await handlePushSubscribe(req, res);
    if (p === '/api/push/unsubscribe' && req.method === 'POST') return await handlePushUnsubscribe(req, res);
    if (p === '/api/community/search' && req.method === 'GET') return await handleCommunitySearch(req, res, parsed.query);
    if (p === '/api/community/feed' && req.method === 'GET') return await handleCommunityFeed(req, res, parsed.query);
    if (p === '/api/community/verify' && req.method === 'POST') return await handleCommunityVerify(req, res);
    if (p === '/api/leaderboard' && req.method === 'GET') return await handleLeaderboard(req, res, parsed.query);
    if (p === '/api/pseudo' && req.method === 'POST') return await handleSetPseudo(req, res);
    sendJSON(res, 404, { error: 'Route inconnue.' });
  } catch (e) {
    console.error(e);
    sendJSON(res, 500, { error: 'Erreur serveur.' });
  }
});

server.listen(PORT, () => console.log(`EA server actif sur le port ${PORT} (stockage: ${USE_SUPABASE ? 'Supabase' : 'fichier local'})`));
