# EA — Serveur d'abonnement

Backend minimal, zéro dépendance (Node.js pur), pour gérer :
- Comptes utilisateurs par **numéro de téléphone**
- **Essai gratuit de 14 jours** automatique à l'inscription
- Abonnements **mensuel (30j)** et **annuel (365j)**
- **Activation manuelle** par toi (admin) après vérification du paiement Wave
  reçu dans ton appli Wave — pas d'intégration API Wave nécessaire pour démarrer

## 1. Avant de mettre en ligne

Ouvre `server.js` et change absolument cette ligne :
```js
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-moi-absolument';
```
Ou mieux : ne la change pas dans le code, et définis la variable d'environnement
`ADMIN_PASSWORD` sur ton hébergeur (voir plus bas) — c'est plus sûr.

## 2. Héberger le serveur (aucun compte encore, deux options simples)

**Option A — Render.com (gratuit pour démarrer, simple)**
1. Crée un compte sur render.com
2. "New +" → "Web Service" → connecte ton dépôt (ou upload direct du dossier via leur interface / un dépôt Git que tu crées avec ces fichiers)
3. Build command : (laisser vide, rien à installer)
4. Start command : `node server.js`
5. Ajoute la variable d'environnement `ADMIN_PASSWORD` avec un mot de passe fort
6. Une fois déployé, tu obtiens une URL du type `https://ea-server-xxxx.onrender.com`

**Option B — Railway.app** : même principe, interface similaire, aussi simple.

⚠️ Sur les offres gratuites, le serveur peut se "endormir" après une période
d'inactivité et mettre quelques secondes à répondre à la première requête —
normal, pas un bug.

## 3. Panneau d'admin

Une fois en ligne, va sur `https://TON-URL/admin` :
- Entre ton `ADMIN_PASSWORD`
- "Charger la liste" affiche tous les inscrits et leur statut (essai / actif / expiré)
- Pour activer quelqu'un : entre son numéro (au même format que celui qu'il a utilisé
  pour s'inscrire dans l'appli), choisis Mensuel ou Annuel, "Activer / prolonger"
- Si la personne a déjà un abonnement actif en cours, l'activation **prolonge**
  à partir de sa date de fin actuelle (ne perd jamais de jours payés)

## 4. ✅ Base de données persistante — Supabase (gratuit)

**Sans cette étape, chaque redéploiement (même une simple mise à jour du
code) efface TOUS les comptes utilisateurs et abonnements** — c'est ce qui
s'est déjà produit une fois. Avec Supabase, tes données vivent en dehors de
Render, donc plus jamais affectées par un redéploiement.

**Configuration (10-15 minutes, gratuit) :**

1. Va sur [supabase.com](https://supabase.com) → crée un compte → "New Project"
   - Choisis un mot de passe de base de données (à noter, tu n'en auras
     normalement plus besoin après)
   - Attends 1-2 minutes que le projet soit prêt

2. Dans ton projet Supabase, va dans **"SQL Editor"** (menu de gauche) →
   "New query" → colle le contenu du fichier `supabase-setup.sql` fourni
   dans ce zip → "Run". Ça crée la table qui stockera tes utilisateurs.

3. Va dans **"Project Settings"** (icône engrenage) → **"API"** :
   - Copie **"Project URL"** (ressemble à `https://xxxxx.supabase.co`)
   - Copie la clé **"service_role"** (PAS la clé "anon public" — celle-ci
     doit rester secrète, ne jamais la mettre dans le code de l'appli
     ni la partager)

4. Sur Render, dans ton service `EA-SERVER` → **"Environment"** → ajoute
   deux variables :
   - `SUPABASE_URL` = l'URL copiée à l'étape 3
   - `SUPABASE_SERVICE_KEY` = la clé service_role copiée à l'étape 3

5. Redéploie (celui-ci effacera l'ancien `db.json` éphémère une dernière
   fois — normal, plus jamais après). Vérifie dans les logs Render que tu
   vois bien `[DB] Mode Supabase actif` au démarrage.

6. Réinscris-toi une dernière fois dans l'appli — ce compte, et tous les
   suivants, sont désormais permanents.

**Seule limite à connaître** : un projet Supabase gratuit se met en pause
après **7 jours sans aucune requête**. Comme ton serveur interroge la base
à chaque connexion/inscription, ça n'arrivera pas tant que l'appli est
utilisée normalement. Si ça arrivait quand même (longue pause d'activité),
un clic dans le tableau de bord Supabase suffit à tout réactiver — aucune
donnée perdue.

## 5. Communauté — analyses partagées, XP, classement (nouveau)

Choix assumé : **pas d'API sportive externe**. Toute la donnée vient des
utilisateurs entre eux — 100% manuel, comme le reste de l'app.

**Nouvelles routes :**
- `POST /api/community/publish` — publie une analyse (Genèse/Basket) au fil
  communautaire. +5 XP immédiat pour l'auteur.
- `GET /api/community/search?teamA=X&teamB=Y&sport=football&page=0` —
  recherche toutes les analyses publiées sur ce match par n'importe quel
  utilisateur, dans n'importe quel ordre (A-vs-B ou B-vs-A remontent tous
  les deux), triées du plus récent au plus ancien, paginées par 10.
- `GET /api/community/feed?sub=safe|value|score|all&sport=football&page=0` —
  fil public filtré (Safe Bets 82%+, Value Bets à edge réel, Scores exacts
  15%+), alimenté par toute la communauté.
- `POST /api/community/verify` — quand un résultat réel est noté, met à
  jour l'analyse communautaire correspondante (badge vérifié pour tous) et
  verse un bonus XP à l'auteur : **+10 XP par pari juste, +25 XP si le
  score exact est trouvé**. Le classement récompense donc la fiabilité,
  pas seulement le volume de publications.
- `GET /api/leaderboard?phone=...&token=...` — top 50 contributeurs par XP.
- `POST /api/pseudo` — définit le nom public affiché (jamais le téléphone).

**Configuration :** aucune variable d'environnement supplémentaire. Colle
le SQL mis à jour de `supabase-setup.sql` dans l'éditeur SQL Supabase
(tables `community_analyses`, colonnes `pseudo`/`xp`/`analyses_count` sur
`users`, fonction `increment_user_stats`) — tout est `create/alter ... if
not exists`, donc rejouable sans risque même si une partie existe déjà.

## 5bis. Notifications push communauté (nouveau)

À chaque publication dans Communauté, tous les autres utilisateurs abonnés
reçoivent une vraie notification push — **même app fermée** (contrairement
aux notifications locales, qui ne marchent que si l'appli est ouverte ou
en arrière-plan récent). Le message ne révèle jamais le pari lui-même,
seulement que quelque chose de nouveau est disponible (ex : "Real Madrid
vs Real Sociedad — Pari disponible"), pour donner envie d'ouvrir l'appli.

Implémentation "maison" du protocole standard Web Push (VAPID), **sans
aucune dépendance npm** — comme le reste du serveur.

**Nouvelles routes :**
- `GET /api/push/vapid-public-key` — clé publique VAPID (le client en a
  besoin pour s'abonner).
- `POST /api/push/subscribe` — enregistre l'abonnement push d'un appareil.
- `POST /api/push/unsubscribe` — le désenregistre.

**Configuration — une seule variable, fortement recommandée :**
- `VAPID_PRIVATE_KEY` — sans elle, une clé est générée au hasard à
  CHAQUE démarrage du serveur, ce qui invalide tous les abonnements
  existants à chaque redéploiement (les utilisateurs devraient réactiver
  les notifications à chaque fois). Au premier démarrage sans cette
  variable, le serveur affiche dans ses logs une clé prête à copier :
  cherche une ligne `[push] Ajoutez cette variable d'environnement...`
  et colle la valeur proposée dans `VAPID_PRIVATE_KEY` sur ton hébergeur,
  puis redémarre une dernière fois — elle ne bougera plus ensuite.
- `VAPID_SUBJECT` (optionnel) — `mailto:ton-email@exemple.com`, exigé par
  la norme mais sans impact fonctionnel visible.

Colle aussi le SQL mis à jour de `supabase-setup.sql` (table
`push_subscriptions`) si tu es en mode Supabase.

## 6. Étape suivante (plus tard)

Quand tu auras un accès à l'API Wave Business (webhooks), on pourra remplacer
l'activation manuelle par une activation automatique dès réception du paiement
— l'architecture actuelle est prête pour cette évolution sans tout reconstruire.
