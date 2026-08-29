-- ================================================================
-- EA — Table des utilisateurs (à coller dans Supabase > SQL Editor)
-- ================================================================

create table if not exists public.users (
  phone text primary key,
  name text default '',
  salt text not null,
  pin_hash text not null,
  token text not null,
  created_at bigint not null,
  trial_ends_at bigint not null,
  subscription jsonb
);

-- Sécurité : cette table n'est accessible que via la clé service_role
-- (utilisée uniquement par notre serveur, jamais côté navigateur), donc on
-- désactive Row Level Security plutôt que d'écrire des policies pour un
-- accès public qu'on ne veut justement pas.
alter table public.users disable row level security;

-- Depuis fin mai 2026, Supabase exige des droits explicites pour qu'une
-- table soit accessible via l'API REST (PostgREST) — sans cette ligne,
-- le serveur recevrait des erreurs 401/404 malgré la bonne clé.
grant all on public.users to service_role;

-- ================================================================
-- Table des entrées de match partagées (moteur de calibration commun)
-- ================================================================

create table if not exists public.track_entries (
  id bigserial primary key,
  sport text not null,
  league text default '',
  name_a text,
  name_b text,
  timestamp bigint not null,
  evaluations jsonb,
  lambda_a numeric,
  lambda_b numeric,
  final_score jsonb,
  final_stats jsonb,
  stage text,
  leg text,
  tension_used numeric,
  agg_factor_used jsonb,
  agg_diff numeric,
  components jsonb
);

create index if not exists track_entries_sport_idx on public.track_entries (sport);
create index if not exists track_entries_league_idx on public.track_entries (league);

alter table public.track_entries disable row level security;
grant all on public.track_entries to service_role;

-- ================================================================
-- PARTIE COMMUNAUTÉ — profils publics, analyses partagées, classement
-- ================================================================

-- Colonnes de profil/contribution ajoutées à la table users existante.
-- pseudo : nom affiché publiquement (jamais le numéro de téléphone).
-- xp / analyses_count : alimentent le classement des contributeurs.
alter table public.users add column if not exists pseudo text;
alter table public.users add column if not exists xp integer not null default 0;
alter table public.users add column if not exists analyses_count integer not null default 0;

-- Demande d'abonnement déclarée par le client (formule + durée choisies) AVANT
-- son paiement Wave — permet à l'admin de voir directement quoi activer, sans
-- avoir à demander au client quelle formule il a payée.
alter table public.users add column if not exists pending_request jsonb;

-- Incrément atomique (évite les pertes de points si deux requêtes arrivent en même temps)
create or replace function public.increment_user_stats(p_phone text, p_xp_delta integer, p_analyses_delta integer)
returns void as $$
  update public.users
  set xp = xp + p_xp_delta, analyses_count = analyses_count + p_analyses_delta
  where phone = p_phone;
$$ language sql;
grant execute on function public.increment_user_stats to service_role;

create table if not exists public.community_analyses (
  id bigserial primary key,
  author_phone text not null,
  author_pseudo text not null,
  sport text not null,
  league text default '',
  name_a text not null,
  name_b text not null,
  -- slugs normalisés (minuscules, sans accents/espaces) pour une recherche
  -- insensible à la casse et à l'ordre A/B des deux équipes.
  slug_a text not null,
  slug_b text not null,
  stage text,
  leg text,
  lambda_a numeric,
  lambda_b numeric,
  top_scores jsonb,
  bets jsonb,
  context_sentence text,
  -- Indice 0-1 de "conviction contextuelle" (enjeu de classement, dynamique de forme,
  -- pression de phase/match retour) — utilisé pour sélectionner les "Meilleurs Paris"
  -- sans se limiter à la probabilité brute la plus haute.
  conviction_idx numeric default 0,
  timestamp bigint not null,
  -- Rempli après coup quand l'auteur (ou un autre utilisateur qui a vu
  -- l'analyse) valide le résultat réel — permet le badge vérifié dans le fil.
  final_score jsonb,
  evaluations jsonb,
  verified_at bigint
);

-- Migration : si la table community_analyses existe déjà sans cette colonne, exécuter :
-- alter table public.community_analyses add column if not exists conviction_idx numeric default 0;

create index if not exists community_slug_idx on public.community_analyses (slug_a, slug_b, sport);
create index if not exists community_timestamp_idx on public.community_analyses (timestamp desc);
create index if not exists community_author_idx on public.community_analyses (author_phone);

alter table public.community_analyses disable row level security;
grant all on public.community_analyses to service_role;

-- ================================================================
-- Abonnements aux notifications push (Web Push / VAPID). Une ligne
-- par appareil/navigateur abonné (endpoint = identifiant unique
-- fourni par le navigateur pour cet abonnement).
-- ================================================================
create table if not exists public.push_subscriptions (
  endpoint text primary key,
  phone text not null,
  p256dh text not null,
  auth text not null,
  created_at bigint not null default extract(epoch from now()) * 1000
);
create index if not exists push_subscriptions_phone_idx on public.push_subscriptions (phone);

alter table public.push_subscriptions disable row level security;
grant all on public.push_subscriptions to service_role;

-- Série de connexions quotidiennes (5.7).
alter table public.users add column if not exists streak integer not null default 0;
alter table public.users add column if not exists last_checkin_date text;
