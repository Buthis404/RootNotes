-- RedTeam Notes — PostgreSQL schema
-- This file runs only on first DB init (empty volume).
-- No seed data — all data is created through the application.

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    ip          TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT 'Linux',
    added       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notes (
    id        TEXT PRIMARY KEY,
    pid       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title     TEXT NOT NULL,
    phase     TEXT NOT NULL DEFAULT 'recon',
    tags      TEXT[] NOT NULL DEFAULT '{}',
    content   TEXT NOT NULL DEFAULT '',
    ts        TEXT NOT NULL,
    starred   BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS note_attachments (
    id           TEXT PRIMARY KEY,
    note_id      TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    pid          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    file_size    INTEGER NOT NULL DEFAULT 0,
    storage_path TEXT NOT NULL,
    public_url   TEXT NOT NULL,
    ts           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id        TEXT PRIMARY KEY,
    pid       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ip        TEXT NOT NULL,
    hostname  TEXT NOT NULL DEFAULT '',
    os        TEXT NOT NULL DEFAULT 'Linux',
    status    TEXT NOT NULL DEFAULT 'unknown',
    ports     TEXT[] NOT NULL DEFAULT '{}',
    services  TEXT[] NOT NULL DEFAULT '{}',
    tags      TEXT[] NOT NULL DEFAULT '{}',
    interfaces_json JSONB NOT NULL DEFAULT '[]',
    notes     TEXT NOT NULL DEFAULT '',
    domain    TEXT NOT NULL DEFAULT '',
    role      TEXT NOT NULL DEFAULT 'unknown',
    is_attacker BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS creds (
    id        TEXT PRIMARY KEY,
    pid       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    username  TEXT NOT NULL,
    secret    TEXT NOT NULL DEFAULT '',
    type      TEXT NOT NULL DEFAULT 'plain',
    service   TEXT NOT NULL DEFAULT '',
    host      TEXT NOT NULL DEFAULT '',
    domain    TEXT NOT NULL DEFAULT '',
    cracked   BOOLEAN NOT NULL DEFAULT FALSE,
    notes     TEXT NOT NULL DEFAULT '',
    tags      TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS networks (
    id         TEXT PRIMARY KEY,
    pid        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT NOT NULL DEFAULT 'Network',
    background TEXT NOT NULL DEFAULT '#07080b',
    regions_json JSONB NOT NULL DEFAULT '[]',
    nodes_json JSONB NOT NULL DEFAULT '[]',
    edges_json JSONB NOT NULL DEFAULT '[]'
);
