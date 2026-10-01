'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
// better-sqlite3 13 uses N-API 10; older runtimes can crash inside the addon.
if (Number(process.versions.napi) < 10) throw new Error('SQLITE_REQUIRES_NODE_22_14_OR_NEWER_NAPI10');
const Database = require('better-sqlite3');
const config = require('../config/config');
const { SCHEMA_VERSION, SQLITE_SCHEMA } = require('./sqliteSchema');

let database = null;
let normalizedChecksum = '';
// Fixed internal SQL only; never cache user-provided SQL or another connection.
// Reset on close/open failure so statements cannot outlive their database.
let statements = new Map();
function Prepare(db, sql) {
    if (db !== database) return db.prepare(sql);
    let statement = statements.get(sql);
    if (!statement) {
        statement = db.prepare(sql);
        if (statements.size >= 32) statements.delete(statements.keys().next().value);
        statements.set(sql, statement);
    }
    return statement;
}
const NORMALIZED_KEYS = ['servers','serverAliases','serverNotes','disabledServers','drainingServers','serverDrainMeta',
    'clients','clientAliases','clientNotes','disabledClients','licenses','qrAuthRequests','deviceSecrets','deviceSecretMeta',
    'serverFeatureOverrides','clientFeatureOverrides','serverProtocolProfiles','clientProtocolProfiles'];
function NormalizedChecksum(snapshot) {
    return Checksum(JSON.stringify(NORMALIZED_KEYS.map(key => snapshot[key] ?? null)));
}

function EnsureNullableClientServerId(db) {
    const columns = db.prepare('PRAGMA table_info(clients)').all();
    const serverId = columns.find(column => column.name === 'server_id');
    if (!serverId || Number(serverId.notnull) === 0) return;

    db.exec('PRAGMA foreign_keys = OFF;');
    try {
        db.exec(`BEGIN IMMEDIATE;
ALTER TABLE clients RENAME TO clients_schema_v3;
CREATE TABLE clients (
  device_key TEXT PRIMARY KEY,
  client_id TEXT NOT NULL UNIQUE,
  server_id TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  last_auth_at INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT NOT NULL DEFAULT '',
  auth_count INTEGER NOT NULL DEFAULT 0,
  send_count INTEGER NOT NULL DEFAULT 0,
  reconnect_count INTEGER NOT NULL DEFAULT 0,
  alias TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  disabled INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(server_id) REFERENCES servers(server_id)
);
INSERT INTO clients(device_key,client_id,server_id,created_at,last_seen_at,last_auth_at,last_ip,auth_count,send_count,reconnect_count,alias,note,disabled)
SELECT device_key,client_id,NULLIF(server_id,''),created_at,last_seen_at,last_auth_at,last_ip,auth_count,send_count,reconnect_count,alias,note,disabled FROM clients_schema_v3;
DROP TABLE clients_schema_v3;
CREATE INDEX IF NOT EXISTS idx_clients_server_id ON clients(server_id);
COMMIT;`);
    } catch (error) {
        try { db.exec('ROLLBACK'); } catch (_) {}
        throw error;
    } finally {
        db.exec('PRAGMA foreign_keys = ON;');
    }
}

function Checksum(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

function Open() {
    if (database && database.open) return database;
    database = null;
    normalizedChecksum = '';
    statements.clear();
    fs.mkdirSync(path.dirname(config.SQLITE_FILE), { recursive: true });
    const candidate = new Database(config.SQLITE_FILE, { timeout: 5000 });
    try {
        // Refuse corrupt storage before creating/updating schema. A driver change
        // must never silently replace an existing database with a JSON mirror.
        if (candidate.pragma('quick_check', { simple: true }) !== 'ok') throw new Error('SQLITE_INTEGRITY_CHECK_FAILED');
        candidate.pragma('synchronous = FULL');
        candidate.exec(SQLITE_SCHEMA);
        EnsureNullableClientServerId(candidate);
        if (candidate.pragma('journal_mode', { simple: true }) !== 'wal' ||
            candidate.pragma('synchronous', { simple: true }) !== 2 ||
            candidate.pragma('foreign_keys', { simple: true }) !== 1) throw new Error('SQLITE_DURABILITY_POLICY_FAILED');
        const setMeta = candidate.prepare('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
        setMeta.run('schema_version', String(SCHEMA_VERSION));
        setMeta.run('provider', 'sqlite');
        setMeta.run('sqlite_driver', 'better-sqlite3');
        // Publish only a fully initialized connection; failed opens are retryable
        // after an administrator repairs the original database offline.
        database = candidate;
        return database;
    } catch (error) {
        try { candidate.close(); } catch (_) {}
        throw error;
    }
}

function InsertNormalized(db, snapshot) {
    db.exec('DELETE FROM clients; DELETE FROM servers; DELETE FROM licenses; DELETE FROM qr_auth_requests; DELETE FROM device_secrets; DELETE FROM feature_overrides; DELETE FROM protocol_profiles;');
    const serverInsert = Prepare(db, 'INSERT INTO servers(device_key,server_id,alias,note,disabled,draining,drain_meta_json) VALUES(?,?,?,?,?,?,?)');
    for (const [deviceKey, serverId] of Object.entries(snapshot.servers || {})) {
        serverInsert.run(deviceKey, serverId, (snapshot.serverAliases || {})[serverId] || '', (snapshot.serverNotes || {})[serverId] || '', (snapshot.disabledServers || []).includes(serverId) ? 1 : 0, (snapshot.drainingServers || []).includes(serverId) ? 1 : 0, JSON.stringify((snapshot.serverDrainMeta || {})[serverId] || {}));
    }
    const clientInsert = Prepare(db, 'INSERT INTO clients(device_key,client_id,server_id,created_at,last_seen_at,last_auth_at,last_ip,auth_count,send_count,reconnect_count,alias,note,disabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
    for (const [deviceKey, value] of Object.entries(snapshot.clients || {})) {
        clientInsert.run(deviceKey, value.id || value.clientId, value.serverId || null, Number(value.createdAt) || 0, Number(value.lastSeenAt) || 0, Number(value.lastAuthAt) || 0, String(value.lastIP || ''), Number(value.authCount) || 0, Number(value.sendCount) || 0, Number(value.reconnectCount) || 0, (snapshot.clientAliases || {})[value.id || value.clientId] || '', (snapshot.clientNotes || {})[value.id || value.clientId] || '', (snapshot.disabledClients || []).includes(value.id || value.clientId) ? 1 : 0);
    }
    const licenseInsert = Prepare(db, 'INSERT INTO licenses(license_key,created_at,expires_at,bound_client,bound_at,last_auth_at,last_seen_at,last_ip,auth_count,send_count,suspended,memo,tags_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
    for (const [key, value] of Object.entries(snapshot.licenses || {})) {
        licenseInsert.run(key, Number(value.createdAt) || 0, Number(value.expiresAt) || 0, String(value.boundClient || ''), Number(value.boundAt) || 0, Number(value.lastAuthAt) || 0, Number(value.lastSeenAt) || 0, String(value.lastIP || ''), Number(value.authCount) || 0, Number(value.sendCount) || 0, value.suspended ? 1 : 0, String(value.memo || ''), JSON.stringify(value.tags || []));
    }
    const qrInsert = Prepare(db, 'INSERT INTO qr_auth_requests(request_id,client_id,status,issued_at,expires_at,request_json) VALUES(?,?,?,?,?,?)');
    for (const [requestId, value] of Object.entries(snapshot.qrAuthRequests || {})) {
        qrInsert.run(requestId, String(value.clientId || ''), String(value.status || 'UNKNOWN'), Number(value.issuedAt) || 0, Number(value.expiresAt) || 0, JSON.stringify(value));
    }
    const secretInsert = Prepare(db, 'INSERT INTO device_secrets(device_key,secret_value,created_at,updated_at) VALUES(?,?,?,?)');
    for (const [key, secret] of Object.entries(snapshot.deviceSecrets || {})) {
        const meta = (snapshot.deviceSecretMeta || {})[key] || {};
        secretInsert.run(key, secret, Number(meta.createdAt) || 0, Number(meta.rotatedAt) || 0);
    }
    const featureInsert = Prepare(db, 'INSERT INTO feature_overrides(device_type,device_id,flags_json) VALUES(?,?,?)');
    for (const [type, source] of [['SERVER', snapshot.serverFeatureOverrides], ['CLIENT', snapshot.clientFeatureOverrides]]) {
        for (const [id, flags] of Object.entries(source || {})) featureInsert.run(type, id, JSON.stringify(flags || {}));
    }
    const protocolInsert = Prepare(db, 'INSERT INTO protocol_profiles(device_type,device_id,profile_json) VALUES(?,?,?)');
    for (const [type, source] of [['SERVER', snapshot.serverProtocolProfiles], ['CLIENT', snapshot.clientProtocolProfiles]]) {
        for (const [id, profile] of Object.entries(source || {})) protocolInsert.run(type, id, JSON.stringify(profile || {}));
    }
}

function SaveSnapshot(snapshot, options = {}) {
    const db = Open();
    const text = JSON.stringify(snapshot);
    const checksum = Checksum(text);
    const savedAt = Date.now();
    const nextNormalizedChecksum = NormalizedChecksum(snapshot);
    const normalizedChanged = normalizedChecksum !== nextNormalizedChecksum;
    let revision;
    db.exec('BEGIN IMMEDIATE');
    try {
        const previous = Prepare(db, 'SELECT snapshot_revision,checksum_sha256 FROM state_snapshot WHERE id=1').get();
        const previousRevision = Number(previous && previous.snapshot_revision) || 0;
        const contentRevision = previous && previous.checksum_sha256 === checksum ? previousRevision : previousRevision + 1;
        revision = Math.max(Number(options.revision) || 0, contentRevision || 1);
        // Member interactions alter the authoritative snapshot, not device and
        // license tables. Do not delete/reinsert every relay row for a like,
        // message, attendance, or read receipt. Commit durability is unchanged.
        if (normalizedChanged) InsertNormalized(db, snapshot);
        Prepare(db, 'INSERT INTO state_snapshot(id,snapshot_revision,saved_at,source_instance,checksum_sha256,snapshot_json) VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET snapshot_revision=excluded.snapshot_revision,saved_at=excluded.saved_at,source_instance=excluded.source_instance,checksum_sha256=excluded.checksum_sha256,snapshot_json=excluded.snapshot_json').run(revision, savedAt, String(options.sourceInstance || config.HA_INSTANCE_ID || ''), checksum, text);
        Prepare(db, 'INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run('last_saved_at', String(savedAt));
        db.exec('COMMIT');
    } catch (error) {
        try { db.exec('ROLLBACK'); } catch (_) {}
        throw error;
    }
    // Publish this cache only after COMMIT. A failed write must be retried.
    normalizedChecksum = nextNormalizedChecksum;
    return { revision, savedAt, checksum, size: Buffer.byteLength(text), normalizedChanged };
}

function LoadSnapshot() {
    const db = Open();
    const row = Prepare(db, 'SELECT snapshot_revision,saved_at,source_instance,checksum_sha256,snapshot_json FROM state_snapshot WHERE id=1').get();
    if (!row) return null;
    if (Checksum(row.snapshot_json) !== row.checksum_sha256) throw new Error('SQLITE_SNAPSHOT_CHECKSUM_MISMATCH');
    return { revision: Number(row.snapshot_revision), savedAt: Number(row.saved_at), sourceInstance: row.source_instance, checksum: row.checksum_sha256, data: JSON.parse(row.snapshot_json) };
}

function Status() {
    try {
        const db = Open();
        const quick = db.pragma('quick_check', { simple: true });
        const row = Prepare(db, 'SELECT snapshot_revision,saved_at,source_instance,checksum_sha256 FROM state_snapshot WHERE id=1').get() || {};
        const stat = fs.statSync(config.SQLITE_FILE);
        return { ok: quick === 'ok', driver: 'better-sqlite3', sqliteVersion: Prepare(db, 'SELECT sqlite_version() AS version').get().version, file: path.basename(config.SQLITE_FILE), size: stat.size, schemaVersion: SCHEMA_VERSION, revision: Number(row.snapshot_revision) || 0, savedAt: Number(row.saved_at) || 0, sourceInstance: row.source_instance || '', checksum: row.checksum_sha256 || '' };
    } catch (error) {
        return { ok: false, driver: 'better-sqlite3', file: path.basename(config.SQLITE_FILE), size: 0, schemaVersion: SCHEMA_VERSION, revision: 0, savedAt: 0, sourceInstance: '', checksum: '', error: error.message };
    }
}

function Close() {
    const current = database;
    database = null;
    normalizedChecksum = '';
    statements.clear();
    if (current && current.open) current.close();
}

module.exports = { Open, SaveSnapshot, LoadSnapshot, Status, Close };
