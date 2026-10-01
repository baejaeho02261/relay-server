'use strict';

// The legacy writer deliberately uses node:sqlite ONLY in this compatibility
// test. Production storage, migrations and import tools use better-sqlite3.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const mode = process.argv[2];
const hash = text => crypto.createHash('sha256').update(text).digest('hex');

if (!mode) {
    for (const name of ['legacy-v4', 'legacy-v3', 'corrupt-file', 'corrupt-snapshot', 'empty-cutover', 'missing-native', 'unsupported-napi']) {
        const run = spawnSync(process.execPath, [__filename, name], { stdio: 'inherit', timeout: 30000 });
        if (run.error) throw run.error;
        assert.equal(run.status, 0, name);
    }
    console.log('SQLITE DRIVER PASS: node:sqlite v3/v4 database compatibility, WAL/FULL/foreign keys, statement reuse, atomic rollback, close/reopen, native addon and corruption fail closed, explicit empty cutover.');
    process.exit(0);
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-sqlite-driver-'));
process.env.DATA_DIR = temp;
process.env.STORAGE_ENGINE = 'sqlite';
process.env.HA_ENABLED = '0';
const file = path.join(temp, 'relay.db');
const mirror = path.join(temp, 'relay-identities.json');
const snapshot = {
    version: 145, servers: { 'server-device': 'A1A1A1A1A1A1A1A1' },
    clients: { 'client-device': { id: 'B2B2B2B2B2B2B2B2', serverId: 'A1A1A1A1A1A1A1A1', createdAt: 123 } },
    licenses: { 'legacy-record': { createdAt: 100, memo: '기존 데이터' } },
    serviceEnabled: true, customRoundTrip: { title: '서버 저장', number: 4096 }
};
let adapter;
try {
    const { DatabaseSync } = require('node:sqlite');
    const schema = require('../storage/sqliteSchema').SQLITE_SCHEMA;
    if (mode.startsWith('legacy-') || mode === 'corrupt-snapshot') {
        const old = new DatabaseSync(file);
        old.exec(mode === 'legacy-v3' ? schema.replace('server_id TEXT,', 'server_id TEXT NOT NULL,').replace('PRAGMA user_version = 4;', 'PRAGMA user_version = 3;') : schema);
        const text = JSON.stringify(snapshot);
        old.prepare('INSERT INTO state_snapshot VALUES(1,?,?,?,?,?)').run(7, 123456, 'old-node-sqlite', hash(text), text);
        old.prepare('INSERT INTO servers(device_key,server_id) VALUES(?,?)').run('server-device', 'A1A1A1A1A1A1A1A1');
        old.prepare('INSERT INTO clients(device_key,client_id,server_id,created_at) VALUES(?,?,?,?)').run('client-device', 'B2B2B2B2B2B2B2B2', 'A1A1A1A1A1A1A1A1', 123);
        old.prepare('INSERT INTO meta VALUES(?,?)').run('legacy-sentinel', 'unchanged');
        if (mode === 'corrupt-snapshot') old.exec("UPDATE state_snapshot SET checksum_sha256='bad'");
        old.close();
    }
    if (mode === 'unsupported-napi') {
        fs.writeFileSync(mirror, JSON.stringify(snapshot));
        const descriptor = Object.getOwnPropertyDescriptor(process.versions, 'napi');
        Object.defineProperty(process.versions, 'napi', { ...descriptor, value: '9' });
        try {
            assert.throws(() => require('../storage/database').LoadDatabase(), /SQLITE_REQUIRES_NODE_22_14_OR_NEWER_NAPI10/);
            assert.equal(fs.existsSync(file), false);
            assert.equal(fs.readFileSync(mirror, 'utf8'), JSON.stringify(snapshot));
        } finally { Object.defineProperty(process.versions, 'napi', descriptor); }
        fs.rmSync(temp, { recursive: true, force: true });
        console.log('SQLITE unsupported-napi PASS');
        process.exit(0);
    }
    adapter = require('../storage/sqliteDatabase');
    if (mode.startsWith('legacy-')) {
        assert.equal(require('better-sqlite3/package.json').version, '13.0.3');
        assert.deepEqual(adapter.LoadSnapshot().data, snapshot);
        const db = adapter.Open();
        assert.ok(db instanceof require('better-sqlite3'));
        assert.equal(db.pragma('journal_mode', { simple: true }), 'wal');
        assert.equal(db.pragma('synchronous', { simple: true }), 2);
        assert.equal(db.pragma('foreign_keys', { simple: true }), 1);
        assert.equal(db.pragma('busy_timeout', { simple: true }), 5000);
        assert.equal(db.pragma('table_info(clients)').find(column => column.name === 'server_id').notnull, 0);
        assert.equal(db.prepare("SELECT value FROM meta WHERE key='legacy-sentinel'").get().value, 'unchanged');
        assert.equal(adapter.Status().driver, 'better-sqlite3');
        assert.equal(adapter.Status().ok, true);
        // Count prepare calls to verify repeated writes reuse bounded connection
        // statements without confusing an old or subsequently closed connection.
        let prepareCalls = 0;
        const originalPrepare = db.prepare.bind(db);
        db.prepare = sql => { prepareCalls++; return originalPrepare(sql); };
        const changed = structuredClone(snapshot);
        changed.customRoundTrip.number++;
        const saved = adapter.SaveSnapshot(changed, { sourceInstance: 'better-sqlite3' });
        assert.equal(saved.revision, 8);
        assert.equal(saved.normalizedChanged, true);
        const firstPrepareCalls = prepareCalls;
        assert.equal(adapter.SaveSnapshot(changed).normalizedChanged, false);
        assert.equal(prepareCalls, firstPrepareCalls, 'Repeated internal SQL must reuse prepared statements');
        const originalRow = adapter.LoadSnapshot();
        const bad = structuredClone(changed);
        bad.clients['client-device'].serverId = 'C3C3C3C3C3C3C3C3';
        assert.throws(() => adapter.SaveSnapshot(bad), error => error.code === 'SQLITE_CONSTRAINT_FOREIGNKEY');
        assert.equal(db.inTransaction, false);
        assert.deepEqual(adapter.LoadSnapshot(), originalRow, 'Failed writes must roll back snapshot metadata too');
        assert.equal(db.prepare('SELECT server_id FROM clients').get().server_id, 'A1A1A1A1A1A1A1A1');
        bad.servers['second-server-device'] = 'C3C3C3C3C3C3C3C3';
        assert.equal(adapter.SaveSnapshot(bad).normalizedChanged, true, 'Failed normalization must be retried');
        assert.deepEqual(adapter.LoadSnapshot().data, bad);
        adapter.Close();
        assert.equal(db.open, false);
        const reopened = adapter.Open();
        assert.notEqual(reopened, db);
        assert.deepEqual(adapter.LoadSnapshot().data, bad);
        bad.clients['client-device'].serverId = '';
        adapter.SaveSnapshot(bad);
        assert.equal(reopened.prepare('SELECT server_id FROM clients').get().server_id, null);
        adapter.Close();
        // Reverse reader compatibility proves the actual .sqlite file format
        // remains portable and existing data did not move to an alternate store.
        const reader = new DatabaseSync(file);
        assert.equal(reader.prepare('SELECT snapshot_revision FROM state_snapshot').get().snapshot_revision, 10);
        assert.equal(reader.prepare("SELECT value FROM meta WHERE key='provider'").get().value, 'sqlite');
        reader.close();
    } else if (mode.startsWith('corrupt-')) {
        if (mode === 'corrupt-file') fs.writeFileSync(file, Buffer.from('original corrupt sqlite file; do not replace'.repeat(200)));
        fs.writeFileSync(mirror, JSON.stringify(snapshot));
        const originalBytes = fs.readFileSync(file);
        const storage = require('../storage/database');
        assert.throws(() => storage.LoadDatabase(), error => mode === 'corrupt-file' ? error.code === 'SQLITE_NOTADB' : error.message === 'SQLITE_SNAPSHOT_CHECKSUM_MISMATCH');
        assert.equal(fs.readFileSync(mirror, 'utf8'), JSON.stringify(snapshot));
        adapter.Close();
        if (mode === 'corrupt-file') assert.deepEqual(fs.readFileSync(file), originalBytes, 'Corrupt DB must not be reset or replaced');
        assert.throws(() => adapter.LoadSnapshot(), error => mode === 'corrupt-file' ? error.code === 'SQLITE_NOTADB' : error.message === 'SQLITE_SNAPSHOT_CHECKSUM_MISMATCH');
    } else if (mode === 'missing-native') {
        fs.writeFileSync(mirror, JSON.stringify(snapshot));
        const originalLoader = require.extensions['.node'];
        require.extensions['.node'] = (module, filename) => {
            if (filename.includes('better-sqlite3')) { const error = new Error('TEST_NATIVE_ADDON_UNAVAILABLE'); error.code = 'ERR_DLOPEN_FAILED'; throw error; }
            return originalLoader(module, filename);
        };
        try {
            assert.throws(() => require('../storage/database').LoadDatabase(), error => error.code === 'ERR_DLOPEN_FAILED');
            assert.equal(fs.readFileSync(mirror, 'utf8'), JSON.stringify(snapshot));
            assert.equal(fs.existsSync(file), false, 'Missing native addon must not initialize an alternate store');
        } finally { require.extensions['.node'] = originalLoader; }
    } else if (mode === 'empty-cutover') {
        fs.writeFileSync(mirror, JSON.stringify(snapshot));
        require('../storage/database').LoadDatabase();
        const restored = adapter.LoadSnapshot();
        assert.equal(restored.data.servers['server-device'], 'A1A1A1A1A1A1A1A1');
        assert.equal(restored.data.clients['client-device'].serverId, 'A1A1A1A1A1A1A1A1');
        assert.equal(adapter.Status().ok, true);
    } else throw new Error('UNRECOGNIZED_TEST_CASE');
    console.log(`SQLITE ${mode} PASS`);
} finally {
    if (adapter) adapter.Close();
    fs.rmSync(temp, { recursive: true, force: true });
}
// Imported production services can own timers; the test has no pending work.
process.exit(0);
