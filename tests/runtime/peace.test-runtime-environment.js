'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const path = require('node:path'), os = require('node:os'), fs = require('node:fs'), vm = require('node:vm');
const { createRequire } = require('node:module');
const { Read } = require('../../config/peace.runtime-environment');
const { ReadListener } = require('../../config/peace.runtime-environment');
const { spawnSync } = require('node:child_process');
function Environment() {
    return { NODE_ENV:'production', WEB_ADMIN_TRANSPORT:'railway', CONNECT_TCP_HOST:'127.0.0.1',
        WEB_ADMIN_HOST:'127.0.0.1', CONNECT_TCP_PORT:'23101', WEB_ADMIN_PORT:'23102', PORT:'23102',
        DATA_DIR:path.join(os.tmpdir(), 'peace-explicit-server-data') };
}
test('production reads explicit listener and storage variables', () => {
    const env = Environment(), result = Read(env);
    assert.equal(result.HOST, env.CONNECT_TCP_HOST); assert.equal(result.CONNECT_TCP_PORT, 23101);
    assert.equal(result.WEB_ADMIN_PORT, 23102); assert.equal(result.HEALTH_PORT, 0); assert.equal(result.DATA_DIR, env.DATA_DIR);
});
test('production does not silently invent missing bind, ports or data directories', () => {
    for (const name of ['CONNECT_TCP_HOST', 'WEB_ADMIN_HOST', 'CONNECT_TCP_PORT', 'DATA_DIR']) {
        const env = Environment(); delete env[name];
        assert.throws(() => Read(env), new RegExp('RUNTIME_CONFIG_' + name + '_REQUIRED'));
    }
    const env = Environment(); delete env.WEB_ADMIN_PORT; delete env.PORT;
    assert.throws(() => Read(env), /RUNTIME_CONFIG_WEB_ADMIN_PORT_REQUIRED/);
});
test('production rejects malformed ports, hostnames, path controls and listener collisions', () => {
    for (const value of ['0', '-1', '65536', '1.5', '2e3', '08080', 'secret-not-a-port']) {
        assert.throws(() => Read({ ...Environment(), CONNECT_TCP_PORT:value }), /RUNTIME_CONFIG_CONNECT_TCP_PORT_INVALID/);
    }
    for (const value of ['admin.example.invalid', 'https://example.invalid', '127.0.0.1\nSECRET'])
        assert.throws(() => Read({ ...Environment(), CONNECT_TCP_HOST:value }), /RUNTIME_CONFIG_CONNECT_TCP_HOST_INVALID/);
    for (const value of ['relative/data', path.parse(os.tmpdir()).root, os.tmpdir() + '\0SECRET'])
        assert.throws(() => Read({ ...Environment(), DATA_DIR:value }), /RUNTIME_CONFIG_DATA_DIR_INVALID/);
    assert.throws(() => Read({ ...Environment(), CONNECT_TCP_PORT:'23102' }), /LISTENER_PORTS_CONFLICT/);
    assert.throws(() => Read({ ...Environment(), HEALTH_PORT:'23102' }), /LISTENER_PORTS_CONFLICT/);
    assert.throws(() => Read({ ...Environment(), PORT:'23103' }), /HTTP_PORT_MISMATCH/);
});
test('managed aliases are read from variables and explicit invalid configuration is never replaced', () => {
    const env = Environment(); delete env.CONNECT_TCP_PORT; delete env.WEB_ADMIN_PORT;
    env.RAILWAY_TCP_APPLICATION_PORT = '23103';
    assert.equal(Read(env).CONNECT_TCP_PORT, 23103); assert.equal(Read(env).WEB_ADMIN_PORT, 23102);
    assert.throws(() => Read({ ...env, CONNECT_TCP_PORT:'invalid' }), /CONNECT_TCP_PORT_INVALID/);
});
test('configuration errors do not contain submitted secret-like values', () => {
    try { Read({ ...Environment(), CONNECT_TCP_PORT:'PRIVATE_MARKER_VALUE' }); assert.fail(); }
    catch (error) { assert.equal(error.message, 'RUNTIME_CONFIG_CONNECT_TCP_PORT_INVALID'); assert.ok(!error.message.includes('PRIVATE_MARKER_VALUE')); }
});
test('isolated test/development defaults do not apply to production', () => {
    const testConfig = Read({ NODE_ENV:'test', DATA_DIR:os.tmpdir() });
    assert.ok(testConfig.CONNECT_TCP_PORT > 0); assert.ok(testConfig.WEB_ADMIN_PORT > 0);
    assert.throws(() => Read({ NODE_ENV:'production' }), /RUNTIME_CONFIG_/);
});
test('endpoint startup logging carries status and variable names without operational values', () => {
    const file = path.resolve(__dirname, '../../services/network/peace.connect-endpoint.js');
    const stdout = [], module = { exports:{} }, req = createRequire(file);
    vm.runInNewContext(fs.readFileSync(file, 'utf8'), { module, exports:module.exports,
        require:name => name.includes('peace.runtime-configuration') ? { WEB_UI_REVISION:'TEST', WEB_ADMIN_PORT:23102, CONNECT_TCP_PORT:23101 } :
            name.includes('peace.connect-tls') ? { Status:() => ({ ready:true }) } : req(name),
        console:{ log:(...a) => stdout.push(a.join(' ')), warn:(...a) => stdout.push(a.join(' ')) },
        process:{ env:{ DESKTOP_PUBLIC_HOST:'operator-private.example.invalid', DESKTOP_PUBLIC_PORT:'23109', PORT:'23102' } }
    }, { filename:file });
    module.exports.LogConfiguration();
    const output = stdout.join('\n');
    assert.match(output, /CONFIGURED/); assert.ok(!output.includes('operator-private.example.invalid'));
    for (const value of ['23101', '23102', '23109']) assert.ok(!output.includes(value));
});
const roles = [
    ['witness', 'WITNESS_HOST', 'WITNESS_PORT', 'tools/recovery/peace.recovery-witness-server.js'],
    ['packer', 'PACKER_HOST', 'PACKER_PORT', 'tools/artifacts/peace.packing-worker.js'],
    ['gateway', 'GATEWAY_HOST', 'PORT', 'tools/web/peace.admin-gateway.js']
];
for (const [role, hostKey, portKey, file] of roles) test(role + ' entrypoint requires validated production listener variables before TLS/storage setup', () => {
    const valid = { NODE_ENV:'production', [hostKey]:'127.0.0.1', [portKey]:'23104' };
    assert.deepEqual(ReadListener(role, valid), { host:'127.0.0.1', port:23104 });
    for (const bad of ['0', '-1', '65536', 'not-a-port', 'PRIVATE_PORT_MARKER'])
        assert.throws(() => ReadListener(role, { ...valid, [portKey]:bad }), new RegExp('RUNTIME_CONFIG_' + portKey + '_INVALID'));
    const missing = { NODE_ENV:'production' };
    assert.throws(() => ReadListener(role, missing), new RegExp('RUNTIME_CONFIG_' + hostKey + '_REQUIRED'));
    const result = spawnSync(process.execPath, [path.resolve(__dirname, '../..', file)], {
        env:{ NODE_ENV:'production', [hostKey]:'127.0.0.1', [portKey]:'PRIVATE_PORT_MARKER' }, encoding:'utf8', timeout:3000
    });
    assert.equal(result.status, 1); assert.ok(!result.error);
    const output = result.stdout + result.stderr;
    assert.match(output, new RegExp('RUNTIME_CONFIG_' + portKey + '_INVALID'));
    assert.ok(!output.includes('PRIVATE_PORT_MARKER')); assert.ok(!output.includes('Require stack'));
});
test('role listener fixtures retain explicit ephemeral ports without enabling production fallback', () => {
    for (const [role, hostKey, portKey] of roles) {
        assert.equal(ReadListener(role, { NODE_ENV:'test', [hostKey]:'127.0.0.1', [portKey]:'0' }).port, 0);
        assert.throws(() => ReadListener(role, { NODE_ENV:'production', [hostKey]:'127.0.0.1', [portKey]:'0' }), /RUNTIME_CONFIG_/);
    }
    assert.throws(() => ReadListener('PRIVATE_ROLE_MARKER', { NODE_ENV:'production' }), /^Error: RUNTIME_CONFIG_LISTENER_ROLE_INVALID$/);
});
