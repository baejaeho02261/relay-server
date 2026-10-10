'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..'), temp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-writer-lock-'));
const lock = path.join(root, 'services/desktopSingleWriter.js');
const source = `require(${JSON.stringify(lock)}).Acquire(process.env.DATA_DIR,{haEnabled:process.env.HA_ENABLED==='1'});process.send('LOCKED');setInterval(()=>{},1000);`;
const children = new Set();
function Start(dir) {
  const child = spawn(process.execPath, ['-e', source], { cwd: root, env: { ...process.env, DATA_DIR: dir, HA_ENABLED: '0' }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  children.add(child); child.once('close', () => children.delete(child));
  let stderr = ''; child.stderr.on('data', bytes => { stderr += bytes; });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(Error('LOCK_TEST_TIMEOUT')); }, 8000);
    child.once('message', message => { clearTimeout(timer); assert.equal(message, 'LOCKED'); resolve(child); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(Error('LOCK_CHILD_EXIT_' + code + ':' + stderr)); });
  });
}
function Stop(child, signal) { return new Promise(resolve => { child.once('close', resolve); child.kill(signal); }); }
function Probe(dir, args = ['-e', source], extra = {}) {
  return spawnSync(process.execPath, args, { cwd: root, env: { ...process.env, DATA_DIR: dir, HA_ENABLED: '0', ...extra }, encoding: 'utf8', timeout: 8000 });
}
(async () => {
  try {
    const data = path.join(temp, 'data'), first = await Start(data);
    for (let i = 0; i < 3; i++) {
      const blocked = Probe(data);
      assert.equal(blocked.status, 1, blocked.stderr); assert.match(blocked.stderr, /DESKTOP_DATA_DIR_ALREADY_IN_USE/);
    }
    // The real entry point must fail before keys/migrations/audit/listeners.
    const server = Probe(data, ['server.js']);
    assert.equal(server.status, 1, server.stderr); assert.match(server.stderr, /DESKTOP_DATA_DIR_ALREADY_IN_USE/);
    for (const command of [['tools/tls-rotate.js', 'rotate', '--offline'], ['tools/sqlite-import.js', path.join(temp, 'missing-bundle.json'), path.join(data, 'relay.db')]]) {
      const maintenance = Probe(data, command, { CONNECT_TLS_CERT_FILE: '', CONNECT_TLS_KEY_FILE: '' });
      assert.equal(maintenance.status, 1, maintenance.stderr); assert.match(maintenance.stderr, /DESKTOP_DATA_DIR_ALREADY_IN_USE/);
    }
    assert.ok(fs.readdirSync(data).every(name => ['.desktop-single-writer.sqlite', '.desktop-single-writer.sqlite-journal'].includes(name)));
    if (process.platform !== 'win32') {
      const alias = path.join(temp, 'alias'); fs.symlinkSync(data, alias, 'dir');
      assert.match(Probe(alias).stderr, /DESKTOP_DATA_DIR_ALREADY_IN_USE/);
    }
    const race = await Promise.allSettled([Start(path.join(temp, 'race')), Start(path.join(temp, 'race'))]);
    assert.equal(race.filter(result => result.status === 'fulfilled').length, 1);
    assert.match(race.find(result => result.status === 'rejected').reason.message, /DESKTOP_DATA_DIR_ALREADY_IN_USE/);
    await Stop(race.find(result => result.status === 'fulfilled').value, 'SIGTERM');
    const independent = await Start(path.join(temp, 'independent')); await Stop(independent, 'SIGTERM');
    await Stop(first, 'SIGKILL');
    // Presence survives a crash; OS ownership does not. No stale-file removal.
    assert.ok(fs.existsSync(path.join(data, '.desktop-single-writer.sqlite')));
    const recovered = await Start(data); await Stop(recovered, 'SIGTERM');
    const restarted = await Start(data); await Stop(restarted, 'SIGTERM');
    const ha = Probe(path.join(temp, 'ha'), ['-e', source], { HA_ENABLED: '1' });
    assert.match(ha.stderr, /DESKTOP_SINGLE_WRITER_REQUIRED/); assert.equal(fs.existsSync(path.join(temp, 'ha')), false);
    const corrupt = path.join(temp, 'corrupt'); fs.mkdirSync(corrupt); fs.writeFileSync(path.join(corrupt, '.desktop-single-writer.sqlite'), 'not a SQLite database');
    const failure = Probe(corrupt); assert.equal(failure.status, 1); assert.match(failure.stderr, /DESKTOP_WRITER_LOCK_UNAVAILABLE/);
    console.log('SINGLE WRITER PASS: separate-process exclusion, real startup/maintenance before mutation, simultaneous race, path alias, independent directory, crash/restart recovery, HA and corrupt-lock refusal.');
  } finally {
    await Promise.all([...children].map(child => Stop(child, 'SIGKILL')));
    fs.rmSync(temp, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
