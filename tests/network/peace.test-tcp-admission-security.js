"use strict";
const assert = require('node:assert/strict'), { EventEmitter } = require('node:events');
const { Admission } = require("../../services/network/peace.desktop-connection-admission");
const { Isolated } = require("../fixtures/protocol/peace.completion-6-10-fixture");
let count = 0; function test(name, fn) { fn(); count++; console.log('PASS ' + name); }
const take = (a, ip) => { const t = a.Acquire(ip); t.release(); return t; };
test('Rejected single-IP flood cannot exhaust the shared 1800-connection budget', () => {
    const a = new Admission({ now: () => 0 }); for (let i = 0; i < 1200; i++) take(a, '192.0.2.1');
    for (let i = 0; i < 5000; i++) assert.throws(() => a.Acquire('192.0.2.1'), /RATE/);
    assert.equal(a.global.count, 1200); take(a, '192.0.2.2'); assert.equal(a.global.count, 1201);
});
test('Per-IP active socket rejection consumes neither global tokens nor entries', () => {
    const a = new Admission(), tickets = Array.from({ length: 32 }, () => a.Acquire('192.0.2.1'));
    for (let i = 0; i < 2000; i++) assert.throws(() => a.Acquire('192.0.2.1'), /CAPACITY/);
    assert.equal(a.global.count, 32); take(a, '192.0.2.2'); tickets.forEach(t => t.release()); assert.equal(a.active, 0);
});
test('Global active capacity is retained; rejected peers cannot allocate rate entries', () => {
    const a = new Admission({ activeMax: 1 }); const t = a.Acquire('192.0.2.1');
    assert.throws(() => a.Acquire('192.0.2.2'), /CAPACITY/); assert.equal(a.rows.size, 1); assert.equal(a.global.count, 1);
    t.release(); take(a, '192.0.2.2'); assert.equal(a.active, 0);
});
test('Global rate rejection does not spend a new peer token or grow the map', () => {
    const a = new Admission({ globalMax: 2 }); take(a, '192.0.2.1'); take(a, '192.0.2.2');
    assert.throws(() => a.Acquire('192.0.2.3'), /RATE/); assert.equal(a.rows.size, 2); assert.equal(a.global.count, 2);
});
test('Rejected attempts do not prolong fixed window expiry', () => {
    let tick = 0; const a = new Admission({ now: () => tick, ipMax: 1, windowMs: 1000 }); take(a, '192.0.2.1');
    tick = 999; assert.throws(() => a.Acquire('192.0.2.1'), /RATE/); assert.equal(a.rows.get('192.0.2.1').until, 1000);
    tick = 1000; take(a, '192.0.2.1'); assert.equal(a.global.count, 1);
});
test('Admission uses its monotonic clock, and injected rollback fails closed', () => {
    let tick = 100; const a = new Admission({ now: () => tick }); take(a, '192.0.2.1'); tick = 99;
    assert.throws(() => a.Acquire('192.0.2.2'), /CLOCK/); assert.equal(a.global.count, 1);
});
test('Entry bound is exact and expired inactive entries can be reclaimed', () => {
    let tick = 0; const a = new Admission({ maxEntries: 2, windowMs: 1000, now: () => tick });
    take(a, '192.0.2.1'); take(a, '192.0.2.2'); assert.throws(() => a.Acquire('192.0.2.3'), /CAPACITY/);
    assert.equal(a.rows.size, 2); assert.equal(a.global.count, 2); tick = 1000; take(a, '192.0.2.3'); assert.equal(a.rows.size, 1);
});
test('Expired windows never discard live socket accounting', () => {
    let tick = 0; const a = new Admission({ ipActiveMax: 1, windowMs: 1000, now: () => tick }), t = a.Acquire('192.0.2.1');
    tick = 1000; assert.throws(() => a.Acquire('192.0.2.1'), /CAPACITY/); t.release(); take(a, '192.0.2.1'); assert.equal(a.active, 0);
});
test('Duplicate close/release is idempotent and cannot underflow counters', () => {
    const a = new Admission(), t = a.Acquire('192.0.2.1'); assert.equal(t.release(), true); assert.equal(t.release(), false);
    assert.equal(a.active, 0); assert.equal(a.rows.get('192.0.2.1').active, 0); assert.equal(a.global.count, 1);
});
test('Equivalent IPv4/mapped IPv6 spellings share the same peer budget', () => {
    const a = new Admission({ ipMax: 1 }); take(a, '192.0.2.1');
    for (const ip of ['::ffff:192.0.2.1', '::ffff:c000:201']) assert.throws(() => a.Acquire(ip), /RATE/);
    assert.equal(a.rows.size, 1);
});
test('Invalid peers and settings fail without allocating connection state', () => {
    const a = new Admission(); for (const ip of ['', 'UNKNOWN', '127.0.0.1:1', 'fe80::1%eth0']) assert.throws(() => a.Acquire(ip), /PEER/);
    assert.equal(a.rows.size, 0); assert.equal(a.global.count, 0);
    for (const globalMax of [0, -1, NaN, Infinity, '1']) assert.throws(() => new Admission({ globalMax }));
});
test('Production pre-TLS connection handler integrates atomic admission and close cleanup', () => {
    const work = { connections: { active: 0 } }; let counter = 0;
    const serverApi = Isolated("services/network/peace.desktop-connect.js", [], {
        'node:tls': { createServer() { return new EventEmitter(); } },
        "../licensing/peace.desktop-licenses": {}, './peace.connect-transport-key': { Load() {} }, "../bootstrap/peace.desktop-bootstrap": { Initialize() {} },
        './peace.connect-tls': { Load() { return { options: {} }; } }, "../runtime/peace.desktop-work-queue": work,
        './peace.desktop-connection-admission': { Admission: class extends Admission { constructor() { super({ now: () => 0 }); } } }
    });
    const server = serverApi.CreateServer();
    function socket(ip) {
        const s = new EventEmitter(); Object.assign(s, { localAddress: '127.0.0.1', localPort: 3000, remoteAddress: ip, remotePort: ++counter, destroyed: false });
        s.destroy = () => { if (!s.destroyed) { s.destroyed = true; s.emit('close'); } }; server.emit('connection', s); return s;
    }
    for (let i = 0; i < 1200; i++) { const s = socket('192.0.2.1'); assert.equal(s.destroyed, false); s.destroy(); }
    for (let i = 0; i < 5000; i++) assert.equal(socket('192.0.2.1').destroyed, true);
    const healthy = socket('192.0.2.2'); assert.equal(healthy.destroyed, false); assert.equal(work.connections.active, 1);
    healthy.destroy(); assert.equal(work.connections.active, 0);
});
console.log(`TCP ADMISSION SECURITY PASS: ${count} cases; deterministic limiter + production handler with synthetic sockets`);
