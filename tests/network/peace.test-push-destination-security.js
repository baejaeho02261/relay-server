'use strict';
// Isolated production modules. No external DNS, push provider, VAPID key or
// production subscription is contacted. Transport sockets below are mocks.
const test = require('node:test'), assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { Isolated } = require("../fixtures/protocol/peace.completion-6-10-fixture");
const policy = require("../../services/network/peace.push-destination");
delete process.env.WEB_PUSH_ALLOWED_HOSTS;
for (const endpoint of [
    'https://fcm.googleapis.com/fcm/send/test',
    'https://updates.push.services.mozilla.com/wpush/v2/test',
    'https://web.push.apple.com/Qtest',
    'https://wns2-test.notify.windows.com/w/?token=test'
]) test('allows declared provider: ' + new URL(endpoint).hostname, () => assert.equal(policy.ValidateEndpoint(endpoint).endpoint, endpoint));
for (const endpoint of [
    'http://fcm.googleapis.com/fcm/send/x', 'https://127.0.0.1/x', 'https://[::1]/x',
    'https://2130706433/x', 'https://0x7f000001/x', 'https://0177.0.0.1/x',
    'https://localhost/x', 'https://fcm.googleapis.com.evil.test/x',
    'https://evil-notify.windows.com/x', 'https://a.notify.windows.com.evil.test/x',
    'https://fcm.googleapis.com@evil.test/x', 'https://evil@fcm.googleapis.com/x',
    'https://fcm.googleapis.com:8443/x', 'https://fcm.googleapis.com./x',
    'https://fcm%2egoogleapis.com/x', "https:\\\\fcm.googleapis.com\\@evil.test\\x",
    'https://fcm.googleapis.com/x#y', ' https://fcm.googleapis.com/x',
    'https://fcm.googleapis.com/x\r\n', 'file:///etc/passwd'
]) test('rejects untrusted/ambiguous endpoint: ' + JSON.stringify(endpoint), () => assert.throws(() => policy.ValidateEndpoint(endpoint), /^Error: PUSH_/));
test('exact server host override replaces defaults; wildcard/empty overrides fail', () => {
    try {
        process.env.WEB_PUSH_ALLOWED_HOSTS = 'push.example.test';
        assert.equal(policy.ValidateEndpoint('https://push.example.test/x').hostname, 'push.example.test');
        assert.throws(() => policy.ValidateEndpoint('https://fcm.googleapis.com/x'), /PUSH_HOST_NOT_ALLOWED/);
        for (const raw of ['', '*', '*.example.test', '127.0.0.1', 'a.test,a.test', 'https://a.test']) {
            process.env.WEB_PUSH_ALLOWED_HOSTS = raw; assert.throws(() => policy.Policy(), /PUSH_HOST_POLICY_INVALID/);
        }
    } finally { delete process.env.WEB_PUSH_ALLOWED_HOSTS; }
});
test('blocks IPv4/IPv6 private, metadata, special, mapped and transition ranges', () => {
    for (const ip of ['0.1.2.3','10.1.2.3','100.64.0.1','127.1.2.3','169.254.169.254','172.16.1.1',
        '192.0.0.9','192.168.1.1','192.0.2.1','192.88.99.1','198.18.0.1','198.51.100.1','203.0.113.1',
        '224.1.2.3','255.255.255.255','168.63.129.16','::','::1','fc00::1','fe80::1','ff02::1',
        '::ffff:8.8.8.8','64:ff9b::808:808','2001::1','2001:db8::1','2002:0808:0808::1','3fff::1','fe80::1%eth0'])
        assert.equal(policy.IsPublicAddress(ip), false, ip);
    for (const ip of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(policy.IsPublicAddress(ip), true, ip);
});
function ResolverFixture(v4, v6) {
    const calls = []; let cancelled = 0;
    class Resolver {
        resolve4(host) { calls.push([4,host]); return typeof v4 === 'function' ? v4() : Promise.resolve(v4); }
        resolve6(host) { calls.push([6,host]); return typeof v6 === 'function' ? v6() : Promise.resolve(v6); }
        cancel() { cancelled++; }
    }
    return { calls, cancelled: () => cancelled,
        module: Isolated("services/network/peace.push-destination.js", [], { 'node:dns/promises': { Resolver } }) };
}
const missing = () => Promise.reject(Object.assign(Error(), { code:'ENODATA' }));
test('all DNS answers must be public; mixed A/AAAA answers fail before connection', async () => {
    for (const [a,aaaa] of [[['8.8.8.8','127.0.0.1'],[]],[['8.8.8.8'],['::1']],[[],['::ffff:8.8.8.8']]])
        await assert.rejects(ResolverFixture(a,aaaa).module.ResolveEndpoint('https://fcm.googleapis.com/x'), /PUSH_ADDRESS_NOT_PUBLIC/);
});
test('pins one validated numeric address, preserves original host/path, cancels resolver', async () => {
    const f = ResolverFixture(['8.8.8.8'], missing);
    assert.deepEqual(await f.module.ResolveEndpoint('https://fcm.googleapis.com/x?q=1'), {
        endpoint:'https://fcm.googleapis.com/x?q=1', hostname:'fcm.googleapis.com', path:'/x?q=1',address:'8.8.8.8',family:4
    });
    assert.equal(f.calls.length,2); assert.equal(f.cancelled(),1);
});
test('rejects empty, invalid-family, oversized and DNS-failure results', async () => {
    for (const f of [ResolverFixture([],[]), ResolverFixture(['2606:4700::1'],[]),
        ResolverFixture(Array(33).fill('8.8.8.8'),[]), ResolverFixture(['8.8.8.8'],() => Promise.reject({code:'ESERVFAIL'}))])
        await assert.rejects(f.module.ResolveEndpoint('https://fcm.googleapis.com/x'), /^Error: PUSH_/);
});
test('DNS timeout cancels outstanding resolver; rejected hostname never triggers DNS', async () => {
    const f = ResolverFixture(() => new Promise(() => {}), () => new Promise(() => {}));
    await assert.rejects(f.module.ResolveEndpoint('https://fcm.googleapis.com/x', 5), /PUSH_DNS_TIMEOUT/);
    assert(f.cancelled() >= 1);
    const other = ResolverFixture([],[]); await assert.rejects(other.module.ResolveEndpoint('https://localhost/x'));
    assert.equal(other.calls.length,0);
});
test('peer comparison accepts equivalent IPv6, but never a different or private address', () => {
    assert(policy.PeerMatches('2606:4700:0000:0000:0000:0000:0000:1111',{address:'2606:4700::1111',family:6}));
    assert(policy.PeerMatches('::ffff:8.8.8.8',{address:'8.8.8.8',family:4}));
    assert(!policy.PeerMatches('1.1.1.1',{address:'8.8.8.8',family:4}));
    assert(!policy.PeerMatches('127.0.0.1',{address:'8.8.8.8',family:4}));
});
function TransportFixture({ statusCode = 201, peer = '8.8.8.8', authorized = true, responseSize = 0, earlyClose = false, badDetails = false } = {}) {
    const captured = [], bodies = []; let generated;
    const module = Isolated("services/network/peace.push-transport.js", [], {
        './peace.push-destination': { ...policy, ResolveEndpoint: async raw => ({...policy.ValidateEndpoint(raw),address:'8.8.8.8',family:4}) },
        'node:https': { request(options, callback) {
            captured.push(options); const req = new EventEmitter();
            req.destroy = () => { req.destroyed = true; };
            req.end = body => {
                bodies.push(Buffer.from(body));
                const res = new EventEmitter(); res.statusCode = statusCode; res.destroy = () => {};
                callback(res); if (responseSize) res.emit('data',Buffer.alloc(responseSize)); res.emit('end');
            };
            queueMicrotask(() => {
                if (earlyClose) return req.emit('close');
                const socket = new EventEmitter(); socket.remoteAddress=peer; socket.authorized=authorized;
                req.emit('socket',socket); assert.equal(bodies.length,0, 'no request before TLS peer check'); socket.emit('secureConnect');
            }); return req;
        } }
    });
    const webPush = { generateRequestDetails(subscription) {
        generated=Buffer.from('encrypted-fixture');
        return {endpoint:badDetails?'https://127.0.0.1/x':subscription.endpoint,method:'POST',headers:{Authorization:'fixture'},body:generated};
    } };
    const run = () => module.Send(webPush,{endpoint:'https://fcm.googleapis.com/x'},'fixture',{});
    return { run,captured,bodies,generated:()=>generated };
}
test('direct HTTPS writer uses pinned address, original TLS identity, no proxy/agent and bounded headers', async () => {
    const f=TransportFixture(); assert.deepEqual(await f.run(),{statusCode:201});
    const o=f.captured[0]; assert.equal(o.hostname,'8.8.8.8');assert.equal(o.port,443);assert.equal(o.servername,'fcm.googleapis.com');
    assert.equal(o.headers.Host,'fcm.googleapis.com');assert.equal(o.rejectUnauthorized,true);assert.equal(o.agent,false);
    assert.equal(o.minVersion,'TLSv1.2');assert.equal(typeof o.checkServerIdentity,'function');assert.equal(o.lookup,undefined);
    assert.equal(f.bodies.length,1);assert(f.generated().every(x=>x===0));
});
test('invalid peer or TLS authorization sends no HTTP body', async () => {
    for (const options of [{peer:'127.0.0.1'},{peer:'1.1.1.1'},{authorized:false}]) {
        const f=TransportFixture(options); await assert.rejects(f.run(), /PUSH_PEER_INVALID/); assert.equal(f.bodies.length,0);
    }
});
test('redirect is rejected, never followed; 404 preserves subscription-removal signal', async () => {
    for(const statusCode of [301,302,307,308,404,410]) {
        const f=TransportFixture({statusCode}); await assert.rejects(f.run(), e => e.statusCode===statusCode);
        assert.equal(f.captured.length,1);
    }
});
test('response size, malformed generated request and early close fail closed', async () => {
    for(const [options,code] of [[{responseSize:16385},'PUSH_RESPONSE_TOO_LARGE'],[{badDetails:true},'PUSH_REQUEST_INVALID'],[{earlyClose:true},'PUSH_CONNECTION_CLOSED']])
        await assert.rejects(TransportFixture(options).run(), new RegExp(code));
});
