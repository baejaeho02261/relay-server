'use strict';
// Real HTTP sockets and production request handler in an isolated JSON fixture.
// Edge headers/RAILWAY_* environment values are synthetic; this is NOT a live
// Railway deployment or a demonstration that headers authenticate an ingress.
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const http = require('node:http'), net = require('node:net');
const { spawnSync } = require('node:child_process');
const ingress = require('../web/railwayIngress'), transport = require('../web/webTransport');
const base = { WEB_ADMIN_TRANSPORT: 'railway', WEB_ADMIN_RAILWAY_EDGE_ONLY: '1',
    WEB_ADMIN_HOST: '0.0.0.0', WEB_ADMIN_TRUSTED_PROXIES: '',
    PORT: '8080', WEB_ADMIN_PORT: '8080', CONNECT_TCP_PORT: '3000',
    HEALTH_PORT: '0', RAILWAY_TCP_APPLICATION_PORT: '',
    WEB_ADMIN_REQUIRE_HTTPS: '1', WEB_ADMIN_SECURE_COOKIE: '1',
    RAILWAY_PROJECT_ID: '11111111-1111-4111-8111-111111111111',
    RAILWAY_ENVIRONMENT_ID: '22222222-2222-4222-8222-222222222222',
    RAILWAY_SERVICE_ID: '33333333-3333-4333-8333-333333333333',
    WEBAUTHN_RP_ID: 'admin.example.test', WEBAUTHN_ORIGIN: 'https://admin.example.test' };
function headers(extra = {}) { return { host: 'backend.internal:8080',
    'x-forwarded-proto': 'https', 'x-forwarded-host': 'admin.example.test',
    'x-real-ip': '192.0.2.40', 'x-railway-request-id': 'Synthetic-Railway-Request-123', ...extra }; }
function request(extra = {}) { const h = headers(extra); return { headers: h,
    rawHeaders: Object.entries(h).flat(), socket: { remoteAddress: '10.0.0.12' } }; }
const configured = ingress.Settings(base);
let count = 0, server, oldServer, tmp;
async function test(name, fn) { await fn(); count++; console.log('PASS ' + name); }
function close(s) { return !s ? Promise.resolve() : new Promise(resolve => { s.closeAllConnections?.(); s.close(resolve); }); }
async function freePort() { const s=net.createServer(); await new Promise(r=>s.listen(0,'127.0.0.1',r)); const p=s.address().port; await new Promise(r=>s.close(r)); return p; }
function call(port, route, h = {}, body, target = '127.0.0.1', method) {
    return new Promise((resolve, reject) => {
        const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
        const req = http.request({ hostname: target, port, path: route, method: method || (bytes ? 'POST' : 'GET'),
            headers: {...h, ...(bytes ? {'content-type':'application/json','content-length':bytes.length} : {})} }, res => {
            let text = ''; res.on('data', b => text += b); res.on('end', () => {
                let parsed; try { parsed=JSON.parse(text); } catch (_) { parsed=text; }
                resolve({status:res.statusCode, headers:res.headers, body:parsed});
            });
        });
        req.setTimeout(4000,()=>req.destroy(Error('FIXTURE_TIMEOUT'))); req.on('error',reject); req.end(bytes);
    });
}
(async()=>{try {
    await test('Existing generic proxy remains loopback and rejects public binding',()=>{
        assert.equal(transport.Settings({}).host,'127.0.0.1');
        assert.throws(()=>transport.Settings({WEB_ADMIN_HOST:'0.0.0.0'}),/LOOPBACK_REQUIRED/);
    });
    await test('No implicit managed-ingress trust from Railway environment markers',()=>{
        const e={...base}; delete e.WEB_ADMIN_TRANSPORT; delete e.WEB_ADMIN_HOST; delete e.WEB_ADMIN_TRUSTED_PROXIES;
        assert.equal(transport.Settings(e).mode,'proxy');
    });
    await test('Explicit Railway mode accepts 0.0.0.0 without wildcard proxy CIDRs',()=>{
        assert.equal(transport.Settings(base).host,'0.0.0.0'); assert.equal(transport.TrustedProxySetting(base),'');
    });
    await test('Managed ingress requires explicit edge-only deployment acceptance',()=>{
        assert.throws(()=>transport.Settings({...base,WEB_ADMIN_RAILWAY_EDGE_ONLY:'0'}),/EDGE_ONLY_REQUIRED/);
    });
    await test('Missing platform markers fail instead of silently enabling elsewhere',()=>{
        for (const key of ['RAILWAY_PROJECT_ID','RAILWAY_ENVIRONMENT_ID','RAILWAY_SERVICE_ID'])
            assert.throws(()=>transport.Settings({...base,[key]:''}),/CONTEXT_REQUIRED/);
    });
    await test('Loopback, DNS and IPv6 wildcard are not accepted for this Railway adapter',()=>{
        for (const host of ['127.0.0.1','::','localhost']) assert.throws(()=>transport.Settings({...base,WEB_ADMIN_HOST:host}));
    });
    await test('Old proxy CIDRs must be removed, not silently ignored',()=>{
        for (const rule of ['127.0.0.1/32','0.0.0.0/0','::/0','10.0.0.0/8'])
            assert.throws(()=>transport.Settings({...base,WEB_ADMIN_TRUSTED_PROXIES:rule}),/CLEAR_TRUSTED_PROXIES/);
    });
    await test('HTTPS and Secure-cookie opt-outs still fail',()=>{
        for (const key of ['WEB_ADMIN_REQUIRE_HTTPS','WEB_ADMIN_SECURE_COOKIE'])
            assert.throws(()=>transport.Settings({...base,[key]:'0'}),/MUST_BE_1/);
    });
    await test('PORT and explicit web port must agree',()=>{
        assert.throws(()=>transport.Settings({...base,WEB_ADMIN_PORT:'8090'}),/PORT_MISMATCH/);
        for (const p of ['', '0', '65536', '-1', '8080.1','08080','${{UNRESOLVED}}'])
            assert.throws(()=>transport.Settings({...base,PORT:p}));
    });
    await test('Native TLS and HTTP ports cannot collide',()=>{
        assert.throws(()=>transport.Settings({...base,CONNECT_TCP_PORT:'8080'}),/TCP_PORT_CONFLICT/);
    });
    await test('Raw Railway TCP proxy may not target the web listener',()=>{
        assert.throws(()=>transport.Settings({...base,RAILWAY_TCP_APPLICATION_PORT:'8080'}),/TCP_EXPOSURE_FORBIDDEN/);
        assert.equal(ingress.Settings({...base,RAILWAY_TCP_APPLICATION_PORT:'3000'}).port,8080);
    });
    await test('Health listener may share HTTP but not the native listener',()=>{
        assert.equal(ingress.Settings({...base,HEALTH_PORT:'8080'}).healthPort,8080);
        assert.throws(()=>ingress.Settings({...base,HEALTH_PORT:'3000'}),/HEALTH_TCP_PORT_CONFLICT/);
    });
    await test('Explicit fixed RP and HTTPS origin are required',()=>{
        for (const e of [{WEBAUTHN_RP_ID:''},{WEBAUTHN_ORIGIN:''},{WEBAUTHN_ORIGIN:'http://admin.example.test'},
            {WEBAUTHN_ORIGIN:'https://evil.example.test'}]) assert.throws(()=>transport.Settings({...base,...e}));
    });
    await test('Documented single ingress headers establish secure context within declared boundary',()=>{
        assert.deepEqual(ingress.Origin(request(),configured),{ip:'192.0.2.40',https:true});
    });
    await test('Headers alone do not authenticate a private caller; isolation is an explicit assumption',()=>{
        const r=request();r.socket.remoteAddress='10.5.0.9';
        // Deliberately identical to an edge request. This is a documented trust
        // boundary limitation, NOT a claim that spoofed internal traffic is blocked.
        assert.equal(ingress.Origin(r,configured).https,true);
    });
    await test('Missing ingress headers fail HTTPS recognition',()=>{
        for (const key of Object.keys(headers())) {const r=request();delete r.headers[key];r.rawHeaders=Object.entries(r.headers).flat();
            assert.equal(ingress.Origin(r,configured).https,false,key);}
    });
    await test('HTTP, mixed schemes and duplicate proto headers are denied',()=>{
        for (const p of ['http','https,http','https, https',' https']) assert.equal(ingress.Origin(request({'x-forwarded-proto':p}),configured).https,false);
        const r=request();r.rawHeaders.push('X-Forwarded-Proto','https'); assert.equal(ingress.Origin(r,configured).https,false);
    });
    await test('Duplicate Host/forwarded host/client IP/request ID are rejected',()=>{
        for (const key of ['host','x-forwarded-host','x-real-ip','x-railway-request-id']) {
            const r=request();r.rawHeaders.push(key,r.headers[key]);assert.equal(ingress.Origin(r,configured).https,false);}
    });
    await test('Foreign, malformed and credential-bearing forwarded host are denied',()=>{
        for (const h of ['evil.example.test','admin.example.test.evil.test','user@admin.example.test',
            'admin.example.test/','admin.example.test:444','admin.example.test,evil.test'])
            assert.equal(ingress.Origin(request({'x-forwarded-host':h}),configured).https,false,h);
        assert.equal(ingress.Origin(request({'x-forwarded-host':'ADMIN.EXAMPLE.TEST:443'}),configured).https,true);
    });
    await test('Browser origin mismatch or duplicates are denied',()=>{
        assert.equal(ingress.Origin(request({origin:'https://evil.example.test'}),configured).https,false);
        assert.equal(ingress.Origin(request({origin:base.WEBAUTHN_ORIGIN}),configured).https,true);
        const r=request({origin:base.WEBAUTHN_ORIGIN});r.rawHeaders.push('origin',base.WEBAUTHN_ORIGIN);
        assert.equal(ingress.Origin(r,configured).https,false);
    });
    await test('Client address validates IPv4/IPv6 and ignores a forged forwarding chain',()=>{
        for (const ip of ['garbage','192.0.2.1:123','192.0.2.1,192.0.2.2','fe80::1%eth0'])
            assert.equal(ingress.Origin(request({'x-real-ip':ip}),configured).https,false);
        assert.equal(ingress.Origin(request({'x-real-ip':'2001:db8::1'}),configured).https,true);
        assert.equal(ingress.Origin(request({'x-forwarded-for':'8.8.8.8'}),configured).ip,'192.0.2.40');
    });
    await test('Request ID is bounded/validated, not treated as an authentication token',()=>{
        for (const id of ['x','x'.repeat(129),'bad,value','bad value'])
            assert.equal(ingress.Origin(request({'x-railway-request-id':id}),configured).https,false);
        // Any well-formed ID works ONLY as metadata; network isolation is essential.
        assert.equal(ingress.Origin(request({'x-railway-request-id':'Another-Synthetic-Id'}),configured).https,true);
    });
    await test('Railway PORT no longer becomes the native-TCP fallback',()=>{
        const out=spawnSync(process.execPath,['-e',"const c=require('./config/config');console.log(c.CONNECT_TCP_PORT,c.WEB_ADMIN_PORT)"],
            {cwd:path.resolve(__dirname,'..'),env:{...process.env,...base,PORT:'18080',WEB_ADMIN_PORT:'',CONNECT_TCP_PORT:'',RAILWAY_TCP_APPLICATION_PORT:''},encoding:'utf8'});
        assert.equal(out.status,0,out.stderr);assert.equal(out.stdout.trim(),'3000 18080');
    });
    await test('Non-Railway legacy port selection remains compatible',()=>{
        const out=spawnSync(process.execPath,['-e',"const c=require('./config/config');console.log(c.CONNECT_TCP_PORT,c.WEB_ADMIN_PORT)"],
            {cwd:path.resolve(__dirname,'..'),env:{...process.env,WEB_ADMIN_TRANSPORT:'proxy',PORT:'18081',WEB_ADMIN_PORT:'18082',CONNECT_TCP_PORT:'',RAILWAY_TCP_APPLICATION_PORT:''},encoding:'utf8'});
        assert.equal(out.status,0,out.stderr);assert.equal(out.stdout.trim(),'18081 18082');
    });
    tmp=fs.mkdtempSync(path.join(os.tmpdir(),'game-railway-web-'));
    const port=await freePort();
    Object.assign(process.env,base,{PORT:String(port),WEB_ADMIN_PORT:String(port),CONNECT_TCP_PORT:'3000',
        DATA_DIR:tmp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'temporary-railway-regression-password',VAPID_PUBLIC_KEY:'',VAPID_PRIVATE_KEY:''});
    require('../core/utils').EnsureDirs();
    const web=require('../web/webAuth'), context=require('../services/passkeyContext');
    await test('Passkey domain resolves to validated original domain, not backend Host',()=>{
        const req=request();assert.equal(web.IsHttps(req),true);
        assert.deepEqual(context.Resolve(req,web.IsHttps(req)),{rpId:base.WEBAUTHN_RP_ID,origin:base.WEBAUTHN_ORIGIN});
        assert.throws(()=>context.Resolve(request({'x-forwarded-host':'evil.example.test'}),true));
    });
    await test('Preflight validates mode/ports/RP without treating isolation as verified',()=>{
        const out=spawnSync(process.execPath,['tools/check-admin-security.js'],{cwd:path.resolve(__dirname,'..'),env:process.env,encoding:'utf8'});
        assert.equal(out.status,0,out.stderr);assert.match(out.stdout,/ADMIN_SECURITY_CONFIG_OK/);
        assert.match(out.stdout,/"railwayNetworkIsolationVerified": false/);
    });
    const { StartWebAdmin }=require('../web/webServer');
    await test('Production web server binds the actual non-loopback IPv4 listener',async()=>{
        server=StartWebAdmin();await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
        assert.equal(server.address().address,'0.0.0.0');assert.equal(server.address().port,port);
        const target=Object.values(os.networkInterfaces()).flat().find(x=>x&&!x.internal&&x.family==='IPv4');
        if(target) assert.equal((await call(port,'/',headers(),undefined,target.address)).status,200);
        else console.log('NOTE no non-loopback IPv4 interface; wildcard socket and loopback request still tested');
    });
    await test('Admin UI/password/passkey endpoints deny a plain request before login',async()=>{
        for (const route of ['/','/api/login','/api/passkey/login/begin','/api/session','/api/events']) {
            const out=await call(port,route,{},route.includes('login')?{role:'admin',password:process.env.ADMIN_SECRET}:undefined);
            assert.equal(out.status,403,route);assert.equal(out.body.error,'ADMIN_HTTPS_REQUIRED');assert.equal(out.headers['set-cookie'],undefined);
        }
    });
    let cookie;
    await test('Valid simulated edge requests still need credentials and set Secure cookies',async()=>{
        const bad=await call(port,'/api/login',headers(),{role:'admin',password:'wrong'});assert.equal(bad.status,401);
        const out=await call(port,'/api/login',headers(),{role:'admin',password:process.env.ADMIN_SECRET});
        assert.equal(out.status,200,JSON.stringify(out.body));cookie=out.headers['set-cookie'][0].split(';')[0];
        for (const flag of ['Secure','HttpOnly','SameSite=Strict']) assert.ok(out.headers['set-cookie'][0].includes(flag));
        assert.equal(out.headers['strict-transport-security'],'max-age=31536000');
    });
    await test('A valid cookie does not waive ingress validation on subsequent requests',async()=>{
        assert.equal((await call(port,'/api/session',{cookie})).status,403);
        assert.equal((await call(port,'/api/session',headers({cookie}))).status,200);
        assert.equal((await call(port,'/api/session',headers({cookie,'x-forwarded-proto':'http'}))).status,403);
    });
    await test('Real HTTP duplicate ingress header request is rejected',async()=>{
        const out=await call(port,'/',{...headers(),'x-forwarded-proto':['https','https']});assert.equal(out.status,403);
    });
    await test('Readiness with no native listener is honest 503, not a fabricated 200',async()=>{
        const out=await call(port,'/readyz',{host:'healthcheck.railway.app'});assert.equal(out.status,503);assert.equal(out.body.ok,false);
        assert.equal(out.headers['set-cookie'],undefined);
    });
    await test('Readiness permits Railway health Host without opening admin (synthetic native-ready state)',async()=>{
        const native=require('../services/desktopConnect'), saved=native.IsListening;
        native.IsListening=()=>true;
        try {const out=await call(port,'/readyz',{host:'healthcheck.railway.app'});assert.equal(out.status,200);
            const head=await call(port,'/readyz',{host:'healthcheck.railway.app'},undefined,'127.0.0.1','HEAD');assert.equal(head.status,200);assert.equal(head.body,'');
            assert.equal((await call(port,'/',{host:'healthcheck.railway.app'})).status,403);
        } finally {native.IsListening=saved;}
    });
    console.log(`RAILWAY WEB SECURITY PASS: ${count} cases; real HTTP + isolated JSON; synthetic edge; actual Railway/SQLite NOT_RUN.`);
} catch(error){console.error(error.stack||error);process.exitCode=1;} finally{
    await close(server);await close(oldServer);if(tmp)fs.rmSync(tmp,{recursive:true,force:true});
}})();
