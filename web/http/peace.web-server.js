'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");


const webTransport = require("../transport/peace.web-transport");
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const config = require("../../config/peace.runtime-configuration");
const { HealthSnapshot } = require("../../services/observability/peace.dashboard.js");
const { LogEvent } = require("../../storage/audit/peace.audit.js");
const {
    SessionCookie, SESSION_MS, Login, Authenticate, Logout, ValidateCsrf, CheckLoginAttempt, Reauthenticate
} = require("../authentication/peace.web-auth");
const { Json, ApiError, ReadJsonBody, HandleApiRequest } = require('./peace.web-api');
const { OpenEventStream } = require("../events/peace.web-events");
const { RecordAdminActivity } = require("../../services/operations/peace.admin-activity");
const releaseManager = require("../../services/artifacts/peace.release-manager");

const PUBLIC_DIR = path.resolve(MODULE_RESOURCE_ROOT, '..', 'public');
const uiBundle = require("../assets/peace.ui-bundle");
// At most one outstanding reauthentication challenge per live session.
const reauthChallenges = new WeakMap();
function AuthFailure(res, result) {
    if (result.retryAfterSeconds) res.setHeader('Retry-After', String(result.retryAfterSeconds));
    ApiError(res, result.status || 401, result.code || result.reason || 'AUTH_FAILED');
}
function PlainObject(body) { return !!body && typeof body === 'object' && !Array.isArray(body); }

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon'
};

function SecurityHeaders(req, res) {
    if (require("../authentication/peace.web-auth").IsHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}


function ReadReleaseUpload(req, meta) {
    return new Promise((resolve, reject) => {
        releaseManager.SigningSecret();
        const crypto = require('crypto');
        const os = require('os');
        const tmpDir = require('path').join(config.DATA_DIR, 'releases', '.tmp');
        fs.mkdirSync(tmpDir, { recursive: true });
        const tmp = require('path').join(tmpDir, `upload-${Date.now()}-${crypto.randomBytes(8).toString('hex')}.tmp`);
        const out = fs.createWriteStream(tmp, { flags: 'wx', mode: 0o600 });
        const hash = crypto.createHash('sha256');
        let size = 0;
        let failed = false;
        const fail = error => {
            if (failed) return;
            failed = true;
            try { out.destroy(); } catch (_) {}
            try { fs.unlinkSync(tmp); } catch (_) {}
            reject(error);
        };
        req.on('data', chunk => {
            if (failed) return;
            size += chunk.length;
            if (size > releaseManager.MAX_RELEASE_BYTES) {
                fail(new Error('RELEASE_TOO_LARGE'));
                try { req.destroy(); } catch (_) {}
                return;
            }
            hash.update(chunk);
            if (!out.write(chunk)) req.pause(), out.once('drain', () => req.resume());
        });
        req.on('end', () => {
            if (failed) return;
            out.end(() => resolve({ tmp, size, sha256: hash.digest('hex'), meta }));
        });
        req.on('error', fail);
        out.on('error', fail);
    });
}

function ServeUpdateArtifact(req, res, pathname, url) {
    const match = pathname.match(/^\/updates\/([A-Za-z0-9]+)$/);
    if (!match) return false;
    const artifactId = match[1];
    if (!releaseManager.VerifyDownload(artifactId, url.searchParams.get('exp'), url.searchParams.get('sig'))) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('Forbidden');
        return true;
    }
    const release = releaseManager.FindArtifact(artifactId);
    if (release?.type === 'CLIENT') { require("../../services/runtime/peace.desktop-mode").Reject(res); return true; }
    const file = releaseManager.ArtifactPath(release);
    if (!release || !file || !fs.existsSync(file)) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('Not found');
        return true;
    }
    const stat = fs.statSync(file);
    // Filesystem work can cross a deadline; validate the live capability again
    // before sending headers/bytes. This cannot recall bytes already delivered.
    if (!stat.isFile() || !releaseManager.VerifyDownload(artifactId, url.searchParams.get('exp'), url.searchParams.get('sig'))) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('Forbidden'); return true;
    }
    res.writeHead(200, {
        'Content-Type': release.type === 'CLIENT' && file.toLowerCase().endsWith('.apk') ? 'application/vnd.android.package-archive' : 'application/octet-stream',
        'Content-Length': stat.size,
        'Content-Disposition': `attachment; filename="${release.originalName || release.fileName}"`,
        'Cache-Control': 'private, no-store',
        'X-Content-SHA256': release.sha256
    });
    if (String(req.method || 'GET').toUpperCase() === 'HEAD') { res.end(); return true; }
    fs.createReadStream(file).pipe(res);
    return true;
}

function ServeFile(req, res, fileName) {
    const safeName = fileName === '/' ? 'index.html' : fileName.replace(/^\/+/, '');
    const full = path.resolve(PUBLIC_DIR, safeName);
    if (!full.startsWith(PUBLIC_DIR + path.sep) && full !== path.join(PUBLIC_DIR, 'index.html')) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not found');
        return;
    }
    if (safeName === 'index.html' && !uiBundle.Check().ready) {
        uiBundle.Unavailable(res, String(req.method).toUpperCase() === 'HEAD');
        return;
    }
    const ext = path.extname(full).toLowerCase();
    const stat = fs.statSync(full);
    const headers = {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Content-Length': stat.size,
        'Cache-Control': ['.html', '.js', '.css'].includes(ext)
            ? 'no-cache, no-store, must-revalidate'
            : 'public, max-age=3600'
    };
    if (safeName === 'peace.service-worker.js') headers['Service-Worker-Allowed'] = '/';
    res.writeHead(200, headers);
    if (String(req.method || 'GET').toUpperCase() === 'HEAD') { res.end(); return; }
    fs.createReadStream(full).pipe(res);
}

async function RequestHandler(req, res) {
    SecurityHeaders(req, res);
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;
    const method = String(req.method || 'GET').toUpperCase();
    const reset=require('../../services/operations/peace.registration-reset');
    if(reset.IsDraining()&&pathname.startsWith('/api/')&&!(method==='GET'&&pathname===reset.PATH)){ApiError(res,503,'REGISTRATION_RESET_IN_PROGRESS');return;}
    const desktopMode = require("../../services/runtime/peace.desktop-mode");
    if (desktopMode.RetiredPath(pathname)) { desktopMode.Reject(res); return; }
    // Desktop HMAC challenge/execute have their own authentication, rate limits
    // and replay checks. Never route them through an administrator cookie.
    if (await require('./peace.desktop-api').Handle(req, res, url)) return;
    if (await require('./peace.diagnostic-capture-public').Handle(req, res, url)) return;
    if (pathname === '/diagnostics.html') {
        res.setHeader('Cache-Control', 'private, no-store');
        res.setHeader('Permissions-Policy', 'display-capture=(self), camera=(), microphone=(), geolocation=()');
        res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src blob:; media-src blob:; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    }

    if (pathname.startsWith('/internal/ha/')) {
        if (await require("../../services/network/peace.ha-coordinator").HandleInternal(req, res, pathname)) return;
    }

    // Deployment readiness is independent of an administrator disabling
    // licensed operations: the admin web must still be deployable in that state.
    if (pathname === '/readyz' && (method === 'GET' || method === 'HEAD')) {
        const ready = require("../../services/network/peace.desktop-connect").IsListening() && uiBundle.Check().ready;
        Json(res, ready ? 200 : 503, { ok: ready, revision: config.WEB_UI_REVISION });
        return;
    }

    if ((pathname === '/health' || pathname === '/healthz') && method === 'GET') {
        const body = HealthSnapshot();
        Json(res, body.ok ? 200 : 503, body);
        return;
    }

    if ((method === 'GET' || method === 'HEAD') && pathname.startsWith('/updates/')) {
        if (ServeUpdateArtifact(req, res, pathname, url)) return;
    }

    // Public readiness/legacy signed downloads above retain their own rules.
    // Reject admin UI, session, SSE and all admin API traffic before body reads.
    if (!require("../authentication/peace.web-auth").IsHttps(req)) {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Connection', 'close');
        ApiError(res, 403, 'ADMIN_HTTPS_REQUIRED');
        return;
    }

    if (pathname === '/api/login' && method === 'POST') {
        let body;
        try { body = await ReadJsonBody(req); }
        catch (error) { ApiError(res, 400, error.message); return; }
        if (!PlainObject(body)) { ApiError(res, 400, 'INPUT_INVALID'); return; }
        const result = Login(req, body.role, body.password);
        if (!result.ok) {
            if (result.status !== 429) RecordAdminActivity(String(body.role || '').toLowerCase(), require("../authentication/peace.web-auth").ClientIP(req), 'POST', '/api/login', result.status || 401, 'LOGIN_FAILED');
            AuthFailure(res, result);
            return;
        }
        RecordAdminActivity(result.session.role, result.session.ip, 'POST', '/api/login', 200, 'LOGIN');
        res.setHeader('Set-Cookie', SessionCookie(req, result.session.token, SESSION_MS / 1000));
        Json(res, 200, {
            ok: true,
            role: result.session.role,
            csrf: result.session.csrf,
            expiresAt: result.session.expiresAt
        });
        return;
    }

    if (pathname === '/api/passkey/login/begin' && method === 'POST') {
        let body; try { body = await ReadJsonBody(req); } catch (error) { ApiError(res, 400, error.message); return; }
        if (!PlainObject(body)) { ApiError(res, 400, 'INPUT_INVALID'); return; }
        const limited = CheckLoginAttempt(req, body.role);
        if (!limited.ok) { AuthFailure(res, limited); return; }
        const result = require("../../services/authentication/peace.passkey-auth").LoginBegin(body.role, req);
        if (!result.ok) ApiError(res, result.status || 400, result.reason); else Json(res, 200, result);
        return;
    }

    if (pathname === '/api/passkey/login/finish' && method === 'POST') {
        let body; try { body = await ReadJsonBody(req); } catch (error) { ApiError(res, 400, error.message); return; }
        if (!PlainObject(body)) { ApiError(res, 400, 'INPUT_INVALID'); return; }
        const limited = CheckLoginAttempt(req, '');
        if (!limited.ok) { AuthFailure(res, limited); return; }
        const result = require("../../services/authentication/peace.passkey-auth").LoginFinish(req, body);
        if (!result.ok) { ApiError(res, 401, result.reason); return; }
        const session = require("../authentication/peace.web-auth").CreateSession(req, result.role, { credentialId: result.credentialId });
        if (!session) { ApiError(res, 503, 'ADMIN_SESSION_CAPACITY'); return; }
        require("../../services/authentication/peace.desktop-admin-guard").MarkVerified(session,result.credentialId);
        res.setHeader('Set-Cookie', SessionCookie(req, session.token, SESSION_MS / 1000));
        Json(res, 200, { ok:true, role:session.role, csrf:session.csrf, expiresAt:session.expiresAt });
        return;
    }

    if (pathname.startsWith('/api/')) {
        const session = Authenticate(req);
        if (!session) {
            ApiError(res, 401, 'NOT_AUTHORIZED');
            return;
        }

        // Refresh browser cookie only up to the server's remaining idle/absolute lifetime.
        res.setHeader('Set-Cookie', SessionCookie(req, session.token, (session.expiresAt - Date.now()) / 1000));

        if (pathname === '/api/session' && method === 'GET') {
            Json(res, 200, {
                ok: true,
                role: session.role,
                id: session.id, csrf: session.csrf,
                expiresAt: session.expiresAt
            });
            return;
        }

        if (pathname === '/api/events' && method === 'GET') {
            OpenEventStream(req, res, session);
            return;
        }

        if (pathname === '/api/releases/upload' && method === 'POST') {
            if (desktopMode.RetiredTarget(pathname, {}, url.searchParams)) { desktopMode.Reject(res); return; }
            if (!ValidateCsrf(req, session)) { ApiError(res, 403, 'CSRF_FAILED'); return; }
            if (session.role !== 'admin') { ApiError(res, 403, 'FORBIDDEN'); return; }
            if (!require("../../services/network/peace.ha-coordinator").CanAcceptTraffic()) { ApiError(res, 409, 'RELAY_STANDBY_READ_ONLY'); return; }
            const meta = {
                type: url.searchParams.get('type'), channel: url.searchParams.get('channel'), version: url.searchParams.get('version'),
                fileName: url.searchParams.get('fileName'), mandatory: url.searchParams.get('mandatory') === '1',
                rolloutPercent: Number(url.searchParams.get('rolloutPercent') || 100), notes: url.searchParams.get('notes') || ''
            };
            try {
                const upload = await ReadReleaseUpload(req, meta);
                if(reset.IsDraining()){try{fs.unlinkSync(upload.tmp);}catch(_){}ApiError(res,503,'REGISTRATION_RESET_IN_PROGRESS');return;}
                // A slow upload must not retain authority after logout, expiry
                // or credential rotation. Never publish its temporary file.
                if (!require("../authentication/peace.web-auth").IsSessionActive(session)) {
                    try { fs.unlinkSync(upload.tmp); } catch (_) {}
                    ApiError(res, 401, 'NOT_AUTHORIZED'); return;
                }
                const release = releaseManager.PublishFromTemp(meta, upload.tmp, upload.sha256, upload.size);
                require("../../storage/snapshots/peace.database.js").SaveDatabase();
                LogEvent('RELEASE_PUBLISHED', `${release.type}/${release.channel} ${release.version} ${release.sha256}`);
                RecordAdminActivity(session.role, session.ip, method, pathname, 200, 'RELEASE_UPLOAD');
                Json(res, 200, { ok: true, release });
            } catch (error) {
                ApiError(res, error.message === 'RELEASE_TOO_LARGE' ? 413 : 400, error.message || 'RELEASE_UPLOAD_FAILED');
            }
            return;
        }

        if (!['GET', 'HEAD'].includes(method) && !ValidateCsrf(req, session)) {
            RecordAdminActivity(session.role, session.ip, method, pathname, 403, 'CSRF_FAILED');
            ApiError(res, 403, 'CSRF_FAILED');
            return;
        }

        if (!['GET', 'HEAD'].includes(method)) {
            res.once('finish', () => {
                RecordAdminActivity(session.role, session.ip, method, pathname, res.statusCode, pathname === '/api/logout' ? 'LOGOUT' : 'MUTATION');
            });
        }

        if (method === 'POST' && ['/api/session/reauthenticate', '/api/session/reauthenticate/passkey/begin', '/api/session/reauthenticate/passkey/finish'].includes(pathname)) {
            let body;
            try { body = await ReadJsonBody(req, 16384); }
            catch (error) { ApiError(res, 400, error.message); return; }
            if (!require("../authentication/peace.web-auth").IsSessionActive(session)) { ApiError(res, 401, 'NOT_AUTHORIZED'); return; }
            if (!PlainObject(body)) { ApiError(res, 400, 'INPUT_INVALID'); return; }
            const actions=require("../../services/authentication/peace.desktop-action-approval");
            const actionId=body.actionId===undefined?'':body.actionId;
            if(typeof actionId!=='string'||actionId&&!/^[a-f0-9]{48}$/.test(actionId)){ApiError(res,400,'ADMIN_ACTION_INVALID');return;}
            if(actionId && !pathname.endsWith('/finish')){
                try{actions.Pending(session,actionId);}catch(e){ApiError(res,e.status||409,e.message);return;}
            }
            if (pathname === '/api/session/reauthenticate') {
                const result = Reauthenticate(req, session, body.password);
                if (!result.ok) { if(actionId)actions.Cancel(session,actionId); AuthFailure(res, result); }
                else {try{Json(res,200,{...result,...(actionId?{action:actions.Approve(session,actionId)}:{})});}catch(e){ApiError(res,e.status||409,e.message);}}
                return;
            }
            const limited = CheckLoginAttempt(req, session.role);
            if (!limited.ok) { AuthFailure(res, limited); return; }
            const passkeys = require("../../services/authentication/peace.passkey-auth");
            if (pathname.endsWith('/begin')) {
                const result = passkeys.LoginBegin(session.role, req, session);
                if (!result.ok) { AuthFailure(res, result); return; }
                reauthChallenges.set(session, { id: result.challengeId, actionId, expiresAt: Date.now() + 5 * 60000 });
                Json(res, 200, result); return;
            }
            const pending = reauthChallenges.get(session);
            reauthChallenges.delete(session);
            if (!pending || pending.expiresAt <= Date.now() || pending.id !== body.challengeId || pending.actionId !== actionId) {
                ApiError(res, 403, 'REAUTH_CHALLENGE_INVALID'); return;
            }
            if(actionId){try{actions.Pending(session,actionId);}catch(e){ApiError(res,e.status||409,e.message);return;}}
            const assertion={...body};delete assertion.actionId;
            const result = passkeys.LoginFinish(req, assertion, session);
            if (!result.ok || result.role !== session.role || !require("../authentication/peace.web-auth").MarkReauthenticated(session, result.credentialId)) {
                if(actionId)actions.Cancel(session,actionId);
                ApiError(res, 403, 'REAUTH_FAILED'); return;
            }
            require("../../services/authentication/peace.desktop-admin-guard").MarkVerified(session, result.credentialId);
            try{Json(res, 200, { ok: true, validForMs: require("../authentication/peace.web-auth").REAUTH_MS, ...(actionId?{action:actions.Approve(session,actionId)}:{}) });}catch(e){ApiError(res,e.status||409,e.message);}return;
        }

        if (pathname === '/api/logout' && method === 'POST') {
            const role = session.role;
            Logout(req);
            res.setHeader('Set-Cookie', SessionCookie(req, '', 0));
            LogEvent('WEB_ADMIN_LOGOUT', role);
            Json(res, 200, { ok: true });
            return;
        }

        await HandleApiRequest(req, res, session);
        return;
    }

    if (method !== 'GET' && method !== 'HEAD') {
        res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Method not allowed');
        return;
    }

    if (pathname === '/ui-version.json') {
        res.setHeader('Cache-Control', 'no-store');
        if (method === 'HEAD') {
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end();
        } else Json(res, 200, uiBundle.Check());
        return;
    }
    if (pathname === '/ui-refresh') {
        ServeFile(req, res, '/ui-refresh.html');
        return;
    }

    if (pathname === '/') {
        ServeFile(req, res, '/index.html');
        return;
    }

    ServeFile(req, res, pathname);
}

function StartWebAdmin() {
    const port = Number(config.WEB_ADMIN_PORT || 0);
    if (!(port > 0)) return null;
    const ui = uiBundle.Check();
    if (!ui.ready) console.error('[WEB_UI_FILES_MISMATCH]', ui.issues.join(', '));

    const transport = webTransport.CreateServer((req, res) => {
        Promise.resolve(RequestHandler(req, res)).catch(error => {
            const reference = crypto.randomBytes(6).toString('hex').toUpperCase();
            console.error(
                `[WEB ADMIN ERROR ${reference}]`, 'REQUEST_FAILED'
            );
            if (!res.headersSent) ApiError(res, 500, 'INTERNAL_ERROR', `REF:${reference}`);
            else { try { res.end(); } catch (_) {} }
        });
    });

    const { server } = transport;
    server.on('error', error => {
        console.error('WEB ADMIN SERVER ERROR:', ['EADDRINUSE','EACCES','EADDRNOTAVAIL'].includes(error.code)?error.code:'WEB_LISTENER_FAILED');
        // A failed web bind must not leave a seemingly running native-only app.
        // peace.relay-server.js owns fatal shutdown; do not pretend deployment succeeded.
        throw error;
    });
    server.listen(port, transport.host, () => {
        console.log('WEB_ADMIN_LISTENER_READY', transport.mode);
        if (transport.mode === 'railway') console.log('Railway HTTP ready path: /readyz; raw TCP exposure of this HTTP port is forbidden.');
        if (!config.ADMIN_CREDENTIALS.admin) console.log('Web Admin admin role disabled: ADMIN_SECRET is not configured.');
    });
    return server;
}

module.exports = {
    StartWebAdmin,
    RequestHandler
};
