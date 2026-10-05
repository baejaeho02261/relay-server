'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const config = require('../config/config');
const { HealthSnapshot } = require('../services/dashboard');
const { LogEvent } = require('../storage/audit');
const {
    SessionCookie, SESSION_MS, Login, Authenticate, Logout, ValidateCsrf, IsHttps, AllowLoginAttempt
} = require('./webAuth');
const { Json, ApiError, ReadJsonBody, HandleApiRequest } = require('./webApi');
const { OpenEventStream } = require('./webEvents');
const { RecordAdminActivity } = require('../services/adminActivity');
const releaseManager = require('../services/releaseManager');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
const uiBundle = require('./uiBundle');

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
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (IsHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}


async function ReadReleaseUpload(req, meta) {
    releaseManager.SigningSecret();
    const { pipeline } = require('node:stream/promises');
    const { Transform } = require('node:stream');
    const tmpDir = path.join(config.DATA_DIR, 'releases', '.tmp');
    fs.mkdirSync(tmpDir, { recursive: true });
    const tmp = path.join(tmpDir, `upload-${crypto.randomBytes(16).toString('hex')}.tmp`);
    const hash = crypto.createHash('sha256');
    let size = 0;
    const limit = new Transform({ transform(chunk, encoding, callback) {
        size += chunk.length;
        if (size > releaseManager.MAX_RELEASE_BYTES) { callback(new Error('RELEASE_TOO_LARGE')); return; }
        hash.update(chunk); callback(null, chunk);
    }});
    try {
        await pipeline(req, limit, fs.createWriteStream(tmp, { flags: 'wx', mode: 0o600 }));
        return { tmp, size, sha256: hash.digest('hex'), meta };
    } catch (error) {
        // pipeline settles after stream destruction, so unlink cannot race open.
        try { fs.unlinkSync(tmp); } catch (_) {}
        throw error;
    }
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
    if (release?.type === 'CLIENT') { require('../services/desktopMode').Reject(res); return true; }
    const file = releaseManager.ArtifactPath(release);
    if (!release || !file || !fs.existsSync(file)) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('Not found');
        return true;
    }
    const stat = fs.statSync(file);
    res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
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
    if (safeName === 'service-worker.js') headers['Service-Worker-Allowed'] = '/';
    res.writeHead(200, headers);
    if (String(req.method || 'GET').toUpperCase() === 'HEAD') { res.end(); return; }
    fs.createReadStream(full).pipe(res);
}

async function RequestHandler(req, res) {
    SecurityHeaders(req, res);
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;
    const method = String(req.method || 'GET').toUpperCase();
    const desktopMode = require('../services/desktopMode');
    if (desktopMode.RetiredPath(pathname)) { desktopMode.Reject(res); return; }
    // Desktop HMAC challenge/execute have their own authentication, rate limits
    // and replay checks. Never route them through an administrator cookie.
    if (await require('./desktopApi').Handle(req, res, url)) return;

    if (pathname.startsWith('/internal/ha/')) {
        if (await require('../services/haCoordinator').HandleInternal(req, res, pathname)) return;
    }

    // Deployment readiness is independent of an administrator disabling
    // licensed operations: the admin web must still be deployable in that state.
    if (pathname === '/readyz' && (method === 'GET' || method === 'HEAD')) {
        const ready = require('../services/desktopConnect').IsListening() && uiBundle.Check().ready;
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

    if (['/api/login', '/api/passkey/login/begin', '/api/passkey/login/finish'].includes(pathname) && method === 'POST' && String(req.headers['sec-fetch-site'] || '') === 'cross-site') {
        ApiError(res, 403, 'CROSS_SITE_LOGIN'); return;
    }

    if (pathname === '/api/login' && method === 'POST') {
        let body;
        try { body = await ReadJsonBody(req, 16 * 1024); }
        catch (error) { ApiError(res, 400, error.message); return; }
        const result = Login(req, body.role, body.password);
        if (!result.ok) {
            if (result.status === 429) res.setHeader('Retry-After', '60');
            RecordAdminActivity(String(body.role || '').toLowerCase(), require('./webAuth').ClientIP(req), 'POST', '/api/login', result.status || 401, 'LOGIN_FAILED');
            ApiError(res, result.status || 401, result.code);
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
        if (!AllowLoginAttempt(req)) { ApiError(res, 429, 'AUTH_RATE_LIMIT'); return; }
        let body; try { body = await ReadJsonBody(req, 16 * 1024); } catch (error) { ApiError(res, 400, error.message); return; }
        const result = require('../services/passkeyAuth').LoginBegin(body.role, req);
        if (!result.ok) ApiError(res, 400, result.reason); else Json(res, 200, result);
        return;
    }

    if (pathname === '/api/passkey/login/finish' && method === 'POST') {
        if (!AllowLoginAttempt(req)) { ApiError(res, 429, 'AUTH_RATE_LIMIT'); return; }
        let body; try { body = await ReadJsonBody(req, 16 * 1024); } catch (error) { ApiError(res, 400, error.message); return; }
        const result = require('../services/passkeyAuth').LoginFinish(req, body);
        if (!result.ok) { ApiError(res, 401, result.reason); return; }
        const session = require('./webAuth').CreateSession(req, result.role);
        require('../services/desktopAdminGuard').MarkVerified(session,result.credentialId);
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

        if (pathname === '/api/session' && method === 'GET') {
            Json(res, 200, {
                ok: true,
                role: session.role,
                csrf: session.csrf,
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
            if (!require('../services/haCoordinator').CanAcceptTraffic()) { ApiError(res, 409, 'RELAY_STANDBY_READ_ONLY'); return; }
            const meta = {
                type: url.searchParams.get('type'), channel: url.searchParams.get('channel'), version: url.searchParams.get('version'),
                fileName: url.searchParams.get('fileName'), mandatory: url.searchParams.get('mandatory') === '1',
                rolloutPercent: Number(url.searchParams.get('rolloutPercent') || 100), notes: url.searchParams.get('notes') || ''
            };
            try {
                const upload = await ReadReleaseUpload(req, meta);
                if (!require('./webAuth').IsSessionActive(session)) {
                    try { fs.unlinkSync(upload.tmp); } catch (_) {}
                    ApiError(res, 401, 'NOT_AUTHORIZED'); return;
                }
                const release = releaseManager.PublishFromTemp(meta, upload.tmp, upload.sha256, upload.size);
                require('../storage/database').SaveDatabase();
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

    const server = http.createServer((req, res) => {
        Promise.resolve(RequestHandler(req, res)).catch(error => {
            const reference = crypto.randomBytes(6).toString('hex').toUpperCase();
            console.error(
                `[WEB ADMIN ERROR ${reference}] ${String(req.method || 'GET').toUpperCase()} ${req.url}`,
                error && error.stack ? error.stack : error
            );
            if (!res.headersSent) ApiError(res, 500, 'INTERNAL_ERROR', `REF:${reference}`);
            else { try { res.end(); } catch (_) {} }
        });
    });

    server.headersTimeout = 15000;
    server.requestTimeout = 120000;
    server.keepAliveTimeout = 5000;
    server.maxRequestsPerSocket = 1000;
    server.on('error', error => console.error('WEB ADMIN SERVER ERROR:', error.message));
    server.listen(port, config.HOST, () => {
        console.log('Web Admin HTTP Port:', port);
        if (!config.ADMIN_CREDENTIALS.admin) console.log('Web Admin admin role disabled: ADMIN_SECRET is not configured.');
    });
    return server;
}

module.exports = {
    StartWebAdmin
};
