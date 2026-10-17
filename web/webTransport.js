"use strict";
// No new framework. proxy = on-host loopback; direct = native TLS;
// railway = explicitly accepted, isolated managed-edge deployment boundary.
// Never expose a railway-mode HTTP listener through a raw public TCP port.
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const { Address, ParseTrustedProxies } = require('./webAuthPolicy');
const LOOPBACK_PROXIES = '127.0.0.1/32,::1/128';
function TrustedProxySetting(env = process.env) {
    return env.WEB_ADMIN_TRUSTED_PROXIES === undefined
        ? (['direct', 'railway'].includes(env.WEB_ADMIN_TRANSPORT) ? '' : LOOPBACK_PROXIES)
        : env.WEB_ADMIN_TRUSTED_PROXIES;
}
function Settings(env = process.env) {
    const mode = env.WEB_ADMIN_TRANSPORT || 'proxy';
    if (!['proxy', 'direct', 'railway'].includes(mode)) throw Error('WEB_ADMIN_TRANSPORT_INVALID');
    // Old opt-out flags cannot silently undo the new invariant.
    for (const name of ['WEB_ADMIN_REQUIRE_HTTPS', 'WEB_ADMIN_SECURE_COOKIE'])
        if (env[name] !== undefined && env[name] !== '' && env[name] !== '1') throw Error(name + '_MUST_BE_1');
    const host = env.WEB_ADMIN_HOST || (mode === 'proxy' ? '127.0.0.1' : '0.0.0.0');
    const address = Address(host);
    if (!address) throw Error('WEB_ADMIN_HOST_MUST_BE_IP');
    if (mode === 'proxy' && !((address.family === 4 && address.value >> 24n === 127n) ||
        (address.family === 6 && address.value === 1n))) throw Error('WEB_ADMIN_HTTP_LOOPBACK_REQUIRED');
    if (mode === 'railway') {
        if (host !== '0.0.0.0') throw Error('WEB_ADMIN_RAILWAY_WILDCARD_REQUIRED');
        require('./railwayIngress').Settings(env);
    }
    const proxies = ParseTrustedProxies(TrustedProxySetting(env));
    if (mode === 'proxy') {
        if (!proxies.length) throw Error('WEB_ADMIN_PROXY_REQUIRED');
        // No blanket trust for private/public networks. Proxy must share the
        // network namespace/host, or the deployment must use direct TLS.
        for (const p of proxies) {
            const loopback = p.family === 4 ? p.shift <= 24n && p.network >> (24n - p.shift) === 127n
                : p.shift === 0n && p.network === 1n;
            if (!loopback) throw Error('WEB_ADMIN_PROXY_MUST_BE_LOOPBACK');
        }
    }
    if (mode === 'direct' && proxies.length) throw Error('WEB_ADMIN_DIRECT_PROXY_TRUST_FORBIDDEN');
    return { mode, host, certFile: env.WEB_ADMIN_TLS_CERT_FILE || '', keyFile: env.WEB_ADMIN_TLS_KEY_FILE || '' };
}
function ReadPem(file) {
    if (!file) throw Error('WEB_ADMIN_TLS_FILES_REQUIRED');
    const fd = fs.openSync(file, 'r');
    try {
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.size < 1 || stat.size > 262144) throw Error('WEB_ADMIN_TLS_FILE_INVALID');
        const data = fs.readFileSync(fd);
        if (data.length !== stat.size) throw Error('WEB_ADMIN_TLS_FILE_CHANGED');
        return data;
    } finally { fs.closeSync(fd); }
}
function CreateServer(handler, env = process.env) {
    const settings = Settings(env);
    let server;
    if (settings.mode === 'direct') {
        const cert = ReadPem(settings.certFile), key = ReadPem(settings.keyFile);
        try {
            const options = { cert, key, minVersion: 'TLSv1.2', handshakeTimeout: 10000 };
            tls.createSecureContext(options); // reject bad/mismatching identity before listen
            server = https.createServer(options, handler);
        } finally { key.fill(0); }
    } else server = http.createServer(handler);
    return { server, ...settings };
}
module.exports = { Settings, TrustedProxySetting, CreateServer };
