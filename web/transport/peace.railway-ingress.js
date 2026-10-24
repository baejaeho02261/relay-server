"use strict";
// Explicit managed-ingress mode, NOT a general-purpose trust-proxy switch.
// SECURITY BOUNDARY: Railway must be the only public HTTP ingress. Other
// services in this environment must be trusted/isolated. Header names and
// RAILWAY_* env variables are NOT cryptographic proof of a proxy's identity.
// Never publish this listener via TCP Proxy, Docker -p, or an untrusted VPC.
const { Address } = require("../authentication/peace.web-auth-policy");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function Port(value, name) {
    const text = String(value === undefined ? '' : value);
    if (!/^[1-9][0-9]{0,4}$/.test(text) || Number(text) > 65535) throw Error(name + '_INVALID');
    return Number(text);
}
function Settings(env = process.env) {
    if (env.WEB_ADMIN_RAILWAY_EDGE_ONLY !== '1') throw Error('WEB_ADMIN_RAILWAY_EDGE_ONLY_REQUIRED');
    for (const name of ['RAILWAY_PROJECT_ID', 'RAILWAY_ENVIRONMENT_ID', 'RAILWAY_SERVICE_ID'])
        if (!UUID.test(String(env[name] || ''))) throw Error('WEB_ADMIN_RAILWAY_CONTEXT_REQUIRED');
    if (env.WEB_ADMIN_TRUSTED_PROXIES && env.WEB_ADMIN_TRUSTED_PROXIES.trim())
        throw Error('WEB_ADMIN_RAILWAY_CLEAR_TRUSTED_PROXIES');
    const port = Port(env.PORT, 'PORT');
    if (env.WEB_ADMIN_PORT && Port(env.WEB_ADMIN_PORT, 'WEB_ADMIN_PORT') !== port)
        throw Error('WEB_ADMIN_RAILWAY_PORT_MISMATCH');
    const tcpPort = Port(env.CONNECT_TCP_PORT || env.RAILWAY_TCP_APPLICATION_PORT || '3000', 'CONNECT_TCP_PORT');
    if (tcpPort === port) throw Error('WEB_ADMIN_TCP_PORT_CONFLICT');
    if (env.RAILWAY_TCP_APPLICATION_PORT && Port(env.RAILWAY_TCP_APPLICATION_PORT, 'RAILWAY_TCP_APPLICATION_PORT') === port)
        throw Error('WEB_ADMIN_RAILWAY_TCP_EXPOSURE_FORBIDDEN');
    const healthPort = env.HEALTH_PORT && env.HEALTH_PORT !== '0' ? Port(env.HEALTH_PORT, 'HEALTH_PORT') : 0;
    if (healthPort && healthPort === tcpPort) throw Error('WEB_ADMIN_HEALTH_TCP_PORT_CONFLICT');
    // Fixed operator configuration. A client Host header never creates an RP.
    const { host, origin, rpId } = require("../../services/authentication/peace.passkey-context").Configuration(env);
    return Object.freeze({ port, tcpPort, healthPort, host, origin, rpId });
}
function Single(req, name, max = 512) {
    const value = req.headers && req.headers[name];
    if (typeof value !== 'string' || !value || value.length > max || /[\x00-\x20\x7f,]/.test(value)) return null;
    if (Array.isArray(req.rawHeaders)) {
        let count = 0;
        for (let i = 0; i < req.rawHeaders.length; i += 2)
            if (String(req.rawHeaders[i]).toLowerCase() === name) count++;
        if (count !== 1) return null;
    }
    return value;
}
function Host(value, configured) {
    if (!value || /[\s,@\\\/#?%]/.test(value)) return false;
    try {
        const u = new URL('https://' + value);
        return !u.username && !u.password && u.origin === configured.origin && u.host === configured.host;
    } catch (_) { return false; }
}
function Origin(req, configured) {
    const peer = Address(String(req.socket && req.socket.remoteAddress || ''));
    const denied = { ip: peer ? peer.text : 'unknown', https: false };
    if (!peer || !configured) return denied;
    // Railway documents these edge-generated headers. X-Forwarded-For is NOT
    // used as a replacement for X-Real-IP (which avoids a client-supplied chain).
    const proto = Single(req, 'x-forwarded-proto', 8);
    const host = Single(req, 'x-forwarded-host', 259);
    const requestId = Single(req, 'x-railway-request-id', 128);
    const realIP = Single(req, 'x-real-ip', 45);
    const inboundHost = Single(req, 'host', 259);
    if (proto !== 'https' || !Host(host, configured) || !inboundHost ||
        !requestId || !/^[A-Za-z0-9_-]{8,128}$/.test(requestId) || !realIP) return denied;
    const client = Address(realIP);
    if (!client) return denied;
    // A browser Origin, when present, must match the fixed administrator origin.
    if (req.headers.origin !== undefined && Single(req, 'origin', 300) !== configured.origin) return denied;
    return { ip: client.text, https: true };
}
module.exports = { Port, Settings, Single, Origin };
