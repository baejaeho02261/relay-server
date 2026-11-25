"use strict";
// A fixed single-host administrator RP. Never derive trust from Host or XFH.
function Configuration(env = process.env) {
    const rpId = String(env.WEBAUTHN_RP_ID || '').trim().toLowerCase();
    const originText = String(env.WEBAUTHN_ORIGIN || '').trim();
    if (!rpId || !originText) throw Error('PASSKEY_CONFIG_REQUIRED');
    if (rpId.length > 253 || rpId.split('.').some(x => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x)) || require('node:net').isIP(rpId)) throw Error('PASSKEY_RP_CONFIG_INVALID');
    let u; try { u = new URL(originText); } catch (_) { throw Error('PASSKEY_ORIGIN_CONFIG_INVALID'); }
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.pathname !== '/' ||
        u.hostname !== rpId || ![u.origin, u.origin + '/'].includes(originText)) throw Error('PASSKEY_ORIGIN_CONFIG_INVALID');
    return { rpId, origin: u.origin, host: u.host };
}
function Resolve(req, https, env = process.env) {
    if (!https) throw Error('ADMIN_HTTPS_REQUIRED');
    // Railway preserves the original domain in X-Forwarded-Host. This path is
    // reached only after the caller validates HTTPS with the ingress policy.
    const hostHeader = env.WEB_ADMIN_TRANSPORT === 'railway' ? 'x-forwarded-host' : 'host';
    const ctx = Configuration(env), host = req.headers?.[hostHeader];
    if (typeof host !== 'string' || !host || host.length > 259 || /[\s,@\\\/#?%]/.test(host)) throw Error('PASSKEY_HOST_INVALID');
    if (Array.isArray(req.rawHeaders) && req.rawHeaders.filter((x, i) => !(i % 2) && String(x).toLowerCase() === hostHeader).length !== 1) throw Error('PASSKEY_HOST_INVALID');
    let url; try { url = new URL('https://' + host); } catch (_) { throw Error('PASSKEY_HOST_INVALID'); }
    if (url.host !== ctx.host || url.origin !== ctx.origin) throw Error('PASSKEY_HOST_INVALID');
    if (req.headers.origin !== undefined && req.headers.origin !== ctx.origin) throw Error('PASSKEY_ORIGIN_INVALID');
    return { rpId: ctx.rpId, origin: ctx.origin };
}
module.exports = { Configuration, Resolve };
