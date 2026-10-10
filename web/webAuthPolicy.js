'use strict';
// Only the directly connected peer may establish a trusted forwarding chain.
const net = require('node:net');
const { performance } = require('node:perf_hooks');

function IntegerSetting(name, fallback, min, max) {
    const value = process.env[name];
    if (value === undefined || value === '') return fallback;
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < min || Number(value) > max)
        throw new Error(`${name}_INVALID`);
    return Number(value);
}
function Address(value) {
    if (typeof value !== 'string' || value.length > 45 || value.includes('%')) return null;
    const family = net.isIP(value);
    if (family === 4) {
        const parts = value.split('.').map(Number);
        return { family, originalFamily: family, value: parts.reduce((n, x) => (n << 8n) | BigInt(x), 0n), text: parts.join('.') };
    }
    if (family !== 6) return null;
    let text = value.toLowerCase();
    if (text.includes('.')) {
        const p = text.lastIndexOf(':');
        const v4 = Address(text.slice(p + 1));
        if (!v4 || v4.family !== 4) return null;
        text = text.slice(0, p + 1) + (v4.value >> 16n).toString(16) + ':' + (v4.value & 65535n).toString(16);
    }
    const sides = text.split('::');
    const left = sides[0] ? sides[0].split(':') : [];
    const right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
    const groups = sides.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    if (groups.length !== 8) return null;
    const numeric = groups.reduce((n, x) => (n << 16n) | BigInt('0x' + x), 0n);
    if ((numeric >> 32n) === 65535n) {
        const v4 = numeric & 0xffffffffn;
        return { family: 4, originalFamily: 6, value: v4, text: [24n, 16n, 8n, 0n].map(x => Number((v4 >> x) & 255n)).join('.') };
    }
    return { family, originalFamily: family, value: numeric, text: groups.map(x => parseInt(x, 16).toString(16)).join(':') };
}
function ParseTrustedProxies(text = '') {
    if (typeof text !== 'string' || text.length > 8192) throw new Error('WEB_ADMIN_TRUSTED_PROXIES_INVALID');
    if (!text.trim()) return [];
    const parts = text.split(',');
    if (parts.length > 128) throw new Error('WEB_ADMIN_TRUSTED_PROXIES_INVALID');
    return parts.map(part => {
        const pieces = part.trim().split('/');
        const address = Address(pieces[0]);
        if (!address || pieces.length > 2 || (pieces.length === 2 && !/^\d{1,3}$/.test(pieces[1])))
            throw new Error('WEB_ADMIN_TRUSTED_PROXIES_INVALID');
        let prefix = pieces.length === 1 ? (address.originalFamily === 4 ? 32 : 128) : Number(pieces[1]);
        if (prefix > (address.originalFamily === 4 ? 32 : 128)) throw new Error('WEB_ADMIN_TRUSTED_PROXIES_INVALID');
        if (address.originalFamily === 6 && address.family === 4) {
            if (prefix < 96) throw new Error('WEB_ADMIN_TRUSTED_PROXIES_INVALID');
            prefix -= 96;
        }
        const shift = BigInt((address.family === 4 ? 32 : 128) - prefix);
        return { family: address.family, shift, network: address.value >> shift };
    });
}
function Trusted(address, rules) {
    return !!address && rules.some(x => x.family === address.family && (address.value >> x.shift) === x.network);
}
function RequestOrigin(req, rules) {
    const peer = Address(String(req.socket && req.socket.remoteAddress || ''));
    const direct = { ip: peer ? peer.text : 'unknown', https: !!(req.socket && req.socket.encrypted) };
    if (!Trusted(peer, rules)) return direct;
    const proto = req.headers && req.headers['x-forwarded-proto'];
    if (!direct.https && typeof proto === 'string' && proto.toLowerCase() === 'https') direct.https = true;
    const forwarded = req.headers && req.headers['x-forwarded-for'];
    if (typeof forwarded !== 'string' || forwarded.length > 2048) return direct;
    const raw = forwarded.split(',');
    if (!raw.length || raw.length > 16) return direct;
    const chain = raw.map(x => Address(x.trim()));
    if (chain.some(x => !x)) return direct;
    chain.push(peer);
    let i = chain.length - 1;
    while (i > 0 && Trusted(chain[i], rules)) i--;
    direct.ip = chain[i].text;
    return direct;
}

// Ephemeral fixed windows: rejected requests never prolong a lock. Every
// authentication attempt (password and passkey) is charged before validation.
class LoginLimiter {
    constructor({ windowMs = 300000, ipMax = 20, roleMax = 200, globalMax = 1000, maxEntries = 4096, now = () => performance.now() } = {}) {
        this.windowMs = windowMs; this.ipMax = ipMax; this.roleMax = roleMax;
        this.globalMax = globalMax; this.maxEntries = maxEntries; this.now = now;
        this.entries = new Map();
    }
    Check(ip, role) {
        const now = this.now();
        for (const [key, entry] of this.entries) if (entry.until <= now) this.entries.delete(key);
        const keys = [[`ip:${ip}`, this.ipMax], [`role:${role}`, this.roleMax], ['global', this.globalMax]];
        let retryMs = 0;
        for (const [key, max] of keys) {
            const entry = this.entries.get(key);
            if (entry && entry.count >= max) retryMs = Math.max(retryMs, entry.until - now);
        }
        if (retryMs > 0) return { ok: false, status: 429, code: 'LOGIN_RATE_LIMITED', retryAfterSeconds: Math.max(1, Math.ceil(retryMs / 1000)) };
        const missing = keys.filter(([key]) => !this.entries.has(key)).length;
        if (this.entries.size + missing > this.maxEntries)
            return { ok: false, status: 429, code: 'LOGIN_RATE_LIMITED', retryAfterSeconds: Math.max(1, Math.ceil(this.windowMs / 1000)) };
        for (const [key] of keys) {
            const entry = this.entries.get(key) || { until: now + this.windowMs, count: 0 };
            entry.count++; this.entries.set(key, entry);
        }
        return { ok: true };
    }
}
module.exports = { IntegerSetting, Address, ParseTrustedProxies, RequestOrigin, LoginLimiter };
