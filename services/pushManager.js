'use strict';

const crypto = require('crypto');
const config = require('../config/config');
const state = require('../core/state');
const destination = require('./pushDestination');
const pushTransport = require('./pushTransport');
const { Now, SafeField } = require('../core/utils');

let webPush = null;
let initialized = false;
let initError = '';

function Initialize() {
    if (initialized) return !initError;
    initialized = true;
    try { destination.Policy(); } catch (_) { initError = 'PUSH_HOST_POLICY_INVALID'; return false; }
    if (!config.VAPID_PUBLIC_KEY || !config.VAPID_PRIVATE_KEY) {
        initError = 'VAPID_KEYS_NOT_CONFIGURED';
        return false;
    }
    try {
        webPush = require('web-push');
        webPush.setVapidDetails(config.VAPID_SUBJECT, config.VAPID_PUBLIC_KEY, config.VAPID_PRIVATE_KEY);
        return true;
    } catch (error) {
        initError = error && error.code === 'MODULE_NOT_FOUND' ? 'WEB_PUSH_MODULE_NOT_INSTALLED' : SafeField(error.message || 'WEB_PUSH_INIT_FAILED');
        return false;
    }
}

function SubscriptionId(endpoint) {
    return crypto.createHash('sha256').update(String(endpoint || '')).digest('hex').slice(0, 24);
}

function NormalizeSubscription(input) {
    if (!input || Object.getPrototypeOf(input) !== Object.prototype ||
        !input.keys || Object.getPrototypeOf(input.keys) !== Object.prototype)
        throw new Error('INVALID_PUSH_SUBSCRIPTION');
    const endpoint = destination.ValidateEndpoint(input.endpoint).endpoint;
    const { p256dh, auth } = input.keys;
    const decode = (value, size) => {
        if (typeof value !== 'string' || value.length > 100 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value))
            throw new Error('INVALID_PUSH_SUBSCRIPTION');
        const bytes = Buffer.from(value, 'base64url');
        if (bytes.length !== size || bytes.toString('base64url') !== value.replace(/=+$/, ''))
            throw new Error('INVALID_PUSH_SUBSCRIPTION');
        return bytes;
    };
    const publicKey = decode(p256dh, 65), secret = decode(auth, 16);
    try {
        if (publicKey[0] !== 4) throw new Error('INVALID_PUSH_SUBSCRIPTION');
        crypto.ECDH.convertKey(publicKey, 'prime256v1');
    } catch (_) { throw new Error('INVALID_PUSH_SUBSCRIPTION'); }
    finally { secret.fill(0); }
    const expirationTime = input.expirationTime ?? null;
    if (expirationTime !== null && (!Number.isSafeInteger(expirationTime) || expirationTime < 0))
        throw new Error('INVALID_PUSH_SUBSCRIPTION');
    return { endpoint, expirationTime, keys: { p256dh, auth } };
}

function ImportPersisted(data) {
    state.pushSubscriptions.clear();
    const source = data && data.pushSubscriptions;
    if (!source || typeof source !== 'object') return;
    for (const [id, raw] of Object.entries(source)) {
        try {
            const subscription = NormalizeSubscription(raw.subscription || raw);
            const expected = SubscriptionId(subscription.endpoint);
            state.pushSubscriptions.set(expected, {
                id: expected,
                subscription,
                role: SafeField(raw.role || ''),
                userAgent: SafeField(raw.userAgent || '').slice(0, 300),
                createdAt: Number(raw.createdAt) || Now(),
                lastSuccessAt: Number(raw.lastSuccessAt) || 0,
                failureCount: Math.max(0, Number(raw.failureCount) || 0)
            });
        } catch (_) {}
    }
}

function Status() {
    const available = Initialize();
    return { available, reason: available ? '' : initError, publicKey: available ? config.VAPID_PUBLIC_KEY : '', subscriptions: state.pushSubscriptions.size };
}

function Subscribe(input, meta = {}) {
    if (!Initialize()) throw new Error(initError);
    const subscription = NormalizeSubscription(input);
    const id = SubscriptionId(subscription.endpoint);
    const existing = state.pushSubscriptions.get(id);
    state.pushSubscriptions.set(id, {
        id,
        subscription,
        role: SafeField(meta.role || existing && existing.role || ''),
        userAgent: SafeField(meta.userAgent || existing && existing.userAgent || '').slice(0, 300),
        createdAt: existing && existing.createdAt || Now(),
        lastSuccessAt: existing && existing.lastSuccessAt || 0,
        failureCount: 0
    });
    require('../storage/database').SaveDatabase();
    return { id, subscriptions: state.pushSubscriptions.size };
}

function Unsubscribe(endpointOrId) {
    const raw = String(endpointOrId || '');
    const id = state.pushSubscriptions.has(raw) ? raw : SubscriptionId(raw);
    const removed = state.pushSubscriptions.delete(id);
    if (removed) require('../storage/database').SaveDatabase();
    return removed;
}

function Payload(input = {}) {
    return JSON.stringify({
        title: SafeField(input.title || 'Relay Operations'),
        body: SafeField(input.body || input.message || ''),
        severity: SafeField(input.severity || 'INFO').toUpperCase(),
        type: SafeField(input.type || 'SYSTEM'),
        entityId: SafeField(input.entityId || ''),
        url: String(input.url || '/').startsWith('/') ? String(input.url || '/') : '/',
        createdAt: Number(input.createdAt) || Now()
    });
}

async function Send(input, options = {}) {
    if (!Initialize()) return { ok: false, reason: initError, sent: 0, failed: 0, removed: 0 };
    const severity = String(input && input.severity || 'INFO').toUpperCase();
    if (!options.force && !['WARNING', 'CRITICAL'].includes(severity)) return { ok: true, skipped: true, sent: 0, failed: 0, removed: 0 };
    const payload = Payload(input);
    let sent = 0, failed = 0, removed = 0;
    for (const [id, item] of Array.from(state.pushSubscriptions.entries())) {
        try {
            // Revalidate persisted entries and resolve/pin the destination on EVERY send.
            const subscription = NormalizeSubscription(item.subscription);
            await pushTransport.Send(webPush, subscription, payload, { urgency: severity === 'CRITICAL' ? 'high' : 'normal' });
            item.lastSuccessAt = Now();
            item.failureCount = 0;
            sent++;
        } catch (error) {
            failed++;
            item.failureCount++;
            const status = Number(error && error.statusCode || 0);
            if (status === 404 || status === 410 || item.failureCount >= 5) {
                state.pushSubscriptions.delete(id);
                removed++;
            }
        }
    }
    if (removed) require('../storage/database').SaveDatabase();
    return { ok: true, sent, failed, removed };
}

function DispatchNotification(item) {
    return Send({ title: item.title, body: item.message, severity: item.severity, type: item.type, entityId: item.entityId, createdAt: item.createdAt, url: item.entityId ? `/?entity=${encodeURIComponent(item.entityId)}` : '/' })
        .catch(() => ({ ok: false }));
}

module.exports = { Initialize, ImportPersisted, Status, Subscribe, Unsubscribe, Send, DispatchNotification, SubscriptionId };
