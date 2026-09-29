'use strict';

const crypto = require('crypto');
const state = require('../core/state');
const { NormalizeID, Now, SendLine } = require('../core/utils');
const { NormalizeAccessType } = require('./accessType');

const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const RESUME_TTL_MS = 24 * 60 * 60 * 1000;

// A lease belongs to the last genuine phone proof, not a client-supplied flag.
// Fresh socket HMAC, installation, permissions, OAuth and license checks remain
// mandatory. Relinking, secret rotation and a new game preparation change this
// binding, so none can reuse an earlier proof.
function ResumeBinding(connection) {
    try {
        const store = require('./member/store');
        const subject = store.Subject(connection), account = store.DB().profiles[subject];
        const link = require('./member/oauthLifecycle').Record(account);
        const secret = state.deviceSecrets.get(`CLIENT:${connection.clientId}`);
        const deviceKey = connection.installationDeviceKey || require('../identity/identityManager').FindClientDeviceKey(connection.clientId);
        const order = store.DB().orders[account?.activeOrderId];
        if (!link?.generation || !secret || !deviceKey || !connection.installationToken) return '';
        return crypto.createHash('sha256').update(JSON.stringify([
            connection.clientId, deviceKey, connection.installationToken, secret,
            subject, account.id, link.generation, connection.licenseKey,
            account.activeOrderId || '', order?.preparedAt || 0
        ])).digest('hex').toUpperCase();
    } catch (_) { return ''; }
}

function TryResume(connection) {
    if (!connection || !connection.connected || !connection.licenseAuthorized ||
        !connection.deviceAuthVerified || !connection.deviceAuthChallengeId ||
        !/^[0-9A-F]{24,64}$/.test(connection.biometricResumeRequestId || '') ||
        state.clients.get(connection.clientId) !== connection ||
        !state.serviceEnabled || state.disabledClients.has(connection.clientId) ||
        !require('./deviceAuth').Verified('CLIENT', connection.clientId) ||
        !require('./clientPermissions').Ready(connection) || require('./clientPermissions').NeedsApproval(connection) ||
        !require('./clientInstallation').Ready(connection) || !require('./member/identity').Ready(connection)) return false;
    const profile = state.clientBiometricProfiles.get(connection.clientId), lease = profile?.resume;
    const now = Now(), binding = ResumeBinding(connection);
    const active = require('../license/licenseManager').GetUsableLicenseForConnection(connection);
    if (!active || !lease || !binding || lease.binding !== binding ||
        !Number.isSafeInteger(lease.expiresAt) || lease.expiresAt <= now ||
        profile.verifiedAt > now || lease.expiresAt !== profile.verifiedAt + RESUME_TTL_MS) return false;
    const game = require('./member/entryPass').ForClient(connection, true);
    const accessType = game ? NormalizeAccessType(game.accessType) : '';
    const groupGuid = require('./userDashboard').GroupGuid(accessType);
    const fields = [connection.deviceAuthChallengeId, connection.biometricResumeRequestId, accessType, groupGuid, String(lease.expiresAt)];
    const mac = HmacHex(state.deviceSecrets.get(`CLIENT:${connection.clientId}`),
        `BIOMETRIC_RESUMED|${connection.clientId}|${fields.join('|')}`);
    connection.biometricVerified = true;
    connection.accessType = accessType;
    state.clientBiometricChallenges.delete(connection.clientId);
    SendLine(connection.socket, `BIOMETRIC_RESUMED|${fields.join('|')}|${mac}`);
    connection.biometricResumeRequestId = '';
    // This restores member entry only. A PC still needs its own current HMAC,
    // matching order and Build lease; no Build grant is fabricated here.
    require('../relay/notifications').NotifyServerAuthorized(connection.clientId,
        connection.serverId, active.license.expiresAt, 'QR_BIOMETRIC_RESUME');
    require('../storage/audit').LogEvent('CLIENT_BIOMETRIC_RESUMED', connection.clientId);
    return true;
}

function HmacHex(key, data) {
    return crypto.createHmac('sha256', String(key || ''))
        .update(String(data || ''), 'utf8').digest('hex').toUpperCase();
}

function EqualHex(a, b) {
    try {
        const aa = Buffer.from(String(a || ''), 'hex');
        const bb = Buffer.from(String(b || ''), 'hex');
        return aa.length === 32 && aa.length === bb.length &&
            crypto.timingSafeEqual(aa, bb);
    } catch (_) { return false; }
}

function Proof(secret, mode, clientId, nonce, accessType) {
    return HmacHex(secret, `BIOMETRIC|${String(mode || '').toUpperCase()}|${NormalizeID(clientId)}|${String(nonce || '').toUpperCase()}|${NormalizeAccessType(accessType)}`);
}

function SendChallenge(connection, challenge) {
    SendLine(connection.socket, `BIOMETRIC_CHALLENGE|${challenge.mode}|${challenge.nonce}|${challenge.accessType}|${challenge.expiresAt}`);
}

function Begin(connection, requestedType = '') {
    if (!require('./member/identity').Ready(connection)) return { ok: false, reason: 'IDENTITY_REQUIRED' };
    if (!require('./clientPermissions').Ready(connection) || require('./clientPermissions').NeedsApproval(connection)) return { ok: false, reason: 'PERMISSIONS_REQUIRED' };
    if (!connection || !connection.connected || !connection.clientId ||
        !connection.licenseAuthorized) return { ok: false, reason: 'LICENSE_REQUIRED' };
    const clientId = NormalizeID(connection.clientId);
    if (!clientId) return { ok: false, reason: 'CLIENT_NOT_CONNECTED' };
    if (!require('./deviceAuth').Verified('CLIENT', clientId)) {
        require('./deviceAuth').IssueChallenge('CLIENT', clientId);
        return { ok: false, reason: 'DEVICE_AUTH_REQUIRED' };
    }
    const capabilities = require('./deviceControl').Capabilities('CLIENT', clientId);
    if (!capabilities.includes('BIOMETRIC_AUTH')) {
        SendLine(connection.socket, 'BIOMETRIC_ERROR|CAPABILITY_REQUIRED');
        return { ok: false, reason: 'BIOMETRIC_CAPABILITY_REQUIRED' };
    }
    const profile = state.clientBiometricProfiles.get(clientId) || null;
    // Once renewed proof is required, reconnect must not revive the old lease.
    if (profile?.resume) {
        connection.biometricVerified = false;
        delete profile.resume;
        let saved = false;
        try { saved = require('../storage/database').SaveDatabase(); } catch (_) {}
        if (!saved) {
            SendLine(connection.socket, 'BIOMETRIC_ERROR|STORAGE_SAVE_FAILED');
            return { ok: false, reason: 'STORAGE_SAVE_FAILED' };
        }
    }
    const accessType = NormalizeAccessType(requestedType ||
        (profile && profile.accessType) || connection.accessType);
    const now = Now();
    const challenge = {
        clientId,
        mode: profile ? 'VERIFY' : 'ENROLL',
        nonce: crypto.randomBytes(24).toString('hex').toUpperCase(),
        accessType,
        issuedAt: now,
        expiresAt: now + CHALLENGE_TTL_MS
    };
    connection.biometricVerified = false;
    connection.accessType = accessType;
    state.clientBiometricChallenges.set(clientId, challenge);
    SendChallenge(connection, challenge);
    return { ok: true, mode: challenge.mode, accessType };
}

function NotifyAuthorized(connection, accessType, profile) {
    if (!require('./member/identity').Ready(connection)) return false;
    if (!require('./clientPermissions').Ready(connection) || require('./clientPermissions').NeedsApproval(connection)) return false;
    const active = require('../license/licenseManager').GetUsableLicenseForConnection(connection);
    if (!active) {
        connection.biometricVerified = false;
        require('./member/testAccess').Revoke(connection);
        SendLine(connection.socket, 'BIOMETRIC_ERROR|LICENSE_REQUIRED');
        return false;
    }
    const installation = require('./clientInstallation');
    if (!installation.Ready(connection)) return false;
    const saved = require('../identity/identityManager').GetSavedClientByID(connection.clientId);
    const savedBefore = structuredClone(saved);
    const deviceKey = connection.installationDeviceKey || require('../identity/identityManager').FindClientDeviceKey(connection.clientId);
    const registryKey = installation.RegistryKey(deviceKey);
    const registryBefore = state.clientInstallations.has(registryKey) ? structuredClone(state.clientInstallations.get(registryKey)) : null;
    const existing = state.clientBiometricProfiles.get(connection.clientId);
    const groupsBefore = new Map(state.accessGroupGuids);
    const previousAccessType = connection.accessType;
    let groupGuid = '';
    let failure = 'STORAGE_SAVE_FAILED';
    try {
        // Profile enrollment, installation trust and group metadata are one durable commit.
        // No authorized frame or Build dispatch may escape before persistence succeeds.
        state.clientBiometricProfiles.set(connection.clientId, profile);
        connection.biometricVerified = true;
        const game = require('./member/entryPass').ForClient(connection,true);
        connection.accessType = game ? NormalizeAccessType(game.accessType) : '';
        if (!installation.MarkAuthorized(connection)) { failure = 'INSTALLATION_REQUIRED'; throw Error(failure); }
        groupGuid = require('./userDashboard').GroupGuid(connection.accessType);
        if (!require('../storage/database').SaveDatabase()) throw Error(failure);
    } catch (_) {
        if (existing) state.clientBiometricProfiles.set(connection.clientId, existing);
        else state.clientBiometricProfiles.delete(connection.clientId);
        for (const key of Object.keys(saved)) delete saved[key];
        Object.assign(saved, savedBefore);
        if (registryBefore) state.clientInstallations.set(registryKey, registryBefore);
        else state.clientInstallations.delete(registryKey);
        state.accessGroupGuids.clear();
        for (const [key, value] of groupsBefore) state.accessGroupGuids.set(key, value);
        connection.biometricVerified = false;
        connection.accessType = previousAccessType;
        require('./member/testAccess').Revoke(connection);
        // Keep the still-unexpired challenge retryable; it has granted no access.
        SendLine(connection.socket, `BIOMETRIC_ERROR|${failure}`);
        return false;
    }
    state.clientBiometricChallenges.delete(connection.clientId);
    require('../storage/audit').LogEvent(existing ? 'CLIENT_BIOMETRIC_VERIFIED' : 'CLIENT_BIOMETRIC_ENROLLED',
        `${connection.clientId} / ${accessType}`);
    SendLine(connection.socket, `BIOMETRIC_OK|${connection.accessType}|${groupGuid}`);
    require('../relay/notifications').NotifyServerAuthorized(connection.clientId,
        connection.serverId, active.license.expiresAt, 'QR_BIOMETRIC');
    require('./buildGate').TryDispatchClient(connection.clientId);
    return true;
}

function HandleProof(connection, parts) {
    if (!require('./member/identity').Ready(connection)) return false;
    if (!require('./clientPermissions').Ready(connection) || require('./clientPermissions').NeedsApproval(connection)) return false;
    if (!Array.isArray(parts) || parts.length !== 4) {
        if (connection && connection.socket)
            SendLine(connection.socket, 'BIOMETRIC_ERROR|FORMAT_INVALID');
        return false;
    }
    if (!connection || !connection.connected || !connection.clientId ||
        !connection.licenseAuthorized) return false;
    const clientId = NormalizeID(connection.clientId);
    if (!require('./deviceAuth').Verified('CLIENT', clientId)) {
        SendLine(connection.socket, 'BIOMETRIC_ERROR|DEVICE_AUTH_REQUIRED');
        return false;
    }
    const mode = String(parts[1] || '').toUpperCase();
    const nonce = String(parts[2] || '').toUpperCase();
    const supplied = String(parts[3] || '').toUpperCase();
    const challenge = state.clientBiometricChallenges.get(clientId);
    if (!challenge || challenge.mode !== mode || challenge.nonce !== nonce) {
        SendLine(connection.socket, 'BIOMETRIC_ERROR|CHALLENGE_INVALID');
        Begin(connection, connection.accessType);
        return false;
    }
    if (challenge.expiresAt <= Now()) {
        state.clientBiometricChallenges.delete(clientId);
        SendLine(connection.socket, 'BIOMETRIC_ERROR|CHALLENGE_EXPIRED');
        Begin(connection, challenge.accessType);
        return false;
    }
    const secret = state.deviceSecrets.get(`CLIENT:${clientId}`) || '';
    const expected = Proof(secret, mode, clientId, nonce, challenge.accessType);
    if (!secret || !/^[0-9A-F]{64}$/.test(supplied) ||
        !EqualHex(expected, supplied)) {
        SendLine(connection.socket, 'BIOMETRIC_ERROR|PROOF_INVALID');
        require('../storage/audit').LogEvent('CLIENT_BIOMETRIC_REJECTED', clientId);
        Begin(connection, challenge.accessType);
        return false;
    }
    const now = Now();
    const existing = state.clientBiometricProfiles.get(clientId);
    const profile = {
        accessType: challenge.accessType,
        enrolledAt: existing ? Number(existing.enrolledAt) || now : now,
        verifiedAt: now,
        verificationCount: Math.max(0, Number(existing && existing.verificationCount) || 0) + 1,
        resetAt: Math.max(0, Number(existing && existing.resetAt) || 0),
        resetBy: String(existing && existing.resetBy || ''),
        resume: { binding: ResumeBinding(connection), expiresAt: now + RESUME_TTL_MS }
    };
    return NotifyAuthorized(connection, challenge.accessType, profile);
}

function SetAccessType(clientId, accessType) {
    clientId = NormalizeID(clientId);
    const normalized = NormalizeAccessType(accessType);
    const profile = state.clientBiometricProfiles.get(clientId);
    if (profile) profile.accessType = normalized;
    const connection = state.clients.get(clientId);
    if (connection) connection.accessType = normalized;
    return normalized;
}

function PublicStatus(clientId) {
    clientId = NormalizeID(clientId);
    const profile = clientId ? state.clientBiometricProfiles.get(clientId) : null;
    const live = clientId ? state.clients.get(clientId) : null;
    return {
        enrolled: !!profile,
        verified: !!(live && live.biometricVerified),
        accessType: NormalizeAccessType(profile && profile.accessType),
        enrolledAt: Number(profile && profile.enrolledAt) || 0,
        verifiedAt: Number(profile && profile.verifiedAt) || 0,
        verificationCount: Math.max(0, Number(profile && profile.verificationCount) || 0),
        resetAt: Math.max(0, Number(profile && profile.resetAt) || 0),
        resetBy: String(profile && profile.resetBy || '')
    };
}

function Reset(clientId, actor = 'WEB_ADMIN') {
    clientId = NormalizeID(clientId);
    if (!clientId) return { ok: false, reason: 'CLIENT_NOT_FOUND' };
    state.clientBiometricProfiles.delete(clientId);
    state.clientBiometricChallenges.delete(clientId);
    const connection = state.clients.get(clientId);
    require('./member/testAccess').Revoke(connection);
    if (connection && connection.connected && connection.socket &&
        !connection.socket.destroyed) {
        connection.biometricVerified = false;
        SendLine(connection.socket, 'BIOMETRIC_RESET|ADMIN');
        require('../relay/notifications').NotifyServerUnauthorized(clientId,
            'BIOMETRIC_RESET');
        if (!require('./memberEntry').Supports(connection)) Begin(connection, connection.accessType);
    }
    require('../storage/database').SaveDatabase();
    require('../storage/audit').LogEvent('CLIENT_BIOMETRIC_RESET',
        `${clientId} / ${String(actor || 'WEB_ADMIN').slice(0, 64)}`);
    return { ok: true, status: PublicStatus(clientId) };
}

module.exports = {
    CHALLENGE_TTL_MS,
    RESUME_TTL_MS,
    TryResume,
    Proof,
    Begin,
    HandleProof,
    SetAccessType,
    PublicStatus,
    Reset
};
