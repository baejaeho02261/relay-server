"use strict";
// Ordinary member entry is deliberately independent from the phone proof that
// protects a PC game session. A local preference can never issue this grant.
const crypto = require('crypto');
const state = require('../core/state');
function Supports(c) {
    return !!c && require('./deviceControl').Capabilities('CLIENT', c.clientId).includes('MEMBER_ENTRY');
}
function Binding(c) {
    try {
        if (!c || !c.connected || c.socket?.destroyed || state.clients.get(c.clientId) !== c ||
            !state.serviceEnabled || state.disabledClients.has(c.clientId) ||
            !require('./haCoordinator').CanAcceptTraffic() || !c.licenseAuthorized ||
            !c.deviceAuthVerified || !c.deviceAuthChallengeId ||
            !require('./deviceAuth').Verified('CLIENT', c.clientId) ||
            !require('./clientPermissions').Ready(c) || require('./clientPermissions').NeedsApproval(c) ||
            !require('./clientInstallation').Ready(c) || !require('./member/identity').Ready(c)) return '';
        const store = require('./member/store'), account = store.DB().profiles[store.Subject(c)];
        const link = require('./member/oauthLifecycle').Record(account);
        const active = require('../license/licenseManager').GetUsableLicenseForConnection(c);
        const secret = state.deviceSecrets.get('CLIENT:' + c.clientId);
        if (!account || account.blocked || !link?.generation || !secret || !active ||
            !c.installationToken || !Supports(c)) return '';
        return crypto.createHash('sha256').update(JSON.stringify([
            c.clientId, c.deviceAuthChallengeId, c.installationDeviceKey,
            c.installationToken, secret, c.licenseKey,
            account.id, account.subject, link.generation
        ])).digest('hex');
    } catch (_) { return ''; }
}
function Ready(c) {
    const bound = c?.memberEntryGrant;
    if (!bound) return false;
    const current = Binding(c);
    if (!current || current !== bound) { c.memberEntryGrant = null; return false; }
    return true;
}
function Grant(c) {
    if (!c) return false;
    if (!c.memberEntryRequestId && Ready(c)) return true;
    c.memberEntryGrant = null;
    const binding = Binding(c);
    if (!binding || !/^[0-9A-F]{24,64}$/.test(c.memberEntryRequestId || '')) return false;
    const expiry = String(c.licenseExpiresAt || 0);
    const fields = [c.deviceAuthChallengeId, c.memberEntryRequestId, expiry];
    const mac = crypto.createHmac('sha256', state.deviceSecrets.get('CLIENT:' + c.clientId))
        .update('MEMBER_ENTRY_OK|' + c.clientId + '|' + fields.join('|')).digest('hex').toUpperCase();
    c.memberEntryGrant = binding;
    require('../core/utils').SendLine(c.socket, 'MEMBER_ENTRY_OK|' + fields.join('|') + '|' + mac);
    c.memberEntryRequestId = '';
    require('../storage/audit').LogEvent('CLIENT_MEMBER_ENTRY', c.clientId);
    // No biometric profile, proof, PC notification, or Build grant is created.
    return true;
}
module.exports = { Supports, Ready, Grant };
