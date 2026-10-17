'use strict';
// Real web session / guard / one-use permit code, temporary JSON storage.
// Credential metadata below is a fixture; real WebAuthn signatures are covered
// by test-web-auth-hardening.js and test-admin-auth-choice.js.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'game-auth-choice-stepup-'));
Object.assign(process.env, { DATA_DIR: tmp, STORAGE_ENGINE: 'json', ADMIN_SECRET: 'synthetic-long-admin-password',
    WEB_ADMIN_TRANSPORT: 'proxy', WEB_ADMIN_REQUIRE_HTTPS: '1', WEB_ADMIN_LOGIN_IP_MAX: '500',
    DESKTOP_ADMIN_REAUTH_REQUIRED: '0', DESKTOP_SECURITY_STEP_UP_REQUIRED: '0' });
const state = require('../core/state'), web = require('../web/webAuth');
const guard = require('../services/desktopAdminGuard'), enrollment = require('../services/desktopAdminEnrollment');
const request = { socket: { remoteAddress: '127.0.0.1', encrypted: true }, headers: { host: 'localhost' } };
const begin = '/api/production/passkeys/register/begin', finish = '/api/production/passkeys/register/finish';
const critical = '/api/desktop/bootstrap/security-operations/signers';
const realNow = Date.now; let now = realNow(); Date.now = () => now;
function session(credential = false) {
    if (credential) state.production.passkeyCredentials.set('verified', { id: 'verified', role: 'admin', revokedAt: 0 });
    return web.CreateSession(request, 'admin', credential ? { credentialId: 'verified' } : {});
}
function stale(s) { now += web.REAUTH_MS + 1; assert.equal(web.IsSessionActive(s), true); assert.equal(web.HasRecentAuthentication(s), false); }
test.beforeEach(() => { now = realNow(); state.production.passkeyCredentials.clear(); state.production.deploymentManifest.dualApprovalRequired = false;
    process.env.ADMIN_SECRET = 'synthetic-long-admin-password'; process.env.DESKTOP_ADMIN_REAUTH_REQUIRED = '0'; process.env.DESKTOP_SECURITY_STEP_UP_REQUIRED = '0'; });
test.afterEach(() => web.RevokeAllSessions());
test.after(() => { Date.now = realNow; fs.rmSync(tmp, { recursive: true, force: true }); });

test('correct password login permits critical work without any passkey', () => {
    const r = web.Login(request, 'admin', process.env.ADMIN_SECRET); assert.equal(r.ok, true);
    assert.equal(web.HasRecentPasskey(r.session), false); assert.equal(guard.Authorize(r.session, 'POST', critical, {}).ok, true);
    assert.equal(state.production.passkeyCredentials.size, 0);
});
test('wrong password does not create a session', () => assert.equal(web.Login(request, 'admin', 'wrong').ok, false));
test('stale password login requires fresh authentication, not a mandatory passkey', () => {
    const s = session(); stale(s); assert.equal(guard.Authorize(s, 'POST', critical, {}).reason, 'ADMIN_REAUTH_REQUIRED');
});
test('wrong password reauthentication cannot refresh a stale grant', () => {
    const s = session(); stale(s); assert.equal(web.Reauthenticate(request, s, 'wrong').code, 'REAUTH_FAILED');
    assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, false);
});
test('correct password reauthentication refreshes only general authentication', () => {
    const s = session(); stale(s); assert.equal(web.Reauthenticate(request, s, process.env.ADMIN_SECRET).ok, true);
    assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, true); assert.equal(web.HasRecentPasskey(s), false); assert.equal(guard.Identity(s), '');
});
test('verified credential metadata still admits critical work', () => {
    const s = session(true); assert.equal(web.HasRecentPasskey(s), true); assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, true);
});
test('password can refresh a stale passkey session without pretending to be passkey verification', () => {
    const s = session(true); stale(s); assert.equal(web.Reauthenticate(request, s, process.env.ADMIN_SECRET).ok, true);
    assert.equal(web.HasRecentPasskey(s), false); assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, true);
});
test('mutable public flags do not manufacture private freshness metadata', () => {
    const s = session(); stale(s); Object.assign(s, { passkeyCredentialId: 'verified', securityVerifiedAt: now,
        authenticatedAt: now, reauthenticatedAt: now, passkeyAt: now });
    assert.equal(web.HasRecentAuthentication(s), false); assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, false);
});
test('copying a session object cannot create verified authentication', () => {
    const s = session(); assert.equal(guard.Authorize({ ...s }, 'POST', critical, {}).ok, false);
});
test('revoked credential invalidates its session even after password reauthentication', () => {
    const s = session(true); assert.equal(web.Reauthenticate(request, s, process.env.ADMIN_SECRET).ok, true);
    state.production.passkeyCredentials.get('verified').revokedAt = now;
    assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, false); assert.equal(web.Reauthenticate(request, s, process.env.ADMIN_SECRET).ok, false);
});
test('all critical categories retain the freshness floor when optional flag is zero', () => {
    const s = session(); stale(s);
    for (const route of [critical, '/api/desktop/bootstrap/security-authority', '/api/desktop/bootstrap/integrity-policy',
        '/api/desktop/bootstrap/security-operations/activate', '/api/desktop/bootstrap/security-operations/controls',
        '/api/desktop/bootstrap/security-operations/ci-signers', '/api/desktop/bootstrap/security-operations/recovery/apply',
        '/api/desktop/bootstrap/server-state/device-replacement', '/api/production/transport', '/api/production/config/apply',
        '/api/production/update/rollback', '/api/production/passkeys/revoke'])
        assert.equal(guard.Authorize(s, 'POST', route, {}).reason, 'ADMIN_REAUTH_REQUIRED', route);
});
test('ordinary reads and candidate planning remain accessible to live stale-auth sessions', () => {
    const s = session(); stale(s); assert.equal(guard.Authorize(s, 'GET', critical, {}).ok, true);
    assert.equal(guard.Authorize(s, 'POST', '/api/desktop/bootstrap/security-operations/plan-release', {}).ok, true);
});
test('first passkey enrollment accepts recent password with no console token', () => {
    const s = session(); assert.equal(state.production.passkeyCredentials.size, 0);
    assert.equal(guard.Authorize(s, 'POST', begin, {}).ok, true);
    assert.equal(fs.existsSync(path.join(tmp, '.admin-enrollment')), false);
});
test('existing passkeys do not force a password-authenticated administrator to use them', () => {
    const s = session(); state.production.passkeyCredentials.set('known', { role: 'admin', revokedAt: 0 });
    assert.equal(guard.Authorize(s, 'POST', begin, {}).ok, true);
    assert.equal(guard.Authorize(s, 'POST', '/api/production/passkeys/revoke', {}).ok, true);
});
test('ordinary enrollment begin and finish require current recent authentication', () => {
    const s = session(); stale(s);
    for (const route of [begin, finish]) assert.equal(guard.Authorize(s, 'POST', route, {}).reason, 'ADMIN_REAUTH_REQUIRED');
});
test('explicit invalid server recovery token never silently falls back to a recent password', () => {
    const s = session(); assert.equal(guard.Authorize(s, 'POST', begin, {}, '', 'bad-token').ok, false);
});
test('optional console recovery stays single-use, hashed, and registration-only', () => {
    const s = session(); stale(s); const approval = enrollment.Issue(s.id);
    const file = path.join(tmp, '.admin-enrollment', crypto.createHash('sha256').update(approval.token).digest('hex') + '.json');
    assert(!fs.readFileSync(file, 'utf8').includes(approval.token));
    assert.equal(guard.Authorize(s, 'POST', begin, {}, '', approval.token).ok, true); assert.equal(fs.existsSync(file), false);
    enrollment.Bind(s, { ok: true, challengeId: 'ONE_USE_CHALLENGE' });
    assert.equal(guard.Authorize(s, 'POST', finish, { challengeId: 'ONE_USE_CHALLENGE' }, '').ok, true);
    assert.equal(guard.Authorize(s, 'POST', finish, { challengeId: 'ONE_USE_CHALLENGE' }, '').ok, false);
    assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, false);
});
test('recovery permit cannot refresh sensitive-action authorization', () => {
    const s = session(); stale(s); const p = enrollment.Issue(s.id);
    assert.equal(guard.Authorize(s, 'POST', critical, {}, '', p.token).ok, false);
    assert.equal(guard.Authorize(s, 'POST', begin, {}, '', p.token).ok, true);
});
test('wrong session cannot consume a permit for itself', () => {
    const a = session(), b = session(), p = enrollment.Issue(a.id);
    assert.equal(guard.Authorize(b, 'POST', begin, {}, '', p.token).ok, false);
});
test('wrong registration challenge burns optional finish permit', () => {
    const s = session(), p = enrollment.Issue(s.id); enrollment.Authorize(s, 'POST', begin, {}, p.token);
    enrollment.Bind(s, { ok: true, challengeId: 'RIGHT' });
    assert.equal(enrollment.Authorize(s, 'POST', finish, { challengeId: 'WRONG' }, '').ok, false);
    assert.equal(enrollment.Authorize(s, 'POST', finish, { challengeId: 'RIGHT' }, '').ok, false);
});
test('expired optional console permit cannot enroll', () => {
    const s = session(), p = enrollment.Issue(s.id); now = p.expiresAt;
    assert.equal(enrollment.Authorize(s, 'POST', begin, {}, p.token).ok, false);
});
test('viewer, removed session, non-POST, and unbounded recovery token remain rejected', () => {
    const s = session(), p = enrollment.Issue(s.id);
    assert.equal(guard.Authorize(web.CreateSession(request, 'viewer'), 'POST', critical, {}).ok, false);
    assert.equal(enrollment.Authorize(s, 'GET', begin, {}, p.token).ok, false);
    assert.equal(enrollment.Authorize(s, 'POST', begin, {}, 'a'.repeat(65536)).ok, false);
    web.RevokeSession(s.id); assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, false);
});
test('changing server password invalidates previously authenticated sessions', () => {
    const s = session(); process.env.ADMIN_SECRET += '-rotated'; assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, false);
});
test('optional larger step-up scope still accepts either method, not stale cookies', () => {
    const s = session(); process.env.DESKTOP_ADMIN_REAUTH_REQUIRED = '1';
    const route = '/api/desktop/bootstrap/security-operations/plan-release';
    assert.equal(guard.Authorize(s, 'POST', route, {}).ok, true); stale(s);
    assert.equal(guard.Authorize(s, 'POST', route, {}).reason, 'ADMIN_REAUTH_REQUIRED');
});
test('explicit unrelated dual-approval identity policy is not disabled by password choice', () => {
    const s = session(); state.production.deploymentManifest.dualApprovalRequired = true;
    assert.equal(guard.Authorize(s, 'POST', '/api/production/transport', {}).reason, 'SECURITY_ADMIN_IDENTITY_REQUIRED');
    assert.equal(guard.Authorize(s, 'POST', critical, {}).ok, true); // existing SINGLE_ADMIN desktop scope
});
test('status advertises password OR passkey and retains mandatory recent-authentication floor', () => {
    const status = guard.Status(); assert.equal(status.mode, 'SINGLE_ADMIN'); assert.equal(status.stepUpRequired, true);
    assert.equal(status.criticalAuthenticationMethod, 'PASSWORD_OR_PASSKEY'); assert.equal(status.criticalReauthenticationMandatory, true);
    assert.equal(status.enrollmentAuthentication, 'PASSWORD_OR_PASSKEY'); assert.equal(status.dualApprovalRequired, false);
});
