'use strict';

const crypto = require('crypto');
const config = require('../config/config');
const state = require('../core/state');

const { ADMIN_CREDENTIALS, ADMIN_AUTH_WINDOW_SECONDS, ADMIN_SESSION_TIMEOUT_MS, CONFIRM_TOKEN_TTL_MS, DANGEROUS_PREFIXES } = config;
const { confirmTokens } = state;

function ConstantTimeEqual(...args) { return require('../core/utils').ConstantTimeEqual(...args); }
function ExecuteAdminCommand(...args) { return require('./adminHandler').ExecuteAdminCommand(...args); }
function LogEvent(...args) { return require('../storage/audit').LogEvent(...args); }
function Now(...args) { return require('../core/utils').Now(...args); }
function RandomNonce(...args) { return require('../core/utils').RandomNonce(...args); }
function RandomToken(...args) { return require('../core/utils').RandomToken(...args); }
function SafeIP(...args) { return require('../core/utils').SafeIP(...args); }
function SendLine(...args) { return require('../core/utils').SendLine(...args); }

function ResolveAdminRole(role) {
    const r = String(role || '').trim().toLowerCase();
    return ['admin', 'operator', 'viewer'].includes(r) ? r : '';
}

function RoleConfigured(role) {
    return !!ADMIN_CREDENTIALS[role];
}

const VIEWER_OPERATIONS = new Set(['WHOAMI','LIST','SEARCH','VIEW','DASHBOARD','SERVER_LIST','CLIENT_LIST','CLIENT_DETAIL','SERVER_TREE','AUDIT','VERSION_STATUS','SCHEDULE_STATUS']);
const OPERATOR_OPERATIONS = new Set([...VIEWER_OPERATIONS, 'EXTEND','UNBIND','SUSPEND','RESUME','TRANSFER','NOTICE','NOTE']);

function AdminAllowed(role, operation) {
    if (role === 'admin') return true;
    return role === 'viewer' ? VIEWER_OPERATIONS.has(operation) : role === 'operator' ? OPERATOR_OPERATIONS.has(operation) : false;
}

function MakeRoleHmac(role, nonce, timestamp) {
    return crypto.createHmac('sha256', ADMIN_CREDENTIALS[role]).update(`${role}|${nonce}|${timestamp}`, 'utf8').digest('hex').toUpperCase();
}

function ResetAdminSession(connection) {
    const sessionId = connection.adminSessionId;
    for (const [token, item] of confirmTokens) if (item.sessionId === sessionId || item.expiresAt <= Now()) confirmTokens.delete(token);
    connection.adminAuthenticated = false;
    connection.adminRole = '';
    connection.adminSessionId = '';
    connection.adminNonce = '';
    connection.pendingAdminRole = '';
}

function Authenticated(connection) {
    return !!connection.adminAuthenticated && !!connection.adminSessionId &&
        Now() - connection.adminAuthenticatedAt <= ADMIN_SESSION_TIMEOUT_MS;
}

function HandleAdminHello(connection, line) {
    ResetAdminSession(connection);
    const parts = line.split('|');
    const role = ResolveAdminRole(parts[1] || 'admin');
    if (!role || !RoleConfigured(role)) { SendLine(connection.socket, 'ADMIN_ERROR|ROLE_NOT_CONFIGURED'); return; }
    connection.pendingAdminRole = role;
    connection.adminNonce = RandomNonce();
    connection.adminNonceCreatedAt = Now();
    connection.adminAuthenticated = false;
    SendLine(connection.socket, `CHALLENGE|${connection.adminNonce}|${role}`);
}

function HandleAdminAuth(connection, line) {
    const parts = line.split('|');
    if (parts.length !== 4) { ResetAdminSession(connection); SendLine(connection.socket, 'ADMIN_ERROR|AUTH_FORMAT'); return; }
    const role = connection.pendingAdminRole;
    const nonce = parts[1];
    const timestampText = parts[2];
    const supplied = String(parts[3] || '').trim().toUpperCase();
    const timestamp = Number(timestampText);
    const expectedNonce = connection.adminNonce;
    const nonceCreatedAt = connection.adminNonceCreatedAt;
    ResetAdminSession(connection); // Every challenge permits one authentication attempt.
    if (!role || !RoleConfigured(role) || nonce !== expectedNonce || !Number.isSafeInteger(timestamp) || !/^[0-9]{1,12}$/.test(timestampText) || !/^[0-9A-F]{64}$/.test(supplied)) { SendLine(connection.socket, 'ADMIN_ERROR|AUTH_FAILED'); return; }
    if (Now() - nonceCreatedAt > 60000 || Math.abs(Math.floor(Now()/1000) - timestamp) > ADMIN_AUTH_WINDOW_SECONDS) {
        SendLine(connection.socket, 'ADMIN_ERROR|AUTH_EXPIRED'); return;
    }
    const expected = MakeRoleHmac(role, nonce, timestampText);
    if (!ConstantTimeEqual(expected, supplied)) { SendLine(connection.socket, 'ADMIN_ERROR|AUTH_FAILED'); LogEvent('ADMIN_AUTH_FAILED', `${role} ${SafeIP(connection.socket)}`); return; }
    connection.adminAuthenticated = true;
    connection.adminAuthenticatedAt = Now();
    connection.adminSessionId = RandomToken();
    connection.adminRole = role;
    connection.adminNonce = '';
    connection.pendingAdminRole = '';
    SendLine(connection.socket, `ADMIN_OK|${role}`);
    LogEvent('ADMIN_AUTH', `${role} / ${SafeIP(connection.socket)}`);
}

function IsDangerousCommand(line) {
    return DANGEROUS_PREFIXES.some(prefix => line === prefix || line.startsWith(prefix));
}

function PrepareConfirm(connection, command) {
    if (!Authenticated(connection) || connection.adminRole !== 'admin') { SendLine(connection.socket, 'ADMIN_ERROR|FORBIDDEN'); return; }
    for (const [existing, item] of confirmTokens) if (item.sessionId === connection.adminSessionId || item.expiresAt <= Now()) confirmTokens.delete(existing);
    const token = RandomToken();
    confirmTokens.set(token, { command, expiresAt: Now() + CONFIRM_TOKEN_TTL_MS, role: connection.adminRole, sessionId: connection.adminSessionId });
    SendLine(connection.socket, `CONFIRM_TOKEN|${token}|${Now() + CONFIRM_TOKEN_TTL_MS}`);
}

function ExecuteConfirmed(connection, token) {
    const item = confirmTokens.get(token);
    if (!Authenticated(connection) || !item || item.expiresAt <= Now() || item.role !== connection.adminRole || item.sessionId !== connection.adminSessionId) { SendLine(connection.socket, 'CONFIRM_ERROR|INVALID_OR_EXPIRED'); return; }
    confirmTokens.delete(token);
    ExecuteAdminCommand(connection, item.command, true);
}

module.exports = {
    ResolveAdminRole,
    RoleConfigured,
    AdminAllowed,
    MakeRoleHmac,
    HandleAdminHello,
    HandleAdminAuth,
    IsDangerousCommand,
    PrepareConfirm,
    ExecuteConfirmed
};
