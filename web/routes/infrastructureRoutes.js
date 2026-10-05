'use strict';
const { NormalizeID, LogEvent, storageMigration, securityDashboard, networkSecurity, Json, ApiError, DecodePart, RequireAdmin, RequireOperation } = require('../apiContext');
async function Handle({ method, pathname, url, body, req, res, session }) {
    let match, m;
    if (method === 'GET' && pathname === '/api/storage/migration/status') {
        if (!RequireAdmin(res, session)) return true;
        Json(res, 200, { ok: true, migration: storageMigration.Status() });
        return true;
    }

    if (method === 'GET' && pathname === '/api/storage/migration/schema') {
        if (!RequireAdmin(res, session)) return true;
        Json(res, 200, { ok: true, schema: storageMigration.Schema() });
        return true;
    }

    if (method === 'POST' && pathname === '/api/storage/migration/export') {
        if (!RequireAdmin(res, session)) return true;
        const result = storageMigration.ExportBundle();
        if (!result.ok) { ApiError(res, 409, result.reason); return true; }
        LogEvent('SQLITE_MIGRATION_EXPORT', `${result.directory} ${result.checksum}`);
        Json(res, 201, result);
        return true;
    }

    if (method === 'GET' && pathname === '/api/security/dashboard') {
        if (!RequireOperation(res, session, 'VIEW')) return true;
        Json(res, 200, { ok: true, security: securityDashboard.Build() });
        return true;
    }

    if (method === 'GET' && pathname === '/api/security/network') {
        if (!RequireOperation(res, session, 'VIEW')) return true;
        Json(res, 200, { ok: true, summary: networkSecurity.Summary(), devices: networkSecurity.Overview(), geo: networkSecurity.GeoStatus() });
        return true;
    }

    if (method === 'POST' && pathname === '/api/security/network/trust') {
        if (!RequireAdmin(res, session)) return true;
        const type = String(body.type || '').toUpperCase();
        const id = NormalizeID(body.id);
        if (!['SERVER', 'CLIENT'].includes(type) || !id) { ApiError(res, 400, 'INVALID_DEVICE'); return true; }
        if (!networkSecurity.Trust(type, id)) { ApiError(res, 404, 'NETWORK_PROFILE_NOT_FOUND'); return true; }
        Json(res, 200, { ok: true, profile: networkSecurity.Get(type, id) });
        return true;
    }

    return false;
}
module.exports = { Handle };
