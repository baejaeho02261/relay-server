'use strict';
const { state, Now, NormalizeID, SafeField, SendLine, GetOnlineServer, ServerExists, SaveDatabase, LogEvent, StartDrain, StopDrain, ClearDrainMeta, GetDrainStatus, deviceRegistry, SERVER_KICK_BLOCK_MS, Json, ApiError, DecodePart, NormalizeAlias, NormalizeNote, RequireAdmin, RequireOperation, BuildServers, BuildServerDetail, BuildClientDetail } = require('../apiContext');
async function Handle({ method, pathname, url, body, req, res, session }) {
    let match, m;
    if (method === 'GET' && pathname === '/api/servers') {
        if (!RequireOperation(res, session, 'SERVER_LIST')) return true;
        Json(res, 200, { ok: true, servers: BuildServers() });
        return true;
    }

    match = pathname.match(/^\/api\/servers\/([^/]+)$/);
    if (method === 'DELETE' && match) {
        if (!RequireAdmin(res, session)) return true;
        const result = deviceRegistry.DeleteServer(DecodePart(match[1]));
        if (!result.ok) { ApiError(res, 404, result.reason); return true; }
        Json(res, 200, result);
        return true;
    }
    if (method === 'GET' && match) {
        if (!RequireOperation(res, session, 'SERVER_TREE')) return true;
        const item = BuildServerDetail(DecodePart(match[1]));
        if (!item) { ApiError(res, 404, 'SERVER_NOT_FOUND'); return true; }
        Json(res, 200, { ok: true, server: item });
        return true;
    }

    match = pathname.match(/^\/api\/servers\/([^/]+)\/alias$/);
    if (method === 'POST' && match) {
        if (!RequireAdmin(res, session)) return true;
        const id = NormalizeID(DecodePart(match[1]));
        if (!ServerExists(id)) { ApiError(res, 404, 'SERVER_NOT_FOUND'); return true; }
        const alias = NormalizeAlias(body.alias);
        if (alias) state.serverAliases.set(id, alias); else state.serverAliases.delete(id);
        SaveDatabase();
        LogEvent('SERVER_ALIAS', `${id} -> ${alias || '(cleared)'}`);
        Json(res, 200, { ok: true, id, alias });
        return true;
    }

    match = pathname.match(/^\/api\/servers\/([^/]+)\/note$/);
    if (method === 'POST' && match) {
        if (!RequireOperation(res, session, 'NOTE')) return true;
        const id = NormalizeID(DecodePart(match[1]));
        if (!ServerExists(id)) { ApiError(res, 404, 'SERVER_NOT_FOUND'); return true; }
        const note = NormalizeNote(body.note);
        if (note) state.serverNotes.set(id, note); else state.serverNotes.delete(id);
        SaveDatabase();
        LogEvent('SERVER_NOTE', `${id} ${note ? 'updated' : 'cleared'}`);
        Json(res, 200, { ok: true, id, note });
        return true;
    }

    match = pathname.match(/^\/api\/servers\/([^/]+)\/(kick|disable|enable|drain-on|drain-off)$/);
    if (method === 'POST' && match) {
        if (!RequireAdmin(res, session)) return true;
        const id = NormalizeID(DecodePart(match[1]));
        const action = match[2];
        if (!ServerExists(id)) { ApiError(res, 404, 'SERVER_NOT_FOUND'); return true; }

        if (action === 'kick') {
            const until = Now() + SERVER_KICK_BLOCK_MS;
            state.kickedServers.set(id, until);
            const live = GetOnlineServer(id);
            if (live) { SendLine(live.socket, `ERROR|ADMIN_KICK|${until}`); live.socket.destroy(); }
            LogEvent('SERVER_KICK', `${id} until ${until}`);
            Json(res, 200, { ok: true, id, kickedUntil: until });
            return true;
        }
        if (action === 'disable') {
            state.disabledServers.add(id);
            ClearDrainMeta(id);
            state.kickedServers.delete(id);
            SaveDatabase();
            const live = GetOnlineServer(id);
            if (live) { SendLine(live.socket, 'ERROR|SERVER_DISABLED'); live.socket.destroy(); }
            LogEvent('SERVER_DISABLE', id);
        } else if (action === 'enable') {
            state.disabledServers.delete(id);
            state.kickedServers.delete(id);
            SaveDatabase();
            LogEvent('SERVER_ENABLE', id);
        } else if (action === 'drain-on') {
            const result = StartDrain(id);
            if (!result.ok) { ApiError(res, 409, result.reason); return true; }
            LogEvent('SERVER_DRAIN_ON', `${id} initialClients=${result.status.initialClients}`);
        } else if (action === 'drain-off') {
            StopDrain(id);
            LogEvent('SERVER_DRAIN_OFF', id);
        }
        Json(res, 200, { ok: true, id, action, drain: GetDrainStatus(id) });
        return true;
    }

    return false;
}
module.exports = { Handle };
