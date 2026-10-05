'use strict';

const fs = require('fs');
const path = require('path');

const config = require('../config/config');
const state = require('../core/state');
const {
    Now, NormalizeID, NormalizeLicenseKey, NormalizeVersion, SafeField, SendLine
} = require('../core/utils');
const {
    GetOnlineServer, GetOnlineClient, GetSavedClientByID,
    FindClientDeviceKey, FindServerDeviceKey, ServerExists, ClientExists,
    GetKickUntil, ServerHealth, ClientHealth, GetServerClientCount
} = require('../identity/identityManager');
const { GetLicenseStatus } = require('../storage/licenseArchive');
const { NoticeAll } = require('../relay/notifications');
const { SaveDatabase } = require('../storage/database');
const { CreateBackup, RestoreBackup } = require('../storage/backup');
const { AuditSearch, LogEvent } = require('../storage/audit');
const { EnforceVersionPolicy } = require('../services/versionPolicy');
const { HealthSnapshot } = require('../services/dashboard');
const { BuildSystemHealth } = require('../services/systemHealth');
const { CheckCurrentDatabase, VerifyBackup } = require('../services/integrityCheck');
const { BuildStatistics } = require('../services/statistics');
const { StartDrain, StopDrain, ClearDrainMeta, GetDrainStatus } = require('../services/drainMonitor');
const { ListAdminActivity } = require('../services/adminActivity');
const { GetReconnectStatus } = require('../services/reconnectMonitor');
const { GetExpirySummary } = require('../services/licenseMonitor');
const { ListNotifications, NotificationSummary, MarkRead, MarkAllRead, ClearNotifications } = require('../services/notificationCenter');
const { Can, IsAdmin, ClientIP, ListSessions, RevokeSession, RevokeOtherSessions, RevokeAllSessions } = require('./webAuth');
const deviceControl = require('../services/deviceControl');
const featureFlags = require('../services/featureFlags');
const protocolReadiness = require('../services/protocolReadiness');
const deviceAuth = require('../services/deviceAuth');
const productionRoutes = require('./routes/productionRoutes');
const storageMigration = require('../services/storageMigration');
const releaseManager = require('../services/releaseManager');
const configHistory = require('../services/configHistory');
const deviceEnrollment = require('../services/deviceEnrollment');
const secretRotation = require('../services/deviceSecretRotation');
const securityDashboard = require('../services/securityDashboard');
const maintenanceService = require('../services/maintenance');
const networkSecurity = require('../services/networkSecurity');
const processorCenter = require('../services/processorCenter');
const pushManager = require('../services/pushManager');
const dailyHealth = require('../services/dailyHealth');
const deviceRegistry = require('../services/deviceRegistry');
const historyCleanup = require('../services/historyCleanup');

const {
    BACKUP_DIR, DATA_DIR, CURRENT_PROTOCOL_VERSION,
    SERVER_KICK_BLOCK_MS, CLIENT_KICK_BLOCK_MS,
    MAX_CLIENTS_PER_SERVER, RATE_LIMIT_MAX, MAX_BULK_KEYS,
    ENABLE_LEGACY_TCP_ADMIN, WEB_ADMIN_VERSION
} = config;

function Json(res, status, data) {
    let text;
    try {
        text = JSON.stringify(data);
    } catch (error) {
        console.error('[WEB JSON ERROR]', error && error.stack ? error.stack : error);
        status = 500;
        text = JSON.stringify({
            ok: false,
            error: 'RESPONSE_SERIALIZATION_FAILED',
            detail: 'JSON_SERIALIZATION'
        });
    }
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(text),
        'Cache-Control': 'no-store'
    });
    res.end(text);
}

function ApiError(res, status, code, detail = '') {
    Json(res, status, { ok: false, error: code, detail, problem: require('../services/desktopOperationsErrors').Explain(code) });
}

function DecodePart(value) {
    try { return decodeURIComponent(value); } catch (_) { return ''; }
}

function NormalizeAlias(value) {
    return SafeField(value || '').trim().slice(0, 64);
}

function NormalizeNote(value) {
    return String(value || '').replace(/[\r\n]+/g, ' ').trim().slice(0, 500);
}

function RequireAdmin(res, session) {
    if (IsAdmin(session)) return true;
    ApiError(res, 403, 'FORBIDDEN');
    return false;
}

function RequireOperation(res, session, operation) {
    if (Can(session, operation)) return true;
    ApiError(res, 403, 'FORBIDDEN');
    return false;
}



const { ReadJsonBody } = require('./requestBody');

function BuildDashboard() {
    let available = 0;
    let bound = 0;
    let expired = 0;
    let suspended = 0;
    let onlineServers = 0;
    let onlineClients = 0;

    for (const id of state.serverIdentities.values()) if (GetOnlineServer(id)) onlineServers++;
    for (const saved of state.clientIdentities.values()) if (GetOnlineClient(saved.id)) onlineClients++;
    for (const license of state.licenses.values()) {
        const status = GetLicenseStatus(license);
        if (status === 'AVAILABLE') available++;
        else if (status === 'BOUND') bound++;
        else if (status === 'EXPIRED') expired++;
        else if (status === 'SUSPENDED') suspended++;
    }

    const ackTotal = state.runtimeStats.ackOk + state.runtimeStats.ackError + state.runtimeStats.ackTimeout;
    const ackSuccessRate = ackTotal > 0 ? (state.runtimeStats.ackOk / ackTotal) * 100 : 100;

    return {
        serviceEnabled: state.serviceEnabled,
        maintenanceMode: state.maintenanceMode,
        uptimeMs: Now() - state.runtimeStats.startedAt,
        servers: {
            total: state.serverIdentities.size,
            online: onlineServers,
            disabled: state.disabledServers.size,
            draining: state.drainingServers.size
        },
        clients: {
            total: state.clientIdentities.size,
            online: onlineClients,
            disabled: state.disabledClients.size
        },
        licenses: {
            total: state.licenses.size,
            available,
            bound,
            expired,
            suspended
        },
        ack: {
            pending: state.pendingRequests.size,
            ok: state.runtimeStats.ackOk,
            error: state.runtimeStats.ackError,
            timeout: state.runtimeStats.ackTimeout,
            retries: state.runtimeStats.ackRetries,
            successRate: Number(ackSuccessRate.toFixed(2))
        },
        recovery: {
            queued: state.offlineQueue.size,
            deadLetters: Array.from(state.deadLetters.values()).filter(x => x.status === 'ACTIVE').length,
            replayed: state.runtimeStats.replayedRequests,
            dequeued: state.runtimeStats.dequeuedRequests
        },
        versions: {
            protocol: state.minProtocolVersion,
            server: state.minServerVersion,
            client: state.minClientVersion
        },
        totalConnections: state.runtimeStats.totalConnections,
        notices: state.runtimeStats.notices,
        licenseExpiry: GetExpirySummary(),
        notifications: NotificationSummary(),
        ha: require('../services/haCoordinator').Status(),
        recentEvents: state.events.slice(-30).reverse()
    };
}

function BuildServers() {
    const out = [];
    for (const [deviceKey, serverId] of state.serverIdentities) {
        const live = GetOnlineServer(serverId);
        const kickedUntil = GetKickUntil(state.kickedServers, serverId);
        let status = live ? 'ONLINE' : 'OFFLINE';
        if (state.disabledServers.has(serverId)) status = 'DISABLED';
        else if (state.drainingServers.has(serverId)) status = 'DRAINING';
        else if (kickedUntil > Now()) status = 'KICKED';

        const liveClients = live ? live.clients.size : 0;
        const savedClients = GetServerClientCount(serverId);
        const canAcceptClients = !!live && !state.disabledServers.has(serverId) && !state.drainingServers.has(serverId) && kickedUntil <= Now() && liveClients < MAX_CLIENTS_PER_SERVER && savedClients < MAX_CLIENTS_PER_SERVER;
        let acceptState = 'READY';
        if (!live) acceptState = 'OFFLINE';
        else if (state.disabledServers.has(serverId)) acceptState = 'DISABLED';
        else if (state.drainingServers.has(serverId)) acceptState = 'DRAINING';
        else if (kickedUntil > Now()) acceptState = 'KICKED';
        else if (liveClients >= MAX_CLIENTS_PER_SERVER || savedClients >= MAX_CLIENTS_PER_SERVER) acceptState = 'FULL';

        const ack = state.runtimeStats.serverAckStats.get(serverId) || { ok: 0, error: 0, timeout: 0 };
        const ackTotal = ack.ok + ack.error + ack.timeout;
        const reconnectWindow = GetReconnectStatus('SERVER', serverId);
        out.push({
            id: serverId,
            alias: state.serverAliases.get(serverId) || '',
            note: state.serverNotes.get(serverId) || '',
            ack: { ...ack, successRate: ackTotal ? Number(((ack.ok / ackTotal) * 100).toFixed(2)) : 100 },
            deviceKey,
            status,
            online: !!live,
            health: reconnectWindow.flapping ? 'FLAPPING' : (live ? ServerHealth(live) : 'OFFLINE'),
            reconnectWindow,
            clients: liveClients,
            savedClients,
            canAcceptClients,
            acceptState,
            lastIP: live ? live.lastIP : '',
            lastSeen: live ? live.lastSeen : 0,
            kickedUntil,
            protocolVersion: live ? live.protocolVersion : 0,
            appVersion: live ? live.appVersion : '',
            rttMs: live ? live.rttMs : -1,
            reconnectCount: state.runtimeStats.serverReconnects.get(serverId) || 0,
            drain: GetDrainStatus(serverId)
        });
    }
    return out.sort((a, b) => a.id.localeCompare(b.id));
}

function BuildServerDetail(serverId) {
    serverId = NormalizeID(serverId);
    if (!ServerExists(serverId)) return null;
    const server = BuildServers().find(x => x.id === serverId);
    return { ...server, clientsList: [] };
}





function BuildBackups() {
    try {
        return fs.readdirSync(BACKUP_DIR)
            .filter(file => file.endsWith('.json'))
            .map(file => {
                const stat = fs.statSync(path.join(BACKUP_DIR, file));
                return { file, size: stat.size, mtimeMs: stat.mtimeMs };
            })
            .sort((a, b) => b.mtimeMs - a.mtimeMs);
    } catch (_) {
        return [];
    }
}


function GlobalSearch(query) {
    query = String(query || '').trim().toUpperCase();
    if (!query) return [];
    const out = [];
    const add = (kind, id, label, detail, status = '') => {
        if (out.length >= 60) return;
        out.push({ kind, id, label, detail, status });
    };

    for (const server of BuildServers()) {
        const text = `${server.id}|${server.alias}|${server.deviceKey}|${server.note}|${server.lastIP}`.toUpperCase();
        if (text.includes(query)) add('SERVER', server.id, server.alias || server.id, `${server.id} // ${server.status} // ${server.health}`, server.status);
    }
    for (const trace of require('../services/requestTrace').SearchTraces(query).slice(0, 20)) {
        add('REQUEST', trace.key, trace.requestId, `${trace.status} // ${trace.clientId} → ${trace.serverId} // ${trace.durationMs || 0}ms`, trace.status);
    }
    return out.slice(0, 60);
}

function BuildSystem() {
    return {
        serviceEnabled: state.serviceEnabled,
        maintenanceMode: state.maintenanceMode,
        maintenanceSchedule: state.maintenanceSchedule,
        maintenanceAutomation: maintenanceService.GetMaintenanceAutomationStatus(),
        minProtocolVersion: state.minProtocolVersion,
        minServerVersion: state.minServerVersion,
        minClientVersion: state.minClientVersion,
        currentProtocolVersion: CURRENT_PROTOCOL_VERSION,
        maxClientsPerServer: MAX_CLIENTS_PER_SERVER,
        rateLimit: RATE_LIMIT_MAX,
        dataDir: DATA_DIR,
        webAdminVersion: WEB_ADMIN_VERSION,
        webUiRevision: config.WEB_UI_REVISION,
        legacyTcpAdminEnabled: ENABLE_LEGACY_TCP_ADMIN,
        health: HealthSnapshot()
    };
}


module.exports = { fs, path, config, state, Now, NormalizeID, NormalizeLicenseKey, NormalizeVersion, SafeField, SendLine, GetOnlineServer, GetOnlineClient, GetSavedClientByID, FindClientDeviceKey, FindServerDeviceKey, ServerExists, ClientExists, GetKickUntil, ServerHealth, ClientHealth, GetServerClientCount, GetLicenseStatus, NoticeAll, SaveDatabase, CreateBackup, RestoreBackup, AuditSearch, LogEvent, EnforceVersionPolicy, HealthSnapshot, BuildSystemHealth, CheckCurrentDatabase, VerifyBackup, BuildStatistics, StartDrain, StopDrain, ClearDrainMeta, GetDrainStatus, ListAdminActivity, GetReconnectStatus, GetExpirySummary, ListNotifications, NotificationSummary, MarkRead, MarkAllRead, ClearNotifications, Can, IsAdmin, ClientIP, ListSessions, RevokeSession, RevokeOtherSessions, RevokeAllSessions, deviceControl, featureFlags, protocolReadiness, deviceAuth, productionRoutes, storageMigration, releaseManager, configHistory, deviceEnrollment, secretRotation, securityDashboard, maintenanceService, networkSecurity, processorCenter, pushManager, dailyHealth, deviceRegistry, historyCleanup, BACKUP_DIR, DATA_DIR, CURRENT_PROTOCOL_VERSION, SERVER_KICK_BLOCK_MS, CLIENT_KICK_BLOCK_MS, MAX_CLIENTS_PER_SERVER, RATE_LIMIT_MAX, MAX_BULK_KEYS, ENABLE_LEGACY_TCP_ADMIN, WEB_ADMIN_VERSION, Json, ApiError, DecodePart, NormalizeAlias, NormalizeNote, RequireAdmin, RequireOperation, ReadJsonBody, BuildDashboard, BuildServers, BuildServerDetail, BuildBackups, GlobalSearch, BuildSystem };
