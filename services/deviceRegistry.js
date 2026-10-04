'use strict';

const state = require('../core/state');
const { NormalizeID, SendLine } = require('../core/utils');

function Identity() { return require('../identity/identityManager'); }
function Save() { return require('../storage/database').SaveDatabase(); }
function Log(type, detail) { require('../storage/audit').LogEvent(type, detail); }

function DeleteDeviceMaps(type, id, deviceKey) {
    const key = `${type}:${id}`;
    const enrollmentKey = `${type}:${deviceKey}`;
    for (const map of [
        state.deviceSecrets, state.deviceAuthStatus, state.deviceAuthChallenges,
        state.deviceInfo, state.deviceCapabilities, state.deviceDiagnostics,
        state.deviceReleaseChannels, state.deviceUpdateStatus,
        state.deviceSecretRotations, state.deviceSecretMeta,
        state.deviceNetworkProfiles
    ]) map.delete(key);
    state.deviceEnrollments.delete(enrollmentKey);
    state.ipHistory.delete(key);
    for (const [commandId, command] of Array.from(state.pendingDeviceCommands.entries()))
        if (command && command.type === type && NormalizeID(command.id) === id)
            state.pendingDeviceCommands.delete(commandId);
}

function DeleteServerState(id, deviceKey) {
    state.disabledServers.delete(id);
    state.drainingServers.delete(id);
    state.kickedServers.delete(id);
    state.serverAliases.delete(id);
    state.serverNotes.delete(id);
    state.serverDrainMeta.delete(id);
    state.serverFeatureOverrides.delete(id);
    state.serverProtocolProfiles.delete(id);
    state.runtimeStats.serverReconnects.delete(id);
    state.runtimeStats.serverAckStats.delete(id);
    state.runtimeStats.serverReconnectHistory.delete(id);
    state.runtimeStats.serverFlappingAlerts.delete(id);
    DeleteDeviceMaps('SERVER', id, deviceKey);
}

function DeleteServer(serverId) {
    const identity = Identity();
    const id = NormalizeID(serverId);
    if (!identity.ServerExists(id)) return { ok: false, reason: 'SERVER_NOT_FOUND' };
    const deviceKey = identity.FindServerDeviceKey(id);
    const live = identity.GetOnlineServer(id);
    try { require('../relay/ackManager').FailPendingRequestsForServer(id, 'SERVER_DELETED'); } catch (_) {}

    // Historical rows keep their identity/history, but cannot retain a foreign
    // key to a server the administrator explicitly deleted.
    let releasedClients = 0;
    for (const saved of state.clientIdentities.values()) {
        if (saved && NormalizeID(saved.serverId) === id) { saved.serverId = ''; releasedClients++; }
    }
    for (const [clientId, binding] of state.clientServerBindings) {
        if (NormalizeID(binding?.primaryServerId) === id || NormalizeID(binding?.backupServerId) === id) {
            state.clientServerBindings.delete(clientId);
            state.clientFailoverRecords.delete(clientId);
        }
    }

    state.serverIdentities.delete(deviceKey);
    state.servers.delete(id);
    DeleteServerState(id, deviceKey);
    if (live) {
        live.superseded = true;
        SendLine(live.socket, 'ERROR|SERVER_DELETED');
        try { live.socket.destroy(); } catch (_) {}
    }
    Save();
    Log('SERVER_DELETE', id);
    return { ok: true, id, deviceKey, releasedClients, reassignedClients: 0 };
}

module.exports = { DeleteServer };
