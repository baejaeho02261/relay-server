'use strict';
// Opaque backup compatibility. These fields have no active workflow or code loader.
const state = require('../core/state');
const FIELDS = Object.freeze([
    'clientInstallations', 'memberHub', 'supportThreads', 'supportSettings',
    'emergencyFailoverPolicy', 'clientFailoverEnabled', 'clientFailoverRecords',
    'clientServerBindings', 'offlineQueuePolicy', 'clientOfflineQueueEnabled',
    'offlineQueue', 'deadLetters', 'qrAuthRequests', 'clientBiometricProfiles',
    'pendingBuildGrants', 'buildSessions', 'clientBuildBindings', 'accessGroupGuids',
    'buildSessionPolicy'
]);
let snapshot = {};
function Import(data) {
    snapshot = {};
    for (const name of FIELDS) if (Object.hasOwn(data, name)) snapshot[name] = structuredClone(data[name]);
    state.memberHub = snapshot.memberHub ?? null;
    // Read-only historical views use these maps; they are not delivery queues.
    for (const name of ['offlineQueue', 'deadLetters']) {
        state[name].clear();
        const value = snapshot[name];
        if (value && typeof value === 'object' && !Array.isArray(value))
            for (const [key, row] of Object.entries(value)) if (row && typeof row === 'object') state[name].set(key, structuredClone(row));
    }
}
function Export() { return structuredClone(snapshot); }
module.exports = { Import, Export };
