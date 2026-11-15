'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config/peace.runtime-configuration');
const state = require('./peace.runtime-state');

const { HOST, PORT, HEALTH_PORT, DATA_DIR, DB_FILE, DB_BAK_FILE, BACKUP_DIR, AUDIT_DIR, CURRENT_PROTOCOL_VERSION, DEFAULT_MIN_PROTOCOL_VERSION, DEFAULT_MIN_SERVER_VERSION, DEFAULT_MIN_CLIENT_VERSION, ADMIN_CREDENTIALS, ADMIN_AUTH_WINDOW_SECONDS, ADMIN_SESSION_TIMEOUT_MS, CONFIRM_TOKEN_TTL_MS, SERVER_KICK_BLOCK_MS, CLIENT_KICK_BLOCK_MS, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX, MAX_CLIENTS_PER_SERVER, REQUEST_HISTORY_TIMEOUT_MS, ACK_RETRY_MS, ACK_TIMEOUT_MS, ACK_MAX_RETRIES, MAX_INPUT_BUFFER, MAX_BULK_KEYS, MAX_SEARCH_RESULTS, MAX_EVENT_MEMORY, AUTO_BACKUP_INTERVAL_MS, MAX_BACKUPS, DANGEROUS_PREFIXES } = config;
const { servers, clients, serverIdentities, clientIdentities, licenses, disabledServers, drainingServers, disabledClients, kickedServers, kickedClients, requestHistory, pendingRequests, rateLimits, events, confirmTokens, ipHistory, runtimeStats } = state;

function CreateBackup(...args) { return require("../storage/snapshots/peace.backup.js").CreateBackup(...args); }
function FailPendingRequestsForServer(...args) { return require('../relay/peace.ack-manager').FailPendingRequestsForServer(...args); }
function GetOnlineServer(...args) { return require('../identity/peace.identity-manager').GetOnlineServer(...args); }
function LogEvent(...args) { return require("../storage/audit/peace.audit.js").LogEvent(...args); }
function Now(...args) { return require("./peace.utilities.js").Now(...args); }
function SafeIP(...args) { return require("./peace.utilities.js").SafeIP(...args); }
function SaveDatabase(...args) { return require("../storage/snapshots/peace.database.js").SaveDatabase(...args); }
function SendLine(...args) { return require("./peace.utilities.js").SendLine(...args); }

function ForceReconnectAll(reason) {
    for (const c of Array.from(clients.values())) { SendLine(c.socket, `ERROR|${reason}`); try { c.socket.destroy(); } catch (_) {} }
    for (const c of Array.from(servers.values())) { SendLine(c.socket, `ERROR|${reason}`); try { c.socket.destroy(); } catch (_) {} }
}

function CleanupTransient() {
    const now=Now();
    for(const [key,state] of rateLimits) if(state.startedAt<now-RATE_LIMIT_WINDOW_MS*5) rateLimits.delete(key);
    for(const [id,until] of kickedServers) if(now>=until){kickedServers.delete(id);LogEvent('SERVER_KICK_EXPIRED',id);}
    for(const [id,until] of kickedClients) if(now>=until){kickedClients.delete(id);LogEvent('CLIENT_KICK_EXPIRED',id);}
    for(const [token,item] of confirmTokens) if(now>=item.expiresAt) confirmTokens.delete(token);
    // Connection callbacks normally complete pairing synchronously.  This
    // idempotent sweep closes the narrow race where Android and its PC finish
    // registering in the same event-loop interval or one transport is being
    // replaced.  It never moves an existing fixed binding.
    // Desktop mode preserves archived pairing records without repair/backfill.
}

function DisconnectConnection(connection) {
    require("../services/licensing/peace.retired-legacy").Service('member/testAccess').Revoke(connection);
    // Legacy workflow queues are retired; normal connection cleanup follows.
    if (connection.serviceWaiting) { connection.disconnected = true; return; }
    if(connection.disconnected)return;connection.disconnected=true;
    if(connection.type==='server'){
        const currentServer=connection.serverId?servers.get(connection.serverId):null;
        // A reconnect replaces the map entry before the old socket's close
        // callback necessarily runs. Ignore that stale callback completely.
        if(connection.serverId&&(connection.superseded||(currentServer&&currentServer!==connection))){
            LogEvent('SERVER_STALE_CONNECTION_CLOSED',connection.serverId);
            return;
        }
        if(connection.serverId&&servers.get(connection.serverId)===connection)servers.delete(connection.serverId);
        if(connection.serverId){
            require("../services/licensing/peace.retired-legacy").Service('buildGate').RevokeForServer(connection.serverId,'SERVER_OFFLINE');
            if(connection.buildGateCapable)for(const client of clients.values()){
                if(client.serverId!==connection.serverId)continue;
                client.buildCompleted=false;
                SendLine(client.socket,`BUILD_REQUIRED|${connection.serverId}`);
            }
            FailPendingRequestsForServer(connection.serverId,'SERVER_OFFLINE');LogEvent('SERVER_OFFLINE',connection.serverId);try{require("../services/licensing/peace.retired-legacy").Service('emergencyFailover').MarkServerOffline(connection.serverId);}catch(_){}
        }
    }else if(connection.type==='client'){
        const currentClient=connection.clientId?clients.get(connection.clientId):null;
        if(connection.clientId&&(connection.superseded||(currentClient&&currentClient!==connection))){
            LogEvent('CLIENT_STALE_CONNECTION_CLOSED',connection.clientId);
            return;
        }
        if(connection.clientId) require("../services/licensing/peace.retired-legacy").Service('buildGate').RevokeForClient(connection.clientId,'CLIENT_OFFLINE');
        if(connection.clientId) state.clientBiometricChallenges.delete(connection.clientId);
        if(connection.clientId&&clients.get(connection.clientId)===connection)clients.delete(connection.clientId);
        if(connection.clientId&&connection.serverId){const s=GetOnlineServer(connection.serverId);if(s)s.clients.delete(connection.clientId);}
        if(connection.clientId)LogEvent('CLIENT_OFFLINE',connection.clientId);
    }else if(connection.type==='admin'){
        LogEvent('ADMIN_OFFLINE',SafeIP(connection.socket));
    }
}

const shutdownHooks=new Set();let shutdownPromise,persistenceReady=false;
function MarkStorageReady(){if(shutdownPromise)throw Error('SERVER_SHUTTING_DOWN');persistenceReady=true;}
function RegisterShutdownHook(stop){if(typeof stop!=='function')throw Error('SHUTDOWN_HOOK_INVALID');shutdownHooks.add(stop);return()=>shutdownHooks.delete(stop);}
function StopLoaded(name,method){const file=require.resolve(name);const entry=require.cache[file];return entry?.exports?.[method]?.();}
function Shutdown(code=0){
 if(shutdownPromise)return shutdownPromise;const exitCode=Number.isInteger(code)?code:0;
 const deadline=setTimeout(()=>{console.error('SHUTDOWN_DEADLINE_REACHED');process.exit(exitCode||1);},8000);deadline.unref();
 shutdownPromise=(async()=>{
  let failed=false;
  const stops=Array.from(shutdownHooks,stop=>Promise.resolve().then(stop));shutdownHooks.clear();
  for(const [name,method]of [
   ["../services/operations/peace.desktop-workspace",'Stop'],["../services/security/peace.server-security-center",'Stop'],
   ["../services/artifacts/peace.desktop-packing-jobs",'Stop'],["../services/artifacts/peace.custom-package-jobs",'Stop'],
   ["../services/network/peace.ha-coordinator",'Stop'],["../services/network/peace.desktop-connect",'Stop'],
   ["../web/events/peace.web-events",'Stop']]){try{stops.push(Promise.resolve(StopLoaded(name,method)));}catch(_){failed=true;}}
  const queues=require.cache[require.resolve("../services/runtime/peace.desktop-work-queue")]?.exports;
  for(const key of ['auth','pe','proof','renewalProof','tpmAttestation'])if(queues?.[key])stops.push(queues[key].close());
  for(const result of await Promise.allSettled(stops))if(result.status==='rejected')failed=true;
  try{if(persistenceReady){if(!exitCode)CreateBackup('shutdown');SaveDatabase();}}catch(_){failed=true;console.error('SHUTDOWN_PERSISTENCE_FAILED');}
  for(const [name,method]of [["../services/observability/peace.desktop-performance-metrics",'Close'],["../storage/sqlite/peace.sqlite-database",'Close'],["../services/recovery/peace.desktop-recovery-witness",'Close']])try{await StopLoaded(name,method);}catch(_){failed=true;}
  clearTimeout(deadline);process.exit(exitCode||(failed?1:0));
 })();return shutdownPromise;
}

module.exports = {
    ForceReconnectAll,
    CleanupTransient,
    DisconnectConnection,
    Shutdown,
    RegisterShutdownHook,
    MarkStorageReady
};
