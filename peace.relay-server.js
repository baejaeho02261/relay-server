'use strict';

let storageOwned=false;

function Fatal(reason){
 const candidate=reason?.code||reason?.message;
 const code=typeof candidate==='string'&&/^[A-Z][A-Z0-9_]{1,79}$/.test(candidate)?candidate:'SERVER_FATAL_ERROR';
 console.error('[SERVER_FATAL]',code,'서버를 안전하게 종료합니다. 설정과 상태를 확인하세요.');
 if(!storageOwned){process.exit(1);return;}
 try{Promise.resolve(require("./core/peace.lifecycle.js").Shutdown(1)).catch(()=>process.exit(1));}catch(_){process.exit(1);}
}
process.on('uncaughtException',Fatal);
process.on('unhandledRejection',Fatal);


require("./services/security/peace.service-isolation").Check('authority');
const http = require('http');

const config = require('./config/peace.runtime-configuration');
// Fail before storage locks, key generation or listeners on a bad web mode.
try { require("./web/transport/peace.web-transport").Settings(); }
catch (error) { console.error('[WEB_ADMIN_CONFIGURATION_ERROR]'); throw error; }
// Acquire before loading any service that can create keys, migrate storage,
// save state or open a listener. The lock remains held through shutdown writes.
require("./services/storage/peace.desktop-storage-acl").Check();
require("./services/storage/peace.desktop-single-writer").Acquire(config.DATA_DIR, { haEnabled: config.HA_ENABLED });
storageOwned=true;
require("./tools/runtime/peace.runtime-pem-files").ProvisionAuthority();
const { EnsureDirs } = require("./core/peace.utilities.js");
const { LoadRecentAudit } = require("./storage/audit/peace.audit.js");
const { LoadDatabase, SaveDatabase } = require("./storage/snapshots/peace.database.js");
const { CreateBackup } = require("./storage/snapshots/peace.backup.js");
const { Shutdown, RegisterShutdownHook, MarkStorageReady } = require("./core/peace.lifecycle.js");
const scheduledTimers=new Set();
function ScheduleEvery(fn,ms){const timer=setInterval(fn,ms);scheduledTimers.add(timer);return timer;}
RegisterShutdownHook(()=>{for(const timer of scheduledTimers)clearInterval(timer);scheduledTimers.clear();});
function TrackServer(server){if(!server)return;const sockets=new Set();server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});RegisterShutdownHook(()=>new Promise(resolve=>{for(const socket of sockets)socket.destroy();sockets.clear();if(server.listening)server.close(resolve);else resolve();}));}
const desktopMode = require("./services/runtime/peace.desktop-mode");
const { ApplyMaintenanceSchedule } = require("./services/runtime/peace.maintenance.js");
const { HealthSnapshot } = require("./services/observability/peace.dashboard.js");
const { StartWebAdmin } = require("./web/http/peace.web-server");

const { HOST, HEALTH_PORT, WEB_ADMIN_PORT, WEB_ADMIN_VERSION, DATA_DIR, AUTO_BACKUP_INTERVAL_MS } = config;

EnsureDirs();
// Never silently initialize a missing configured witness from a restored backup.
require("./services/recovery/peace.desktop-recovery-witness").Get();
// Authenticate every independent authority before mirror recovery or audit
// reconciliation can write, and before any listener accepts a session. A stale
// integrity/policy store must not remain undetected until its first HTTP request.
require("./services/licensing/peace.desktop-licenses").DB();
require("./services/devices/peace.desktop-machine-policy").Load();
require("./services/bootstrap/peace.desktop-bootstrap-store").Load();
require("./services/integrity/peace.desktop-integrity-reports").Policy();
require("./services/operations/peace.desktop-workspace-store").Load();
LoadDatabase();
require("./services/authentication/peace.admin-credential-revocations").Reconcile();
LoadRecentAudit();
if (!require("./storage/audit/peace.audit.js").VerifyAuditChain().ok) throw Error('AUDIT_CHAIN_UNAVAILABLE');
require("./services/storage/peace.desktop-audit-retention").Cleanup();
require("./services/devices/peace.desktop-machine-policy").ReconcileAudit();
// Recovery emits audit events: restore the authoritative chain head first.
require("./services/licensing/peace.desktop-licenses").ReconcileOperations();
require("./services/bootstrap/peace.desktop-bootstrap-store").Load();
require("./services/storage/peace.desktop-operation-audit").Drain({reconcile:true});
require("./services/storage/peace.desktop-storage-maintenance").Status();
require("./services/storage/peace.desktop-audit-archive").Cleanup();
require("./services/storage/peace.desktop-orphan-files").RecoverPending();
require("./services/devices/peace.desktop-device-registry").Prune();
require("./services/network/peace.ha-coordinator").Start();
console.log('Game Windows License Service');
console.log('WEB_ADMIN_ENABLED', WEB_ADMIN_VERSION);
console.log('Storage engine:', config.STORAGE_ENGINE.toUpperCase());
console.log('APK / legacy relay protocol: retired');
require("./services/network/peace.desktop-connect").Start();
require("./services/network/peace.connect-endpoint").LogConfiguration();

require("./services/security/peace.server-security-center").Start();
TrackServer(StartWebAdmin());
require("./services/operations/peace.desktop-workspace").Start();

if (HEALTH_PORT > 0 && HEALTH_PORT !== WEB_ADMIN_PORT) {
    const health = http.createServer((req, res) => {
        if (req.url !== '/health' && req.url !== '/healthz') {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'not_found' }));
            return;
        }

        const body = HealthSnapshot();
        res.writeHead(body.ok ? 200 : 503, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify(body));
    });

    TrackServer(health);
    health.listen(HEALTH_PORT, HOST, () =>
        console.log('HEALTH_LISTENER_READY')
    );
}

// No APK QR, biometric, pairing, member OAuth or relay work is scheduled.
ScheduleEvery(() => {
    desktopMode.Cleanup();
    ApplyMaintenanceSchedule();
    require("./services/observability/peace.daily-health").EnsureCurrent();
    require("./services/authentication/peace.passkey-auth").Cleanup();
}, 1000);

ScheduleEvery(() => {
    try { require("./services/runtime/peace.production-center").RetentionApply('SCHEDULED'); }
    catch (_) { console.error('SERVER_RETENTION_PENDING'); }
}, 24 * 60 * 60 * 1000).unref();

ScheduleEvery(() => { require("./services/storage/peace.desktop-operation-audit").BestEffortDrain();
    try { require("./services/storage/peace.desktop-operation-audit").Compact({minimum:4096}); } catch (_) { console.error('SERVER_AUDIT_COMPACTION_PENDING'); }
    SaveDatabase(); }, 30000);
// Retention is enforced server-side; no client clock controls deletion.
ScheduleEvery(() => {
    try { require("./services/devices/peace.desktop-device-registry").Prune(); }
    catch (_) { console.error('DEVICE_PROOF_RETENTION_PENDING'); }
}, 60 * 60 * 1000).unref();
ScheduleEvery(() => CreateBackup('auto'), AUTO_BACKUP_INTERVAL_MS);

// Persist on shutdown only after the complete synchronous startup validation.
MarkStorageReady();
process.on('SIGINT', Shutdown);
process.on('SIGTERM', Shutdown);
