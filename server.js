'use strict';

process.on('uncaughtException', error => {
    console.error('================================');
    console.error('FATAL UNCAUGHT EXCEPTION');
    console.error('================================');
    console.error(error && error.stack ? error.stack : error);
    console.error('================================');
    process.exit(1);
});

process.on('unhandledRejection', reason => {
    console.error('================================');
    console.error('FATAL UNHANDLED REJECTION');
    console.error('================================');
    console.error(reason && reason.stack ? reason.stack : reason);
    console.error('================================');
    process.exit(1);
});


const http = require('http');

const config = require('./config/config');
// Fail before storage locks, key generation or listeners on a bad web mode.
try { require('./web/webTransport').Settings(); }
catch (error) { console.error('[WEB_ADMIN_CONFIGURATION_ERROR]', error.message); throw error; }
// Acquire before loading any service that can create keys, migrate storage,
// save state or open a listener. The lock remains held through shutdown writes.
require('./services/desktopStorageAcl').Check();
require('./services/desktopSingleWriter').Acquire(config.DATA_DIR, { haEnabled: config.HA_ENABLED });
const { EnsureDirs } = require('./core/utils');
const { LoadRecentAudit } = require('./storage/audit');
const { LoadDatabase, SaveDatabase } = require('./storage/database');
const { CreateBackup } = require('./storage/backup');
const { Shutdown } = require('./core/lifecycle');
const desktopMode = require('./services/desktopMode');
const { ApplyMaintenanceSchedule } = require('./services/maintenance');
const { HealthSnapshot } = require('./services/dashboard');
const { StartWebAdmin } = require('./web/webServer');

const { HOST, HEALTH_PORT, WEB_ADMIN_PORT, WEB_ADMIN_VERSION, DATA_DIR, AUTO_BACKUP_INTERVAL_MS } = config;

EnsureDirs();
// Never silently initialize a missing configured witness from a restored backup.
require('./services/desktopRecoveryWitness').Get();
// Authenticate every independent authority before mirror recovery or audit
// reconciliation can write, and before any listener accepts a session. A stale
// integrity/policy store must not remain undetected until its first HTTP request.
require('./services/desktopLicenses').DB();
require('./services/desktopMachinePolicy').Load();
require('./services/desktopBootstrapStore').Load();
require('./services/desktopIntegrityReports').Policy();
require('./services/desktopWorkspaceStore').Load();
LoadDatabase();
LoadRecentAudit();
if (!require('./storage/audit').VerifyAuditChain().ok) throw Error('AUDIT_CHAIN_UNAVAILABLE');
require('./services/desktopAuditRetention').Cleanup();
require('./services/desktopMachinePolicy').ReconcileAudit();
// Recovery emits audit events: restore the authoritative chain head first.
require('./services/desktopLicenses').ReconcileOperations();
require('./services/desktopBootstrapStore').Load();
require('./services/desktopOperationAudit').Drain({reconcile:true});
require('./services/desktopStorageMaintenance').Status();
require('./services/desktopAuditArchive').Cleanup();
require('./services/desktopOrphanFiles').RecoverPending();
require('./services/desktopDeviceRegistry').Prune();
require('./services/haCoordinator').Start();
console.log('Game Windows License Service');
console.log('Web Admin:', WEB_ADMIN_VERSION, 'Port:', WEB_ADMIN_PORT);
console.log('Storage:', config.STORAGE_ENGINE.toUpperCase(), DATA_DIR);
console.log('APK / legacy relay protocol: retired');
require('./services/desktopConnect').Start();
require('./services/connectEndpoint').LogConfiguration();

StartWebAdmin();
require('./services/desktopWorkspace').Start();

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

    health.listen(HEALTH_PORT, HOST, () =>
        console.log('Health HTTP Port:', HEALTH_PORT)
    );
}

// No APK QR, biometric, pairing, member OAuth or relay work is scheduled.
setInterval(() => {
    desktopMode.Cleanup();
    ApplyMaintenanceSchedule();
    require('./services/dailyHealth').EnsureCurrent();
    require('./services/passkeyAuth').Cleanup();
}, 1000);

setInterval(() => {
    try { require('./services/productionCenter').RetentionApply('SCHEDULED'); }
    catch (_) { console.error('SERVER_RETENTION_PENDING'); }
}, 24 * 60 * 60 * 1000).unref();

setInterval(() => { require('./services/desktopOperationAudit').BestEffortDrain();
    try { require('./services/desktopOperationAudit').Compact({minimum:4096}); } catch (_) { console.error('SERVER_AUDIT_COMPACTION_PENDING'); }
    SaveDatabase(); }, 30000);
// Retention is enforced server-side; no client clock controls deletion.
setInterval(() => {
    try { require('./services/desktopDeviceRegistry').Prune(); }
    catch (_) { console.error('DEVICE_PROOF_RETENTION_PENDING'); }
}, 60 * 60 * 1000).unref();
setInterval(() => CreateBackup('auto'), AUTO_BACKUP_INTERVAL_MS);

process.on('SIGINT', Shutdown);
process.on('SIGTERM', Shutdown);
