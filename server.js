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
LoadDatabase();
require('./services/desktopMachinePolicy').Load();
LoadRecentAudit();
require('./services/haCoordinator').Start();
console.log('Game Windows License Service');
console.log('Web Admin:', WEB_ADMIN_VERSION, 'HTTP Port:', WEB_ADMIN_PORT);
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

setInterval(() => require('./services/productionCenter').RetentionApply('SCHEDULED'), 24 * 60 * 60 * 1000).unref();

setInterval(() => SaveDatabase(), 30000);
setInterval(() => CreateBackup('auto'), AUTO_BACKUP_INTERVAL_MS);

process.on('SIGINT', Shutdown);
process.on('SIGTERM', Shutdown);
