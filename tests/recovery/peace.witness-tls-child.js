'use strict';
// Test harness only: one isolated process/store. Production entrypoint acquires
// the native SQLite OS lock; this fixture does not claim that lock is tested.
const fs=require('node:fs');
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const {WitnessFile}=require("../../services/recovery/peace.recovery-witness-file"),w=new WitnessFile(config.dir);
const lifecycle=require("../../tools/recovery/peace.recovery-witness-server");
const server=lifecycle.CreateServer(config,w);
lifecycle.InstallShutdown(server,{timeoutMs:150});
server.listen(0,'127.0.0.1',()=>process.send({port:server.address().port,installationId:w.status().installationId}));
process.on('message',x=>{if(x==='close')lifecycle.CloseServer(server,{timeoutMs:150}).then(()=>process.disconnect());});
// IPC belongs to this harness and must not keep a signal-stopped child alive.
process.channel.unref();
