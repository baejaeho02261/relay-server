'use strict';
// Read-only delivery gate. Findings identify files and categories, never values.
const fs=require('node:fs'),path=require('node:path');
function Run(inputRoot=path.resolve(__dirname,'../../cozy-peace')){
const root=path.resolve(inputRoot);
const excluded=new Set(['node_modules','__pycache__','.git']);
const problems=[];let scanned=0;
function files(dir){return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>{
 if(excluded.has(e.name))return [];
 if(path.resolve(dir)===path.join(root,'Railway')&&['bin','build','Cozy.BuildOutputs'].includes(e.name))return [];
 const p=path.join(dir,e.name);if(e.isSymbolicLink()){problems.push([path.relative(root,p),'SYMLINK']);return [];}
 const relative=path.relative(root,p).split(path.sep).join('/'),parts=relative.split('/');
 const project=parts[0]==='Railway'&&parts[1]==='Cozy.Projects'&&['Cozy.Launcher','Cozy.Client','Cozy.Overlay'].includes(parts[2]);
 // These exact generated paths replace the old shared build/bin exclusions.
 // Check links first, and keep rejecting unknown EXEs/DCUs beside the sources.
 if(project&&parts.length===4&&((e.isDirectory()&&e.name.toLowerCase()==='dcu')||(e.isFile()&&e.name.toLowerCase()===(parts[2]+'.exe').toLowerCase())))return [];
 return e.isDirectory()?files(p):[p];
});}
const source=files(root);
for(const p of source){
 const rel=path.relative(root,p).split(path.sep).join('/'),parts=rel.split('/');
 if(parts[0]==='Railway'&&parts.slice(1).some(x=>!x.startsWith('Cozy.')))problems.push([rel,'NATIVE_NAME_CASE']);
 if(parts[0]==='Railway'&&parts.length===2)problems.push([rel,'UNGROUPED_NATIVE_SOURCE']);
 if(parts[0]==='Relay Server'&&/\.js$/.test(p)&&!path.basename(p).startsWith('peace.'))problems.push([rel,'RELAY_JS_NAME']);
 if(/^Relay Server\/(services|tests|tools)\/[^/]+\.(js|py|ps1|bat|cpp|cs)$/.test(rel))problems.push([rel,'UNGROUPED_RELAY_SOURCE']);
 if(/\.(?:sqlite|db|exe|dll|o|obj|dcu|log|pending)$/i.test(p)||path.basename(p).startsWith('.desktop-single-writer'))problems.push([rel,'RUNTIME_OUTPUT_IN_SOURCE']);
 if(!/\.(?:js|pas|dpr|inc|cpp|h|json|example|md|txt|html|ps1|bat|targets|cs)$/.test(p))continue;
 scanned++;const text=fs.readFileSync(p,'utf8');
 const fixture=parts.some(x=>/^(?:tests|fixtures|Cozy\.Tests)$/i.test(x));
 if(fixture)continue;
 if(/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{64,}-----END (?:RSA |EC )?PRIVATE KEY-----/.test(text))problems.push([rel,'PRIVATE_KEY_MATERIAL']);
 if(/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|AKIA[A-Z0-9]{16})\b/.test(text))problems.push([rel,'CREDENTIAL_TOKEN']);
 if(/\b[a-z0-9-]+\.(?:up\.railway\.app|proxy\.rlwy\.net)\b/i.test(text))problems.push([rel,'DEPLOYMENT_ENDPOINT_LITERAL']);
}
return {passed:problems.length===0,files:source.length,scanned,problems};
}
if(require.main===module){const r=Run();for(const[file,code]of r.problems)console.error(code+': '+file);if(!r.passed)process.exitCode=1;else console.log('SOURCE BOUNDARIES PASS: '+r.files+' files; '+r.scanned+' textual inputs; grouped Cozy/peace names, no detected production key material or deployment endpoint literal. This is a bounded scan, not a zero-vulnerability proof.');}
module.exports={Run};
