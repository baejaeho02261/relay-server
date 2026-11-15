'use strict';
const sourceLayout=require('../source/peace.project-layout');
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "../..");

// Synthetic PE64 DATA for parser tests. Never a native executable/test result.
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
function Isolated(relative,names=[],overrides={}){
 const filename=path.resolve(MODULE_RESOURCE_ROOT,'..',relative),loaded=new Module(filename,module),real=Module.createRequire(filename);
 loaded.filename=filename;loaded.paths=Module._nodeModulePaths(path.dirname(filename));
 loaded.require=sourceLayout.MockRequire(filename,overrides);
 loaded._compile(fs.readFileSync(filename,'utf8')+'\nmodule.exports.__probe={'+names.join(',')+'};\n',filename);return loaded.exports;
}
function DefaultManifest(){
 const catalog=JSON.parse(fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT,'../maintenance/source-manifest.json'),'utf8'));
 if(catalog.scope==='relay-server-only'){
  // The public relay snapshot intentionally contains no private native tree.
  // This independent XML is explicitly synthetic parser input, not a copy of
  // a native manifest or evidence that an Overlay was built/executed.
  return Buffer.from('<?xml version="1.0" encoding="UTF-8"?>\n'+
   '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'+
   '<assemblyIdentity version="1.0.0.0" processorArchitecture="amd64" name="Synthetic.Parser.Fixture" type="win32"/>'+
   '<description>SYNTHETIC TEST DATA ONLY</description>'+
   '<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo>'+
   '<application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>'+
   '<dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>'+
   '<dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>'+
   '</windowsSettings></application>'+
   '<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application></compatibility></assembly>','utf8');
 }
 // Full-source packages retain the strict real-native dependency. Missing or
 // unreadable native inputs must not silently become a synthetic fixture.
 return fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT,"../../Railway/Cozy.Projects/Cozy.Overlay/Cozy.Overlay.manifest"));
}
function PE(role='O',manifest=DefaultManifest(),cfg=false){
 const original=require("../bootstrap/peace.desktop-bootstrap-fixture").PE(role,'GAME-HANDOFF-V3 GAME-MEASUREMENT-PLAN-V1 GAME-TLS-PIN-WINDOW-V1 SYNTHETIC_ONLY'),rsrc=cfg?2048:1536,sectionSize=Math.ceil((96+manifest.length)/512)*512;
 const b=Buffer.alloc(rsrc+sectionSize);original.copy(b);const pe=b.readUInt32LE(60),opt=pe+24,table=opt+240,base=b.readBigUInt64LE(opt+24);
 b.writeUInt16LE(3,pe+6);b.writeUInt32LE(0x3000+Math.ceil(sectionSize/4096)*4096,opt+56);
 b.writeUInt32LE(0x3000,opt+128);b.writeUInt32LE(96+manifest.length,opt+132);
 const p=table+80;b.write('.rsrc',p);b.writeUInt32LE(sectionSize,p+8);b.writeUInt32LE(0x3000,p+12);b.writeUInt32LE(sectionSize,p+16);b.writeUInt32LE(rsrc,p+20);b.writeUInt32LE(0x40000040,p+36);
 b.writeUInt16LE(1,rsrc+14);b.writeUInt32LE(24,rsrc+16);b.writeUInt32LE(0x80000018,rsrc+20);
 b.writeUInt16LE(1,rsrc+38);b.writeUInt32LE(1,rsrc+40);b.writeUInt32LE(0x80000030,rsrc+44);
 b.writeUInt16LE(1,rsrc+62);b.writeUInt32LE(0x409,rsrc+64);b.writeUInt32LE(80,rsrc+68);
 b.writeUInt32LE(0x3060,rsrc+80);b.writeUInt32LE(manifest.length,rsrc+84);manifest.copy(b,rsrc+96);
 if(cfg){b.writeUInt32LE(1024,table+40+8);b.writeUInt32LE(1024,table+40+16);b.writeUInt16LE(b.readUInt16LE(opt+70)|0x4000,opt+70);b.writeUInt32LE(0x2200,opt+192);b.writeUInt32LE(148,opt+196);b.writeUInt32LE(148,1536);b.writeBigUInt64LE(base+0x22e0n,1536+112);b.writeBigUInt64LE(base+0x22f0n,1536+120);b.writeBigUInt64LE(base+0x22c0n,1536+128);b.writeBigUInt64LE(2n,1536+136);b.writeUInt32LE(0x500,1536+144);b.writeUInt32LE(0x1000,1728);b.writeUInt32LE(0x1020,1732);}
 return b;
}
module.exports={Isolated,PE};
