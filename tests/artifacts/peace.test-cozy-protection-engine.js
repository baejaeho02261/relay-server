'use strict';
// Synthetic PE bytes are data, never executed. These tests establish scoped VM
// compilation/encryption and format bindings, not Windows/Delphi runtime PASS.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const engine=require('../../services/artifacts/peace.cozy-protection-engine');
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
const SLOT=1024,TABLE=128+24+240;
function PE(slots=1){
 const bytes=Buffer.alloc(1024+4096*Math.max(1,slots));bytes.write('MZ');bytes.writeUInt32LE(128,60);bytes.write('PE\0\0',128,'ascii');bytes.writeUInt16LE(0x8664,132);bytes.writeUInt16LE(2,134);bytes.writeUInt16LE(240,148);bytes.writeUInt16LE(0x22,150);const o=152;
 bytes.writeUInt16LE(0x20b,o);bytes.writeUInt32LE(0x1000,o+16);bytes.writeBigUInt64LE(0x140000000n,o+24);bytes.writeUInt32LE(4096,o+32);bytes.writeUInt32LE(512,o+36);bytes.writeUInt32LE(0x2000+4096*Math.max(1,slots),o+56);bytes.writeUInt32LE(512,o+60);bytes.writeUInt16LE(2,o+68);bytes.writeUInt32LE(16,o+108);
 bytes.write('.text',TABLE);bytes.writeUInt32LE(512,TABLE+8);bytes.writeUInt32LE(0x1000,TABLE+12);bytes.writeUInt32LE(512,TABLE+16);bytes.writeUInt32LE(512,TABLE+20);bytes.writeUInt32LE(0x60000020,TABLE+36);bytes.fill(0x90,512,1024);bytes.write('SYNTHETIC PE DATA; NEVER EXECUTED',600,'ascii');
 const d=TABLE+40;bytes.write('.cozy',d);bytes.writeUInt32LE(4096*Math.max(1,slots),d+8);bytes.writeUInt32LE(0x2000,d+12);bytes.writeUInt32LE(4096*Math.max(1,slots),d+16);bytes.writeUInt32LE(SLOT,d+20);bytes.writeUInt32LE(0xc0000040,d+36);
 for(let n=0;n<slots;n++)engine.CreateUnsealedSlot().copy(bytes,SLOT+4096*n);return bytes;
}
const arg=index=>({op:'arg',index}),constant=value=>({op:'const',value}),binary=(op,left,right)=>({op,left,right});
function Reject(fn,code){assert.throws(fn,e=>e.message==='COZY_PROTECTION_'+code,code);}
function SecondProgram(code,args=1){const base=engine.Compile(undefined,'A'),builtin=base.subarray(16),out=Buffer.alloc(24+builtin.length+code.length);out.write('CVM1');out.writeUInt16LE(2,4);out.writeUInt16LE(1,8);out[10]=3;out.writeUInt16LE(24,12);out.writeUInt16LE(builtin.length,14);out.writeUInt16LE(2,16);out[18]=args;out.writeUInt16LE(24+builtin.length,20);out.writeUInt16LE(code.length,22);builtin.copy(out,24);code.copy(out,24+builtin.length);return out;}

test('unsealed static data slots are distinct from legacy files and do not imply protection',()=>{assert.equal(engine.Inspect(PE(0)),null);assert.deepEqual(engine.Inspect(PE()),{engine:'COZY_VM_V1',state:'UNSEALED',version:1,role:null,slotBytes:4096,functionCount:0,configProtection:'NONE',windowsVerified:false,arbitraryDelphiTranslation:false});Reject(()=>engine.Pack(PE(0),'A'),'SLOT_MISSING');});
test('A/B/O are actually transformed in their initialized data slot with executable sections unchanged',()=>{
 for(const role of ['A','B','O']){const input=PE(),saved=Buffer.from(input),out=engine.Pack(input,role);assert.equal(out.bytes.length,input.length);assert.deepEqual(input,saved);assert.deepEqual(out.bytes.subarray(0,SLOT),input.subarray(0,SLOT));assert.deepEqual(out.bytes.subarray(SLOT+4080),input.subarray(SLOT+4080));assert.notEqual(out.sha512,out.inputSha512);assert.equal(out.inputSha512,sha(input));assert.equal(out.sha512,sha(out.bytes));assert.equal(out.toolSha512,sha(fs.readFileSync(require.resolve('../../services/artifacts/peace.cozy-protection-engine'))));assert.equal(out.ownProtection.state,'SEALED');assert.equal(out.ownProtection.role,role);assert.equal(out.ownProtection.functionCount,1);assert.equal(out.ownProtection.configProtection,role==='A'?'COZY_A_CONFIG_V2':'NONE');assert.equal(out.ownProtection.windowsVerified,false);assert.equal(out.bytes.includes(engine.Compile(undefined,role)),false);assert.equal(Object.hasOwn(out.ownProtection,'key'),false);}
});
test('per-template random keys/nonces produce distinct output while profile identity is stable',()=>{const source=PE(),a=engine.Pack(source,'A'),b=engine.Pack(source,'A');assert.notEqual(a.sha512,b.sha512);assert.equal(a.profileSha512,b.profileSha512);assert.notDeepEqual(a.bytes.subarray(SLOT+40,SLOT+84),b.bytes.subarray(SLOT+40,SLOT+84));Reject(()=>engine.Pack(a.bytes,'A'),'ALREADY_SEALED');});
test('the startup VM really evaluates role, version and authorization rather than only a packed marker',()=>{
 for(const [i,role]of ['A','B','O'].entries()){const program=engine.Compile(undefined,role);assert.equal(engine.Evaluate(program,1,[i+1,1,1],{role}),1);assert.equal(engine.Evaluate(program,1,[i+1,1,0],{role}),0);assert.equal(engine.Evaluate(program,1,[i+1,2,1],{role}),0);assert.equal(engine.Evaluate(program,1,[4,1,1],{role}),0);}
 assert.equal(engine.Compile(undefined,'A').toString('hex'),'43564d31010000000100030010001b0001000201000000030101020100000003040102020100000003040b');
});
test('structured expression compilation implements branches, logical operations and wrapping integer arithmetic',()=>{
 const profile={version:1,functions:[{id:2,args:2,body:{op:'if',condition:binary('eq',arg(0),constant(7)),then:binary('add',arg(1),constant(2147483647)),else:binary('xor',arg(1),constant(-1))}},{id:3,args:1,body:binary('or',{op:'not',value:arg(0)},binary('eq',arg(0),constant(2)))}]},program=engine.Compile(profile,'B');
 assert.equal(engine.Evaluate(program,2,[7,1]),-2147483648);assert.equal(engine.Evaluate(program,2,[0,0]),-1);for(const [value,expected]of [[0,1],[2,1],[3,0]])assert.equal(engine.Evaluate(program,3,[value]),expected);
 const packed=engine.Pack(PE(),'B',profile);assert.equal(engine.Inspect(packed.bytes).functionCount,3);
});
test('profiles cannot replace the mandatory gate, execute JS, address missing arguments or exceed bounded structure',()=>{
 for(const fn of [{id:1,args:0,body:constant(1)},{id:2,args:0,body:arg(0)},{id:2,args:0,body:constant(1.2)},{id:2,args:0,body:{op:'eval',source:'process.exit()'}}])Reject(()=>engine.Compile({version:1,functions:[fn]},'A'),'PROFILE_INVALID');
 Reject(()=>engine.Compile({version:1,functions:[{id:2,args:0,body:constant(1)},{id:2,args:0,body:constant(2)}]},'A'),'PROFILE_INVALID');let deep=constant(1);for(let n=0;n<34;n++)deep={op:'not',value:deep};Reject(()=>engine.Compile({version:1,functions:[{id:2,args:0,body:deep}]},'A'),'PROFILE_LIMIT');Reject(()=>engine.Compile(undefined,'X'),'ROLE_INVALID');
});
test('instruction decoding rejects truncated operands, non-boundary jumps, bad stack effects and invalid table ranges',()=>{
 const badStack=SecondProgram(Buffer.from([engine.OP.ADD,engine.OP.RETURN]),0);Reject(()=>engine.ValidateProgram(badStack),'STACK_INVALID');
 const jump=SecondProgram(Buffer.from([1,0,9,1,0,2,7,0,0,0,11]));Reject(()=>engine.ValidateProgram(jump),'PROGRAM_INVALID');
 const badTable=engine.Compile(undefined,'A');badTable.writeUInt16LE(17,12);Reject(()=>engine.ValidateProgram(badTable),'PROGRAM_INVALID');
 const operand=SecondProgram(Buffer.from([engine.OP.CONST,1,engine.OP.RETURN]),0);Reject(()=>engine.ValidateProgram(operand),'PROGRAM_INVALID');
});
test('function-local loops cannot escape the explicit instruction budget',()=>{const loop=SecondProgram(Buffer.from([1,0,9,3,0,10,0xf8,0xff,2,7,0,0,0,11]));assert.equal(engine.Evaluate(loop,2,[0]),7);Reject(()=>engine.Evaluate(loop,2,[1],{maxSteps:10}),'STEP_LIMIT');});
test('slots must be unique, initialized, file-backed, non-executable and fully mapped',()=>{
 Reject(()=>engine.Pack(PE(2),'A'),'SLOT_DUPLICATE');for(const flags of [0xe0000060,0xc0000080,0x00000040,0x42000040]){const b=PE();b.writeUInt32LE(flags,TABLE+40+36);Reject(()=>engine.Pack(b,'A'),'SLOT_MAPPING_INVALID');}
 const virtual=PE();virtual.writeUInt32LE(4095,TABLE+40+8);Reject(()=>engine.Pack(virtual,'A'),'SLOT_MAPPING_INVALID');const overlap=PE();overlap.writeUInt32LE(512,TABLE+40+20);Reject(()=>engine.Pack(overlap,'A'),'PE_INVALID');
});
test('existing Authenticode certificate tables require packing an unsigned input and fresh later signing',()=>{const base=PE(),signed=Buffer.concat([base,Buffer.alloc(8)]);signed.writeUInt32LE(base.length,152+144);signed.writeUInt32LE(8,152+148);Reject(()=>engine.Pack(signed,'A'),'SIGNED_INPUT_REQUIRES_NEW_SIGNATURE');});
test('malformed slots, altered header/nonce/tag/cipher and nonzero reserved padding are rejected',()=>{
 for(const at of [SLOT,SLOT+104,SLOT+4080]){const b=PE();b[at]^=1;assert.throws(()=>engine.Pack(b,'A'),/^Error: COZY_PROTECTION_SLOT_INVALID$/);}
 const sealed=engine.Pack(PE(),'A').bytes;for(const at of [SLOT+24,SLOT+40,SLOT+72,SLOT+84,SLOT+128]){const b=Buffer.from(sealed);b[at]^=1;assert.throws(()=>engine.Inspect(b),/COZY_PROTECTION_(?:SLOT_INVALID|AUTHENTICATION_FAILED)/);}
 const padding=Buffer.from(sealed);padding[SLOT+1000]=1;Reject(()=>engine.Inspect(padding),'SLOT_INVALID');
});
test('safe metadata is strictly bounded and never accepts a claimed Windows verification',()=>{const metadata=engine.Pack(PE(),'A').ownProtection;assert.equal(engine.ValidateMetadata(metadata),metadata);for(const patch of [{windowsVerified:true},{functionCount:17},{key:'do not expose'},{configProtection:'NONE'},{arbitraryDelphiTranslation:true}])Reject(()=>engine.ValidateMetadata({...metadata,...patch}),'METADATA_INVALID');});
test('a correctly authenticated all-zero client key is rejected consistently with the native runtime',()=>{const bytes=engine.Pack(PE(),'A').bytes,program=engine.Compile(undefined,'A'),header=Buffer.from(bytes.subarray(SLOT,SLOT+128));header.fill(0,40,72);header.fill(0,84,100);const cipher=crypto.createCipheriv('aes-256-gcm',Buffer.alloc(32),header.subarray(72,84));cipher.setAAD(header);const ciphertext=Buffer.concat([cipher.update(program),cipher.final()]);cipher.getAuthTag().copy(header,84);header.copy(bytes,SLOT);ciphertext.copy(bytes,SLOT+128);Reject(()=>engine.Inspect(bytes),'SLOT_INVALID');});
test('packing establishes a sufficient native startup instruction budget',()=>{const input=PE();input.writeUInt32LE(1,SLOT+36);const output=engine.Pack(input,'A');assert.equal(output.bytes.readUInt32LE(SLOT+36),1024);assert.equal(engine.Inspect(output.bytes).state,'SEALED');});
test('authenticated slots with a budget too small for their startup gate are not publishable',()=>{const bytes=engine.Pack(PE(),'A').bytes,program=engine.Compile(undefined,'A'),header=Buffer.from(bytes.subarray(SLOT,SLOT+128));header.writeUInt32LE(1,36);header.fill(0,84,100);const cipher=crypto.createCipheriv('aes-256-gcm',header.subarray(40,72),header.subarray(72,84));cipher.setAAD(header);const ciphertext=Buffer.concat([cipher.update(program),cipher.final()]);cipher.getAuthTag().copy(header,84);header.copy(bytes,SLOT);ciphertext.copy(bytes,SLOT+128);Reject(()=>engine.Inspect(bytes),'STEP_LIMIT');});
test('A issuance config is authenticated ciphertext with a per-template derived client key',()=>{
 const a=engine.Pack(PE(),'A').bytes,other=engine.Pack(PE(),'A').bytes,plain=Buffer.from('synthetic binary profile and one-time issuance bytes'),nonce=Buffer.alloc(12,7),box=engine.SealLauncherConfig(a,plain,nonce);assert.equal(box.length,52+plain.length);assert.equal(box.includes(plain),false);assert.deepEqual(engine.OpenLauncherConfig(a,box),plain);assert.deepEqual(engine.SealLauncherConfig(a,plain,nonce),box);assert.notDeepEqual(engine.SealLauncherConfig(a,plain,Buffer.alloc(12,8)),box);Reject(()=>engine.OpenLauncherConfig(other,box),'CONFIG_AUTHENTICATION_FAILED');
 for(const role of ['B','O'])Reject(()=>engine.SealLauncherConfig(engine.Pack(PE(),role).bytes,plain,nonce),'CONFIG_TEMPLATE_REQUIRED');Reject(()=>engine.SealLauncherConfig(PE(),plain,nonce),'CONFIG_TEMPLATE_REQUIRED');
});
test('A configuration tampering, wrong bounds, truncated/trailing frames and nonce lengths fail closed',()=>{
 const a=engine.Pack(PE(),'A').bytes,plain=Buffer.from([1,2,3]),nonce=Buffer.alloc(12,9),box=engine.SealLauncherConfig(a,plain,nonce);
 for(const at of [0,16,20]){const b=Buffer.from(box);b[at]^=1;Reject(()=>engine.OpenLauncherConfig(a,b),'CONFIG_INVALID');}for(const at of [24,36,52]){const b=Buffer.from(box);b[at]^=1;Reject(()=>engine.OpenLauncherConfig(a,b),'CONFIG_AUTHENTICATION_FAILED');}
 for(const b of [box.subarray(0,-1),Buffer.concat([box,Buffer.alloc(1)])])Reject(()=>engine.OpenLauncherConfig(a,b),'CONFIG_INVALID');for(const b of [Buffer.alloc(0),Buffer.alloc(8193)])Reject(()=>engine.SealLauncherConfig(a,b,nonce),'CONFIG_INVALID');Reject(()=>engine.SealLauncherConfig(a,plain,Buffer.alloc(11)),'CONFIG_INVALID');
});
test('read-only CLI inspects archives and rejects retired local packing without output',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-vm-cli-')),source=path.join(dir,'input.exe'),target=path.join(dir,'output.exe'),tool=require.resolve('../../tools/protection/peace.cozy-protect');fs.writeFileSync(source,PE(),{mode:0o600});
 try{const before=fs.readFileSync(source),result=child.spawnSync(process.execPath,[tool,'pack','A',source,target],{encoding:'utf8'});assert.notEqual(result.status,0);assert.match(result.stderr,/LEGACY_PACKING_RETIRED_USE_SERVER_POLICY/);assert.equal(fs.existsSync(target),false);assert.deepEqual(fs.readFileSync(source),before);const inspected=JSON.parse(child.execFileSync(process.execPath,[tool,'inspect',source],{encoding:'utf8'}));assert.equal(inspected.ok,true);assert.equal(inspected.ownProtection.state,'UNSEALED');assert.equal(inspected.windowsVerified,false);}finally{fs.rmSync(dir,{recursive:true,force:true});}
});

module.exports={PE};
