'use strict';
// Scoped, statically interpreted integer VM. Only explicitly migrated IR
// functions are transformed; this is not arbitrary Delphi translation. The
// per-template key is stored in the client data slot and is recoverable by its
// owner. It conceals stored VM/config bytes, not a server secret or all code.
const crypto=require('node:crypto'),fs=require('node:fs');
const ENGINE='COZY_VM_V1',SLOT_BYTES=4096,HEADER_BYTES=128,TAIL_OFFSET=4080,MAX_PROGRAM=TAIL_OFFSET-HEADER_BYTES;
const HEAD=Buffer.from('COZY-VM-SLOT-V1\0','ascii'),TAIL=Buffer.from('COZY-VM-END--V1\0','ascii');
const CONFIG_MAGIC=Buffer.from('COZY-A-CONFIG-V2','ascii'),CONFIG_DOMAIN=Buffer.from('COZY-LAUNCHER-CONFIG-V2\0','ascii');
const MAX_FILE=64*1024*1024,MAX_FUNCTIONS=16,MAX_ARGUMENTS=8,MAX_STACK=32,MAX_STEPS=1024;
const OP={ARG:1,CONST:2,EQ:3,AND:4,OR:5,NOT:6,ADD:7,XOR:8,JZ:9,JMP:10,RETURN:11};
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
const TOOL_SHA512=sha(fs.readFileSync(__filename));
const plain=x=>!!x&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
function Fail(code,status=400){const e=Error('COZY_PROTECTION_'+code);e.desktopError=true;e.status=status;throw e;}
function Exact(x,keys){if(!plain(x)||Object.keys(x).length!==keys.length||keys.some(k=>!Object.hasOwn(x,k)))Fail('PROFILE_INVALID');}
function Int32(x){return Number.isInteger(x)&&x>=-2147483648&&x<=2147483647;}
function Role(role){if(!['A','B','O'].includes(role))Fail('ROLE_INVALID');return {A:1,B:2,O:3}[role];}
function Stable(x){if(Array.isArray(x))return '['+x.map(Stable).join(',')+']';if(plain(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+Stable(x[k])).join(',')+'}';return JSON.stringify(x);}
function ParsePE(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>MAX_FILE||bytes.readUInt16LE(0)!==0x5a4d)Fail('PE_INVALID');
 const pe=bytes.readUInt32LE(60);if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)Fail('PE_INVALID');
 const count=bytes.readUInt16LE(pe+6),optionalSize=bytes.readUInt16LE(pe+20),flags=bytes.readUInt16LE(pe+22),optional=pe+24,table=optional+optionalSize;
 if(count<1||count>96||optionalSize<112||table+count*40>bytes.length||!(flags&2)||(flags&0x2000)||bytes.readUInt16LE(optional)!==0x20b)Fail('PE_INVALID');
 const imageSize=bytes.readUInt32LE(optional+56),headers=bytes.readUInt32LE(optional+60),entry=bytes.readUInt32LE(optional+16),directories=bytes.readUInt32LE(optional+108),sections=[];
 if(headers<table+count*40||headers>bytes.length||!imageSize||!entry||entry>=imageSize||directories>16||112+directories*8>optionalSize)Fail('PE_INVALID');
 let executableEntry=false;
 for(let n=0;n<count;n++){
  const p=table+n*40,rva=bytes.readUInt32LE(p+12),virtualSize=bytes.readUInt32LE(p+8),size=bytes.readUInt32LE(p+16),offset=bytes.readUInt32LE(p+20),attributes=bytes.readUInt32LE(p+36),span=Math.max(size,virtualSize);
  if(!rva||!span||rva+span>imageSize||size&&(offset<headers||offset+size>bytes.length)||sections.some(s=>rva<s.rva+s.span&&rva+span>s.rva||size&&s.size&&offset<s.offset+s.size&&offset+size>s.offset))Fail('PE_INVALID');
  const s={rva,virtualSize,size,offset,span,attributes};sections.push(s);if((attributes&0x20000000)&&entry>=rva&&entry<rva+size)executableEntry=true;
 }
 if(!executableEntry)Fail('PE_INVALID');
 let certificateOffset=0,certificateSize=0;
 if(directories>=5){certificateOffset=bytes.readUInt32LE(optional+144);certificateSize=bytes.readUInt32LE(optional+148);if((certificateOffset===0)!==(certificateSize===0)||certificateOffset&&(certificateOffset%8||certificateSize<8||certificateOffset+certificateSize>bytes.length||certificateOffset<Math.max(...sections.map(s=>s.offset+s.size))))Fail('PE_INVALID');}
 return {sections,signed:!!certificateOffset};
}
function CreateUnsealedSlot(){
 const slot=Buffer.alloc(SLOT_BYTES);HEAD.copy(slot);slot.writeUInt16LE(1,16);slot.writeUInt16LE(HEADER_BYTES,18);slot.writeUInt32LE(SLOT_BYTES,20);slot.writeUInt32LE(1,32);slot.writeUInt32LE(MAX_STEPS,36);slot.writeUInt32LE(1,100);TAIL.copy(slot,TAIL_OFFSET);return slot;
}
function FindSlot(bytes,pe){
 const candidates=new Set();
 const add=offset=>{candidates.add(offset);if(candidates.size>1)Fail('SLOT_DUPLICATE');};
 for(let p=bytes.indexOf(HEAD);p>=0;p=bytes.indexOf(HEAD,p+1))if(p+SLOT_BYTES<=bytes.length&&(bytes.readUInt16LE(p+18)===HEADER_BYTES&&bytes.readUInt32LE(p+20)===SLOT_BYTES||bytes.subarray(p+TAIL_OFFSET,p+SLOT_BYTES).equals(TAIL)))add(p);
 for(let p=bytes.indexOf(TAIL);p>=0;p=bytes.indexOf(TAIL,p+1)){const begin=p-TAIL_OFFSET;if(begin>=0&&(bytes.subarray(begin,begin+16).equals(HEAD)||bytes.readUInt16LE(begin+18)===HEADER_BYTES&&bytes.readUInt32LE(begin+20)===SLOT_BYTES))add(begin);}
 if(!candidates.size)return null;if(candidates.size!==1)Fail('SLOT_DUPLICATE');const offset=[...candidates][0],slot=bytes.subarray(offset,offset+SLOT_BYTES);
 const section=pe.sections.find(s=>offset>=s.offset&&offset+SLOT_BYTES<=s.offset+s.size&&offset-s.offset+SLOT_BYTES<=(s.virtualSize||s.size));
 if(!section||!(section.attributes&0x40)||!(section.attributes&0x40000000)||(section.attributes&0x220000a0))Fail('SLOT_MAPPING_INVALID');
 if(slot.length!==SLOT_BYTES||!slot.subarray(0,16).equals(HEAD)||!slot.subarray(TAIL_OFFSET).equals(TAIL)||slot.readUInt16LE(16)!==1||slot.readUInt16LE(18)!==HEADER_BYTES||slot.readUInt32LE(20)!==SLOT_BYTES||slot.readUInt16LE(26)!==0||slot.readUInt32LE(32)!==1||slot.readUInt32LE(36)<1||slot.readUInt32LE(36)>MAX_STEPS||slot.readUInt32LE(100)!==1||slot.subarray(104,HEADER_BYTES).some(x=>x!==0))Fail('SLOT_INVALID');
 const state=slot[25],length=slot.readUInt32LE(28);if(state===0){if(slot[24]!==0||length!==0||slot.subarray(40,100).some(x=>x!==0)||slot.subarray(HEADER_BYTES,TAIL_OFFSET).some(x=>x!==0))Fail('SLOT_INVALID');}
 else if(state!==1||![1,2,3].includes(slot[24])||length<16||length>MAX_PROGRAM||!slot.subarray(40,72).some(x=>x!==0)||slot.subarray(HEADER_BYTES+length,TAIL_OFFSET).some(x=>x!==0))Fail('SLOT_INVALID');
 return {offset,slot,state,length,section};
}
function EmitExpression(node,args,code,budget,depth=0){
 if(depth>32||++budget.nodes>512||!plain(node)||typeof node.op!=='string')Fail('PROFILE_LIMIT');
 const byte=n=>code.push(n),word=n=>{const b=Buffer.alloc(2);b.writeInt16LE(n);code.push(...b);};
 if(node.op==='const'){Exact(node,['op','value']);if(!Int32(node.value))Fail('PROFILE_INVALID');const b=Buffer.alloc(4);b.writeInt32LE(node.value);byte(OP.CONST);code.push(...b);return;}
 if(node.op==='arg'){Exact(node,['op','index']);if(!Number.isInteger(node.index)||node.index<0||node.index>=args)Fail('PROFILE_INVALID');byte(OP.ARG);byte(node.index);return;}
 if(node.op==='not'){Exact(node,['op','value']);EmitExpression(node.value,args,code,budget,depth+1);byte(OP.NOT);return;}
 const binary={eq:OP.EQ,and:OP.AND,or:OP.OR,add:OP.ADD,xor:OP.XOR};
 if(Object.hasOwn(binary,node.op)){Exact(node,['op','left','right']);EmitExpression(node.left,args,code,budget,depth+1);EmitExpression(node.right,args,code,budget,depth+1);byte(binary[node.op]);return;}
 if(node.op==='if'){
  Exact(node,['op','condition','then','else']);EmitExpression(node.condition,args,code,budget,depth+1);byte(OP.JZ);const first=code.length;word(0);EmitExpression(node.then,args,code,budget,depth+1);byte(OP.JMP);const second=code.length;word(0);const alternate=code.length;EmitExpression(node.else,args,code,budget,depth+1);const end=code.length;
  for(const [at,target]of [[first,alternate],[second,end]]){const relative=target-(at+2);if(relative>32767)Fail('PROFILE_LIMIT');const b=Buffer.alloc(2);b.writeInt16LE(relative);code[at]=b[0];code[at+1]=b[1];}return;
 }
 Fail('PROFILE_INVALID');
}
const arg=index=>({op:'arg',index}),constant=value=>({op:'const',value}),eq=(left,right)=>({op:'eq',left,right});
function Builtin(role){return {id:1,args:3,body:{op:'and',left:{op:'and',left:eq(arg(0),constant(Role(role))),right:eq(arg(1),constant(1))},right:eq(arg(2),constant(1))}};}
function FunctionCode(fn,budget){const code=[];EmitExpression(fn.body,fn.args,code,budget);code.push(OP.RETURN);return Buffer.from(code);}
function NormalizeProfile(profile){
 if(profile===undefined)return {version:1,functions:[]};Exact(profile,['version','functions']);if(profile.version!==1||!Array.isArray(profile.functions)||profile.functions.length>=MAX_FUNCTIONS)Fail('PROFILE_INVALID');
 const functions=profile.functions.map(fn=>{Exact(fn,['id','args','body']);if(!Number.isInteger(fn.id)||fn.id<2||fn.id>65535||!Number.isInteger(fn.args)||fn.args<0||fn.args>MAX_ARGUMENTS)Fail('PROFILE_INVALID');return structuredClone(fn);}).sort((a,b)=>a.id-b.id);
 if(new Set(functions.map(fn=>fn.id)).size!==functions.length)Fail('PROFILE_INVALID');return {version:1,functions};
}
function Compile(profile,role){
 Role(role);const normalized=NormalizeProfile(profile),functions=[Builtin(role),...normalized.functions],budget={nodes:0},codes=functions.map(fn=>FunctionCode(fn,budget));
 const total=8+functions.length*8+codes.reduce((n,b)=>n+b.length,0);if(total>MAX_PROGRAM)Fail('PROFILE_LIMIT');const out=Buffer.alloc(total);out.write('CVM1',0,'ascii');out.writeUInt16LE(functions.length,4);
 let offset=8+functions.length*8;for(let n=0;n<functions.length;n++){const p=8+n*8;out.writeUInt16LE(functions[n].id,p);out[p+2]=functions[n].args;out.writeUInt16LE(offset,p+4);out.writeUInt16LE(codes[n].length,p+6);codes[n].copy(out,offset);offset+=codes[n].length;}
 ValidateProgram(out,role);return out;
}
function ValidateProgram(program,role){
 if(!Buffer.isBuffer(program)||program.length<16||program.length>MAX_PROGRAM||program.toString('ascii',0,4)!=='CVM1'||program.readUInt16LE(6)!==0)Fail('PROGRAM_INVALID');
 const count=program.readUInt16LE(4);if(count<1||count>MAX_FUNCTIONS||8+count*8>program.length)Fail('PROGRAM_INVALID');const functions=new Map();let previous=0,expected=8+count*8;
 for(let n=0;n<count;n++){
  const p=8+n*8,id=program.readUInt16LE(p),args=program[p+2],offset=program.readUInt16LE(p+4),length=program.readUInt16LE(p+6);
  if(id<=previous||args>MAX_ARGUMENTS||program[p+3]!==0||offset!==expected||!length||offset+length>program.length)Fail('PROGRAM_INVALID');previous=id;expected=offset+length;
  const instructions=new Map();let cursor=offset;
  while(cursor<expected){const pc=cursor,op=program[cursor++];let operand=0;if(op===OP.ARG){if(cursor>=expected)Fail('PROGRAM_INVALID');operand=program[cursor++];if(operand>=args)Fail('PROGRAM_INVALID');}else if(op===OP.CONST){if(cursor+4>expected)Fail('PROGRAM_INVALID');operand=program.readInt32LE(cursor);cursor+=4;}else if(op===OP.JZ||op===OP.JMP){if(cursor+2>expected)Fail('PROGRAM_INVALID');operand=program.readInt16LE(cursor);cursor+=2;}else if(![OP.EQ,OP.AND,OP.OR,OP.NOT,OP.ADD,OP.XOR,OP.RETURN].includes(op))Fail('PROGRAM_INVALID');instructions.set(pc,{pc,op,operand,next:cursor});}
  if(cursor!==expected||program[expected-1]!==OP.RETURN)Fail('PROGRAM_INVALID');
  for(const i of instructions.values())if((i.op===OP.JZ||i.op===OP.JMP)&&!instructions.has(i.next+i.operand))Fail('PROGRAM_INVALID');
  const heights=new Map(),queue=[[offset,0]];
  while(queue.length){const [pc,height]=queue.pop();if(heights.has(pc)){if(heights.get(pc)!==height)Fail('PROGRAM_INVALID');continue;}const i=instructions.get(pc);if(!i)Fail('PROGRAM_INVALID');heights.set(pc,height);const pops=[OP.EQ,OP.AND,OP.OR,OP.ADD,OP.XOR].includes(i.op)?2:[OP.NOT,OP.JZ,OP.RETURN].includes(i.op)?1:0,pushes=[OP.ARG,OP.CONST,OP.EQ,OP.AND,OP.OR,OP.NOT,OP.ADD,OP.XOR].includes(i.op)?1:0,after=height-pops+pushes;
   if(height<pops||after>MAX_STACK)Fail('STACK_INVALID');if(i.op===OP.RETURN){if(height!==1)Fail('STACK_INVALID');continue;}if(i.op!==OP.JMP)queue.push([i.next,after]);if(i.op===OP.JZ||i.op===OP.JMP)queue.push([i.next+i.operand,after]);
  }
  if(heights.size!==instructions.size)Fail('PROGRAM_INVALID');functions.set(id,{id,args,offset,length,instructions});
 }
 if(expected!==program.length||functions.get(1)?.args!==3)Fail('PROGRAM_INVALID');
 if(role){const fn=functions.get(1),builtin=FunctionCode(Builtin(role),{nodes:0});if(!program.subarray(fn.offset,fn.offset+fn.length).equals(builtin))Fail('PROGRAM_INVALID');}
 return functions;
}
function Evaluate(program,functionId,args,{maxSteps=MAX_STEPS,role}={}){
 const functions=ValidateProgram(program,role),fn=functions.get(functionId);if(!fn||!Array.isArray(args)||args.length!==fn.args||!args.every(Int32)||!Number.isInteger(maxSteps)||maxSteps<1||maxSteps>MAX_STEPS)Fail('ARGUMENT_INVALID');
 const stack=[];let pc=fn.offset;
 for(let steps=0;steps<maxSteps;steps++){
  const i=fn.instructions.get(pc);if(!i)Fail('PROGRAM_INVALID');pc=i.next;const pop=()=>{if(!stack.length)Fail('STACK_INVALID');return stack.pop();};
  if(i.op===OP.ARG)stack.push(args[i.operand]);else if(i.op===OP.CONST)stack.push(i.operand);else if(i.op===OP.NOT)stack.push(pop()===0?1:0);else if(i.op===OP.JZ){if(pop()===0)pc+=i.operand;}else if(i.op===OP.JMP)pc+=i.operand;else if(i.op===OP.RETURN){const result=pop();if(stack.length)Fail('STACK_INVALID');return result;}else{const b=pop(),a=pop();stack.push(i.op===OP.EQ?(a===b?1:0):i.op===OP.AND?(a!==0&&b!==0?1:0):i.op===OP.OR?(a!==0||b!==0?1:0):i.op===OP.ADD?(a+b)|0:(a^b)|0);}if(stack.length>MAX_STACK)Fail('STACK_INVALID');
 }
 Fail('STEP_LIMIT');
}
function OpenProgram(found){
 const header=Buffer.from(found.slot.subarray(0,HEADER_BYTES)),key=Buffer.from(header.subarray(40,72));let clear,first,last;
 try{header.fill(0,84,100);const decipher=crypto.createDecipheriv('aes-256-gcm',key,found.slot.subarray(72,84));decipher.setAAD(header);decipher.setAuthTag(found.slot.subarray(84,100));first=decipher.update(found.slot.subarray(HEADER_BYTES,HEADER_BYTES+found.length));last=decipher.final();clear=Buffer.concat([first,last]);const role={1:'A',2:'B',3:'O'}[found.slot[24]];ValidateProgram(clear,role);if(Evaluate(clear,1,[found.slot[24],1,1],{maxSteps:found.slot.readUInt32LE(36),role})!==1)Fail('PROGRAM_INVALID');return clear;}catch(e){clear?.fill(0);if(e.desktopError)throw e;Fail('AUTHENTICATION_FAILED');}finally{header.fill(0);key.fill(0);first?.fill(0);last?.fill(0);}
}
function SafeMetadata(found,count){const role=found.state===1?{1:'A',2:'B',3:'O'}[found.slot[24]]:null;return {engine:ENGINE,state:found.state===1?'SEALED':'UNSEALED',version:1,role,slotBytes:SLOT_BYTES,functionCount:count,configProtection:found.state===1&&role==='A'?'COZY_A_CONFIG_V2':'NONE',windowsVerified:false,arbitraryDelphiTranslation:false};}
function ValidateMetadata(m){
 const keys=['engine','state','version','role','slotBytes','functionCount','configProtection','windowsVerified','arbitraryDelphiTranslation'];if(!plain(m)||Object.keys(m).length!==keys.length||keys.some(k=>!Object.hasOwn(m,k))||m.engine!==ENGINE||m.version!==1||m.slotBytes!==SLOT_BYTES||m.windowsVerified!==false||m.arbitraryDelphiTranslation!==false||!['SEALED','UNSEALED'].includes(m.state)||!Number.isInteger(m.functionCount)||m.state==='UNSEALED'&&(m.role!==null||m.functionCount!==0||m.configProtection!=='NONE')||m.state==='SEALED'&&(!['A','B','O'].includes(m.role)||m.functionCount<1||m.functionCount>MAX_FUNCTIONS||m.configProtection!==(m.role==='A'?'COZY_A_CONFIG_V2':'NONE')))Fail('METADATA_INVALID');return m;
}
function Inspect(bytes){if(!Buffer.isBuffer(bytes))Fail('PE_INVALID');if(bytes.indexOf(HEAD)<0&&bytes.indexOf(TAIL)<0)return null;const pe=ParsePE(bytes),found=FindSlot(bytes,pe);if(!found)return null;if(!found.state)return SafeMetadata(found,0);const clear=OpenProgram(found);try{return SafeMetadata(found,clear.readUInt16LE(4));}finally{clear.fill(0);}}
function Pack(bytes,role,profile){
 Role(role);const pe=ParsePE(bytes);if(pe.signed)Fail('SIGNED_INPUT_REQUIRES_NEW_SIGNATURE');const found=FindSlot(bytes,pe);if(!found)Fail('SLOT_MISSING');if(found.state!==0)Fail('ALREADY_SEALED');
 const program=Compile(profile,role),key=crypto.randomBytes(32),nonce=crypto.randomBytes(12),out=Buffer.from(bytes),header=Buffer.from(found.slot.subarray(0,HEADER_BYTES));let encrypted;
 try{header[24]=Role(role);header[25]=1;header.writeUInt32LE(program.length,28);header.writeUInt32LE(MAX_STEPS,36);key.copy(header,40);nonce.copy(header,72);header.fill(0,84,100);const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(header);encrypted=Buffer.concat([cipher.update(program),cipher.final()]);cipher.getAuthTag().copy(header,84);header.copy(out,found.offset);encrypted.copy(out,found.offset+HEADER_BYTES);
  for(const s of pe.sections)if((s.attributes&0x20000020)&&!out.subarray(s.offset,s.offset+s.size).equals(bytes.subarray(s.offset,s.offset+s.size)))Fail('EXECUTABLE_SECTION_CHANGED');
  const ownProtection=Inspect(out);return {bytes:out,sha512:sha(out),inputSha512:sha(bytes),profileSha512:sha(Buffer.from('COZY-VM-PROFILE-V1\n'+role+'\n'+Stable(NormalizeProfile(profile)),'utf8')),toolSha512:TOOL_SHA512,ownProtection};
 }catch(e){out.fill(0);throw e;}finally{program.fill(0);key.fill(0);nonce.fill(0);header.fill(0);encrypted?.fill(0);}
}
function ConfigKey(template){
 const pe=ParsePE(template),found=FindSlot(template,pe);if(!found||found.state!==1||found.slot[24]!==1)Fail('CONFIG_TEMPLATE_REQUIRED');const program=OpenProgram(found);program.fill(0);const key=crypto.createHmac('sha512',found.slot.subarray(40,72)).update(CONFIG_DOMAIN).digest();try{return Buffer.from(key.subarray(0,32));}finally{key.fill(0);}
}
function SealLauncherConfig(template,plaintext,nonce){
 if(!Buffer.isBuffer(plaintext)||plaintext.length<1||plaintext.length>8192||!Buffer.isBuffer(nonce)||nonce.length!==12)Fail('CONFIG_INVALID');const key=ConfigKey(template),header=Buffer.alloc(52);CONFIG_MAGIC.copy(header);header.writeUInt32LE(2,16);header.writeUInt32LE(plaintext.length,20);nonce.copy(header,24);let encrypted;
 try{const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(header.subarray(0,36));encrypted=Buffer.concat([cipher.update(plaintext),cipher.final()]);cipher.getAuthTag().copy(header,36);return Buffer.concat([header,encrypted]);}finally{key.fill(0);header.fill(0);encrypted?.fill(0);}
}
function OpenLauncherConfig(template,envelope){
 if(!Buffer.isBuffer(envelope)||envelope.length<53||envelope.length>52+8192||!envelope.subarray(0,16).equals(CONFIG_MAGIC)||envelope.readUInt32LE(16)!==2||envelope.readUInt32LE(20)!==envelope.length-52)Fail('CONFIG_INVALID');const key=ConfigKey(template);let clear,first,last;
 try{const decipher=crypto.createDecipheriv('aes-256-gcm',key,envelope.subarray(24,36));decipher.setAAD(envelope.subarray(0,36));decipher.setAuthTag(envelope.subarray(36,52));first=decipher.update(envelope.subarray(52));last=decipher.final();clear=Buffer.concat([first,last]);return clear;}catch(_){clear?.fill(0);Fail('CONFIG_AUTHENTICATION_FAILED');}finally{key.fill(0);first?.fill(0);last?.fill(0);}
}
module.exports={ENGINE,SLOT_BYTES,HEADER_BYTES,MAX_PROGRAM,MAX_STEPS,MAX_STACK,OP,TOOL_SHA512,CreateUnsealedSlot,Compile,ValidateProgram,Evaluate,Inspect,ValidateMetadata,Pack,SealLauncherConfig,OpenLauncherConfig};
