'use strict';
// Read-only, fail-closed source ABI check. Does not run the renderer or network.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..');
const paths={header:'Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h',
  pascal:'Cozy.Source/Cozy.Overlay/Cozy.Overlay.ImGui.pas',
  bridge:'Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp'};
const schemaPath=path.join(__dirname,'Cozy.ImGui.Abi.json');
const cleanC=s=>s.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,'');
const cleanPascal=s=>s.replace(/\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g,'');
const ctype=s=>s.trim().replace(/\s+/g,' ').replace(/\s*\*\s*/g,'*');
function only(pattern,text,label){const m=[...text.matchAll(pattern)];assert.equal(m.length,1,label+' cardinality');return m[0];}
function cargs(text){return text.trim()==='void'?[]:text.split(',').map(x=>ctype(x.trim().replace(/\s*\b\w+$/,'')));}
function pargs(text){const args=[];for(const field of (text||'').split(';').filter(x=>x.trim())){
  const m=/^\s*(?:(out|var)\s+)?([\w,\s]+):\s*(\w+)\s*$/.exec(field);assert(m,'Pascal argument grammar');
  for(const name of m[2].split(',')){assert(/^\s*\w+\s*$/.test(name),'Pascal argument name');args.push({mode:m[1]||'value',type:m[3]});}
}return args;}
function unique(rows,label){const map=new Map();for(const row of rows){assert(!map.has(row.name),label+' duplicate '+row.name);map.set(row.name,row);}return map;}
function check(sources,schema){
  assert.equal(schema.schemaVersion,1);assert.equal(schema.target,'classic-delphi-win64');
  assert.equal(schema.callingConvention,'cdecl');assert.equal(schema.pointerBytes,8);
  assert.equal(schema.functions.length,32,'review any ABI surface extension explicitly');
  assert.equal(schema.callbacks.length,3);assert.equal(schema.hostFields.length,5);
  const h=cleanC(sources.header),p=cleanPascal(sources.pascal),b=cleanC(sources.bridge);
  assert.match(h,/#if defined\(_WIN32\)\s+#define GAME_IMGUI_CALL __cdecl\s+#else\s+#define GAME_IMGUI_CALL\s+#endif/);
  assert.match(h,/#ifdef __cplusplus\s+#define GAME_IMGUI_NOEXCEPT noexcept\s+extern "C" \{/);
  assert.match(h,/typedef\s+void\*\s+GameImGuiHandle\s*;/);
  assert.match(p,/\bTImGuiContext\s*=\s*Pointer\s*;/);
  assert.deepEqual([...sources.pascal.matchAll(/\{\$ALIGN\s+(\d+)\}/gi)].map(x=>+x[1]),[schema.hostAlignment]);
  const cf=unique([...h.matchAll(/\b(\w+(?:\s*\*)?)\s+GAME_IMGUI_CALL\s+(game_imgui_\w+)\s*\(([^)]*)\)\s*GAME_IMGUI_NOEXCEPT\s*;/g)].map(m=>({name:m[2],result:ctype(m[1]),args:cargs(m[3])})),'C export');
  const declaredNames=[...h.matchAll(/\b(game_imgui_\w+)\s*\(/g)].map(m=>m[1]);
  assert.equal(declaredNames.length,cf.size,'unrecognized C declaration');
  const pf=unique([...p.matchAll(/\b(function|procedure)\s+(game_imgui_\w+)(?:\(([^)]*)\))?(?:\s*:\s*(\w+))?;\s*cdecl;\s*external\s+name\s+'([^']+)'\s*;/g)].map(m=>{
    assert.equal(m[2],m[5],'Pascal external symbol');return {name:m[2],kind:m[1],result:m[4]||'void',args:pargs(m[3])};
  }),'Pascal external');
  assert.equal([...p.matchAll(/\b(?:function|procedure)\s+game_imgui_\w+/g)].length,pf.size,'unrecognized Pascal declaration');
  assert.deepEqual([...cf.keys()].sort(),schema.functions.map(x=>x.name).sort(),'C surface');
  assert.deepEqual([...pf.keys()].sort(),schema.functions.map(x=>x.name).sort(),'Pascal surface');
  for(const fn of schema.functions){
    assert.deepEqual(cf.get(fn.name),{name:fn.name,result:fn.resultC,args:fn.argsC},'C '+fn.name);
    assert.deepEqual(pf.get(fn.name),{name:fn.name,kind:fn.kindPascal,result:fn.resultPascal,args:fn.argsPascal},'Pascal '+fn.name);
  }
  for(const cb of schema.callbacks){
    const cm=only(new RegExp('typedef\\s+([\\w* ]+?)\\s*\\(GAME_IMGUI_CALL\\s*\\*'+cb.c+'\\)\\s*\\(([^)]*)\\)\\s*;','g'),h,cb.c);
    assert.equal(ctype(cm[1]),cb.resultC);assert.deepEqual(cargs(cm[2]),cb.argsC);
    const pm=only(new RegExp('\\b'+cb.pascal+'\\s*=\\s*(function|procedure)\\(([^)]*)\\)(?:\\s*:\\s*(\\w+))?;\\s*cdecl;','g'),p,cb.pascal);
    assert.equal(pm[1],cb.kindPascal);assert.equal(pm[3]||'void',cb.resultPascal);assert.deepEqual(pargs(pm[2]),cb.argsPascal);
  }
  const ch=only(/typedef\s+struct\s+GameImGuiHost\s*\{([^}]+)\}\s*GameImGuiHost\s*;/g,h,'C host')[1];
  const cfields=ch.split(';').filter(x=>x.trim()).map(x=>{const m=/^\s*(\w+)\s+(\w+)\s*$/.exec(x);assert(m,'C host field grammar');return {name:m[2],type:m[1]};});
  const ph=only(/\bTImGuiHost\s*=\s*record\s+([\s\S]*?)\bend\s*;/g,p,'Pascal host')[1];
  const pfields=[];for(const x of ph.split(';').filter(x=>x.trim())){const m=/^\s*([\w,\s]+):\s*(\w+)\s*$/.exec(x);assert(m,'Pascal host field grammar');for(const n of m[1].split(','))pfields.push({name:n.trim(),type:m[2]});}
  assert.deepEqual(cfields,schema.hostFields.map(f=>({name:f.c,type:f.typeC})));
  assert.deepEqual(pfields,schema.hostFields.map(f=>({name:f.pascal,type:f.typePascal})));
  let offset=0;for(const f of schema.hostFields){const size=f.typeC==='uint32_t'?4:8;assert.equal(f.size,size);offset=Math.ceil(offset/size)*size;assert.equal(f.offset,offset);offset+=size;}
  assert.equal(offset,schema.hostSize);assert.equal(schema.hostAlignment,8);
  for(const field of schema.hostFields){
    // Delphi @Callback returns its stored target. @@ is needed for its slot.
    const address=field.typePascal==='Cardinal'?'@':'@@';
    const guard='((NativeUInt('+address+'Host.'+field.pascal+') - NativeUInt(@Host)) <> '+field.offset+') or';
    assert(p.includes(guard),'Pascal field layout admission '+field.pascal);
  }
  for(const [name,value]of Object.entries({ImGuiHostABIVersion:schema.hostVersion,ImGuiHostBytes:schema.hostSize,ImGuiProcFirst:1,ImGuiProcLast:schema.procIds.GI_PROC_LAST})){
    assert.equal(+only(new RegExp('\\b'+name+'\\s*=\\s*(\\d+)\\s*;','g'),p,name)[1],value);
  }
  const ids=only(/enum\s+GameImGuiProcId\s*\{([^}]+)\}\s*;/g,h,'proc ids')[1];
  const actualIds={};for(const entry of ids.split(',').filter(x=>x.trim())){const m=/^\s*(GI_PROC_\w+)\s*=\s*(\d+)\s*$/.exec(entry);assert(m,'proc ID grammar');assert(!(m[1] in actualIds));actualIds[m[1]]=+m[2];}
  assert.deepEqual(actualIds,schema.procIds);
  for(const [name,value]of [['game_imgui_abi_version',schema.hostVersion],['game_imgui_text_input_version',schema.inputVersion]]){
    const m=only(new RegExp('extern "C" uint32_t GAME_IMGUI_CALL '+name+'\\(void\\) GAME_IMGUI_NOEXCEPT\\s*\\{\\s*return (\\d+);\\s*\\}','g'),b,name+' implementation');assert.equal(+m[1],value);
  }
  assert.match(b,new RegExp('host->abi_version!='+schema.hostVersion+'\\b'));
  assert.match(p,new RegExp('game_imgui_text_input_version <> '+schema.inputVersion+'\\b'));
  return {exports:cf.size,callbacks:schema.callbacks.length,hostFields:cfields.length,hostSize:schema.hostSize,procIds:Object.keys(actualIds).length,nativeWindows:'NOT_RUN'};
}
function loadSources(){return Object.fromEntries(Object.entries(paths).map(([k,v])=>[k,fs.readFileSync(path.join(root,v),'utf8').replace(/^\uFEFF/,'')]));}
function compileProbe(schema,cpp){
  // Diagnostic text lives in the editable C/C++ text header. Keep the same
  // stable identifier rule as Cozy.Extract-NativeStrings.py so regeneration
  // cannot silently put literals back into generated ABI probes.
  const source='Cozy.ImGui/Cozy.Tests/Cozy.Abi/Cozy.test_imgui_abi_layout.'+(cpp?'cpp':'c');
  const textName=message=>{
    const literal=JSON.stringify(message),meaning=(literal.match(/[A-Za-z0-9]+/g)||['TEXT']).join('_').toUpperCase().slice(0,48);
    const digest=require('node:crypto').createHash('sha256').update(source+'\0'+literal).digest('hex').slice(0,8).toUpperCase();
    return 'COZY_TEXT_TEST_IMGUI_ABI_LAYOUT_'+meaning+'_'+digest;
  };
  const lines=['/* Cozy central native text imports. */',
    '#include "../../Cozy.Strings/Cozy.Strings.Tests.h"','#line 1','/* Generated by Cozy.Check-ImGui-Abi.js --write-probes. Compile-only; no renderer execution. */',
    '#include "../../Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h"'];
  // Classic bcc64 uses C++11 with Dinkumware headers whose noexcept
  // specializations can collide in <type_traits>. Keep this compile-only
  // fixture independent of the C++ standard library, without dropping any
  // exact type or no-throw assertions. CozyAbiValue is never evaluated.
  if(cpp)lines.push('template<class A, class B> struct CozyAbiSame { static const bool value = false; };',
    'template<class T> struct CozyAbiSame<T, T> { static const bool value = true; };',
    'template<class T> T CozyAbiValue() noexcept;');
  const sa=(x,m)=>lines.push((cpp?'static_assert':'_Static_assert')+'('+x+', '+textName(m)+');');
  sa('sizeof(void*) == '+schema.pointerBytes,'pointer size');sa('sizeof(GameImGuiHost) == '+schema.hostSize,'host size');
  sa((cpp?'alignof':'_Alignof')+'(GameImGuiHost) == '+schema.hostAlignment,'host alignment');
  for(const f of schema.hostFields){sa('offsetof(GameImGuiHost, '+f.c+') == '+f.offset,'offset '+f.c);sa('sizeof(((GameImGuiHost*)0)->'+f.c+') == '+f.size,'size '+f.c);}
  for(const [name,value] of Object.entries(schema.procIds))sa(name+' == '+value,'proc '+name);
  const typeCheck=(name,ret,args,value)=>{
    const expected='CozyExpected_'+name;lines.push('typedef '+ret+' (GAME_IMGUI_CALL *'+expected+')('+ (args.length?args.join(', '):'void')+');');
    sa(cpp?'(CozyAbiSame<'+value+', '+expected+'>::value)':'_Generic('+value+', '+expected+': 1, default: 0)',name+' type');
  };
  for(const cb of schema.callbacks)typeCheck(cb.c,cb.resultC,cb.argsC,cpp?cb.c:'('+cb.c+')0');
  for(const fn of schema.functions){typeCheck(fn.name,fn.resultC,fn.argsC,cpp?'decltype(&'+fn.name+')':'&'+fn.name);if(cpp)sa('noexcept('+fn.name+'('+fn.argsC.map(t=>'CozyAbiValue<'+t+'>()').join(', ')+'))',fn.name+' noexcept');}
  return lines.join('\n')+'\n';
}
function verifyProbes(schema){for(const [ext,cpp]of [['cpp',true],['c',false]]){const file=path.join(root,'Cozy.ImGui/Cozy.Tests/Cozy.Abi/Cozy.test_imgui_abi_layout.'+ext);assert.equal(fs.readFileSync(file,'utf8'),compileProbe(schema,cpp),'stale generated '+ext+' ABI probe');}}
// Independent offline decoder validates the packed asset and its immutable RGBA hash.
function decodeSceneQoi(data,width,height){
  const fail=()=>{throw new Error('SCENE_QOI_INVALID: invalid or unbounded packed artwork');};
  if(!Number.isInteger(width)||!Number.isInteger(height)||width<1||height<1||width>512||height>768)fail();
  const count=width*height;
  if(data.length<22||data.length>count*5+22||data.toString('ascii',0,4)!=='qoif')fail();
  if(data.readUInt32BE(4)!==width||data.readUInt32BE(8)!==height||data[12]!==4||data[13]!==0)fail();
  const end=data.length-8;
  if(!data.subarray(end).equals(Buffer.from([0,0,0,0,0,0,0,1])))fail();
  const output=Buffer.alloc(count*4),index=Array.from({length:64},()=>[0,0,0,0]);
  let pixel=[0,0,0,255],at=14,written=0;
  while(written<count){
    if(at>=end)fail();
    const chunk=data[at++];let run=1;
    if(chunk===254){if(end-at<3)fail();pixel=[data[at++],data[at++],data[at++],pixel[3]];}
    else if(chunk===255){if(end-at<4)fail();pixel=[data[at++],data[at++],data[at++],data[at++]];}
    else if((chunk&192)===0)pixel=index[chunk&63].slice();
    else if((chunk&192)===64)pixel=[(pixel[0]+((chunk>>4)&3)-2)&255,(pixel[1]+((chunk>>2)&3)-2)&255,(pixel[2]+(chunk&3)-2)&255,pixel[3]];
    else if((chunk&192)===128){
      if(at>=end)fail();const next=data[at++],dg=(chunk&63)-32;
      pixel=[(pixel[0]+dg+(next>>4)-8)&255,(pixel[1]+dg)&255,(pixel[2]+dg+(next&15)-8)&255,pixel[3]];
    }else run=(chunk&63)+1;
    if(run>count-written)fail();
    index[(pixel[0]*3+pixel[1]*5+pixel[2]*7+pixel[3]*11)&63]=pixel.slice();
    for(let n=0;n<run;n++){const offset=written++*4;for(let channel=0;channel<4;channel++)output[offset+channel]=pixel[channel];}
  }
  if(at!==end)fail();return output;
}
function verifySceneAssets(sourceRoot=root){
  const crypto=require('node:crypto');
  const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
  const names=['PUBG','TalesRunner','LostSaga','Apex','Overwatch','CounterStrike','BattlEye','XIGNCODE3','EasyAntiCheat','Vanguard','RICOCHET','ACE','Roblox','BrawlStars','PUBGMobile','GenshinImpact','PokemonGO','ClashRoyale'];
  const location='Cozy.ImGui/Cozy.Bridge/Cozy.Core';
  const header=fs.readFileSync(path.join(sourceRoot,location,'Cozy.game_imgui_scene_assets.h'),'utf8');
  assert.match(header,/GameSceneImageWidth=512,GameSceneImageHeight=768;/);
  assert.match(header,/GameSceneImageCount=18;/);
  assert.match(header,/GameSceneBlurWidth=128,GameSceneBlurHeight=192;/);
  const sourceDigests=new Set(),pixelDigests=new Set(),blurDigests=new Set();
  function pixelsFor(index,name,blur){
    const file='Cozy.game_imgui_scene_'+(blur?'blur':'art')+index+'.h';
    assert(header.includes('#include "'+file+'"'),'all embedded texture headers are included');
    const source=fs.readFileSync(path.join(sourceRoot,location,file),'utf8');
    const rows=new RegExp('GameScene'+(blur?'Blur':'Image')+index+'\\[\\]=\\{([^}]+)\\};').exec(source);
    assert(rows,'embedded '+(blur?'frosted ':'')+'artwork '+name);
    assert.match(source,/static const unsigned char GameScene(?:Image|Blur)[0-9]+\[\]/,'packed byte storage');
    const values=rows[1].match(/0x[a-f0-9]{2}(?![a-f0-9])/g)||[];
    const packed=Buffer.from(values.map(Number));
    const packedDigest=new RegExp((blur?'blur-qoi':'qoi')+'-sha256-'+index+': ([a-f0-9]{64})').exec(header);
    assert(packedDigest&&packedDigest[1]===sha(packed),'packed '+(blur?'frosted ':'')+'QOI bytes changed '+name);
    const payload=decodeSceneQoi(packed,blur?128:512,blur?192:768);
    const digest=new RegExp((blur?'blur8':'rgba8')+'-sha256-'+index+': ([a-f0-9]{64})').exec(header);
    assert(digest&&digest[1]===sha(payload),'embedded '+(blur?'frosted ':'')+'RGBA8 bytes changed '+name);
    for(let at=3;at<payload.length;at+=4)assert.equal(payload[at],255,'artwork is opaque before scene composition');
    return sha(payload);
  }
  for(const [index,name]of names.entries()){
    const source=fs.readFileSync(path.join(sourceRoot,'Cozy.ImGui/Cozy.Assets/Cozy.Cards','Cozy.Card-'+name+'.png'));
    assert(source.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])),'PNG signature '+name);
    const sourceMatch=new RegExp('source-sha256-'+index+': ([a-f0-9]{64})').exec(header);
    assert(sourceMatch&&sourceMatch[1]===sha(source),'source PNG changed: regenerate embedded artwork '+name);
    sourceDigests.add(sha(source));pixelDigests.add(pixelsFor(index,name,false));blurDigests.add(pixelsFor(index,name,true));
  }
  assert.equal(sourceDigests.size,names.length,'eighteen distinct scene artwork sources');
  assert.equal(pixelDigests.size,names.length,'eighteen distinct scene artwork textures');
  assert.equal(blurDigests.size,names.length,'eighteen distinct frosted artwork textures');
  for(const digest of blurDigests)assert(!pixelDigests.has(digest),'frosted images are distinct bounded derivatives');
  return {images:names.length,width:512,height:768,blurImages:names.length,blurWidth:128,blurHeight:192,format:'RGBA8'};
}

if(require.main===module){try{verifySceneAssets();const schema=JSON.parse(fs.readFileSync(schemaPath,'utf8'));const result=check(loadSources(),schema);
  if(process.argv.length===3&&process.argv[2]==='--write-probes'){const dest=path.join(root,'Cozy.ImGui/Cozy.Tests/Cozy.Abi');fs.mkdirSync(dest,{recursive:true});for(const [ext,cpp]of [['cpp',true],['c',false]])fs.writeFileSync(path.join(dest,'Cozy.test_imgui_abi_layout.'+ext),compileProbe(schema,cpp));}
  else assert.equal(process.argv.length,2,'expected no arguments or --write-probes');
  verifyProbes(schema);console.log('IMGUI ABI SOURCE PASS '+JSON.stringify(result));
}catch(error){console.error('IMGUI_ABI_CONTRACT_FAILED: '+error.message);process.exitCode=1;}}
module.exports={check,loadSources,schemaPath,compileProbe,verifyProbes,verifySceneAssets,decodeSceneQoi};
