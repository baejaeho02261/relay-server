'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict'),test=require('node:test');
const abi=require('../../Cozy.Build/Cozy.Check-ImGui-Abi.js');
const schema=JSON.parse(fs.readFileSync(abi.schemaPath,'utf8'));
const sources=abi.loadSources();
test('reviewed schema covers all 32 exports, callbacks, host fields and proc identities',()=>{
  assert.deepEqual(abi.check(sources,schema),{exports:32,callbacks:3,hostFields:5,hostSize:32,procIds:19,nativeWindows:'NOT_RUN'});
  abi.verifyProbes(schema);
  // The classic bcc64 C++11 ABI probe must not pull in Dinkumware STL
  // headers. Its local type/noexcept checks are also compiled with
  // -nostdinc++ in the compatibility regression fixture.
  assert.doesNotMatch(abi.compileProbe(schema,true),/#\s*include\s*</);
});
// The source comparator is itself exercised with independent bad inputs. None
// of these mutations is written into the production source or generated files.
const cases=[
 ['C signed argument','header','int32_t width, int32_t height','uint32_t width, int32_t height'],
 ['C float width','header','float scale','double scale'],
 ['C pointer depth','header','GameImGuiHandle* result','GameImGuiHandle result'],
 ['C pointer constness','header','const GameImGuiHost* host','GameImGuiHost* host'],
 ['C return signedness','header','int32_t GAME_IMGUI_CALL game_imgui_destroy','uint32_t GAME_IMGUI_CALL game_imgui_destroy'],
 ['C calling convention','header','#define GAME_IMGUI_CALL __cdecl','#define GAME_IMGUI_CALL __stdcall'],
 ['C no-throw declaration','header','game_imgui_destroy(GameImGuiHandle handle) GAME_IMGUI_NOEXCEPT;','game_imgui_destroy(GameImGuiHandle handle);'],
 ['C missing export','header','uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;',''],
 ['C duplicate export','header','uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;','uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;\nuint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;'],
 ['C unknown extra export','header','uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;','uint32_t GAME_IMGUI_CALL game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT;\nvoid GAME_IMGUI_CALL game_imgui_unreviewed(void) GAME_IMGUI_NOEXCEPT;'],
 ['C callback width','header','*GameImGuiGetProc)(int32_t id)','*GameImGuiGetProc)(int64_t id)'],
 ['C allocation width','header','*GameImGuiAlloc)(size_t bytes)','*GameImGuiAlloc)(uint32_t bytes)'],
 ['C callback result','header','typedef void (GAME_IMGUI_CALL *GameImGuiFree)','typedef int32_t (GAME_IMGUI_CALL *GameImGuiFree)'],
 ['C host field type','header','uint32_t abi_version','int32_t abi_version'],
 ['C host extra field','header','GameImGuiFree free;','GameImGuiFree free; uint32_t trailing;'],
 ['C host reordered fields','header','GameImGuiAlloc alloc;\n    GameImGuiFree free;','GameImGuiFree free;\n    GameImGuiAlloc alloc;'],
 ['C proc identity','header','GI_PROC_THREAD_ID = 17','GI_PROC_THREAD_ID = 18'],
 ['C proc sentinel','header','GI_PROC_LAST = 18','GI_PROC_LAST = 17'],
 ['Pascal calling convention','pascal',"cdecl; external name 'game_imgui_create';","stdcall; external name 'game_imgui_create';"],
 ['Pascal wrong link','pascal',"external name 'game_imgui_create';","external name 'game_imgui_destroy';"],
 ['Pascal result width','pascal','game_imgui_destroy(Context: TImGuiContext): Integer;','game_imgui_destroy(Context: TImGuiContext): Int64;'],
 ['Pascal dropped out','pascal','out Context: TImGuiContext): Integer; cdecl; external','Context: TImGuiContext): Integer; cdecl; external'],
 ['Pascal changed out contract','pascal','out Context: TImGuiContext): Integer; cdecl; external','var Context: TImGuiContext): Integer; cdecl; external'],
 ['Pascal input pointer type','pascal','game_imgui_text(Context: TImGuiContext; Text: PAnsiChar);','game_imgui_text(Context: TImGuiContext; Text: Pointer);'],
 ['Pascal packed record','pascal','TImGuiHost = record','TImGuiHost = packed record'],
 ['Pascal packing directive','pascal','{$ALIGN 8}','{$ALIGN 1}'],
 ['Pascal host field type','pascal','ABIVersion, StructSize: Cardinal;','ABIVersion, StructSize: Integer;'],
 ['Pascal callback width','pascal','TImGuiAlloc = function(Bytes: NativeUInt): Pointer;','TImGuiAlloc = function(Bytes: Cardinal): Pointer;'],
 ['Pascal host version','pascal','ImGuiHostABIVersion = 3;','ImGuiHostABIVersion = 4;'],
 ['Pascal host size','pascal','ImGuiHostBytes = 32;','ImGuiHostBytes = 40;'],
 ['Pascal callback slot uses storage address','pascal','NativeUInt(@@Host.GetProc)','NativeUInt(@Host.GetProc)'],
 ['Pascal callback offset admission','pascal','NativeUInt(@@Host.Alloc) - NativeUInt(@Host)) <> 16','NativeUInt(@@Host.Alloc) - NativeUInt(@Host)) <> 8'],
 ['Pascal input version admission','pascal','game_imgui_text_input_version <> 1','game_imgui_text_input_version <> 2'],
 ['Bridge host version','bridge','game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT {return 3;}','game_imgui_abi_version(void) GAME_IMGUI_NOEXCEPT {return 4;}'],
 ['Bridge input version','bridge','game_imgui_text_input_version(void) GAME_IMGUI_NOEXCEPT {return 1;}','game_imgui_text_input_version(void) GAME_IMGUI_NOEXCEPT {return 2;}'],
 ['Bridge host admission','bridge','host->abi_version!=3','host->abi_version!=4'],
];
for(const [label,key,from,to] of cases)test('reject '+label,()=>{
  assert(sources[key].includes(from),'mutation fixture must target actual source');
  const mutated={...sources,[key]:sources[key].replace(from,to)};
  assert.throws(()=>abi.check(mutated,schema));
});
test('schema layout offset mutation is rejected independently of declarations',()=>{
  const mutated=structuredClone(schema);mutated.hostFields[2].offset=16;
  assert.throws(()=>abi.check(sources,mutated));
});
test('schema signature mutation cannot relabel unchanged sources as compatible',()=>{
  const mutated=structuredClone(schema);mutated.functions[0].argsC[2]='GameImGuiHandle';
  assert.throws(()=>abi.check(sources,mutated));
});
test('source changes that only alter comments preserve declarations',()=>{
  const changed={...sources,header:'/* harmless comment */\n'+sources.header,pascal:'{ harmless comment }\n'+sources.pascal};
  assert.equal(abi.check(changed,schema).exports,32);
});
test('scene artwork originals and embedded bounded pixels agree',()=>{
  assert.deepEqual(abi.verifySceneAssets(),{images:18,width:512,height:768,blurImages:18,blurWidth:128,blurHeight:192,format:'RGBA8'});
});
test('stale artwork and changed embedded pixels fail the offline source gate',()=>{
  const os=require('node:os'),path=require('node:path');
  const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-scene-assets-'));
  const originalRoot=path.resolve(__dirname,'../../..');
  const header='Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene_assets.h';
  const pixels=Array.from({length:18},(_,index)=>'Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene_art'+index+'.h');
  const blurs=Array.from({length:18},(_,index)=>'Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene_blur'+index+'.h');
  const originals=['PUBG','TalesRunner','LostSaga','Apex','Overwatch','CounterStrike','BattlEye','XIGNCODE3','EasyAntiCheat','Vanguard','RICOCHET','ACE','Roblox','BrawlStars','PUBGMobile','GenshinImpact','PokemonGO','ClashRoyale'].map(name=>'Cozy.ImGui/Cozy.Assets/Cozy.Cards/Cozy.Card-'+name+'.png');
  try{
    for(const relative of [header,...pixels,...blurs,...originals]){const target=path.join(temporary,relative);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(originalRoot,relative),target);}
    assert.equal(abi.verifySceneAssets(temporary).images,18);
    const png=path.join(temporary,originals[0]),data=fs.readFileSync(png);const changed=Buffer.from(data);changed[changed.length-1]^=1;fs.writeFileSync(png,changed);
    assert.throws(()=>abi.verifySceneAssets(temporary),/source PNG changed/);
    fs.writeFileSync(png,data);
    const file=path.join(temporary,pixels[0]),text=fs.readFileSync(file,'utf8');
    fs.writeFileSync(file,text.replace(/0x[a-f0-9]{2}/,'0x01'));
    assert.throws(()=>abi.verifySceneAssets(temporary),/packed QOI bytes changed/);
    fs.writeFileSync(file,text);
    const blurFile=path.join(temporary,blurs[0]),blurText=fs.readFileSync(blurFile,'utf8');
    fs.writeFileSync(blurFile,blurText.replace(/0x[a-f0-9]{2}/,'0x01'));
    assert.throws(()=>abi.verifySceneAssets(temporary),/packed frosted QOI bytes changed/);
  }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});
