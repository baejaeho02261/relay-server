'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Cross-language/source contracts for the Delphi renderer replacement.
// These checks do not compile Delphi, exercise DXGI, or assert Windows runtime success.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const native = path.resolve(MODULE_RESOURCE_ROOT, '../../Railway');
const read = name => fs.readFileSync(path.join(native, name), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
const pascal = read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.ImGui.pas");
const renderer = read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas");
const header = read("Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.h");
const cleanC = source => source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '');
const cHeader = cleanC(header);
let checks = 0;
function check(name, fn) { fn(); checks++; console.log('PASS ' + name); }
function inOrder(source, markers, name) {
  let at = 0;
  for (const marker of markers) {
    const next = source.indexOf(marker, at);
    assert(next >= 0, name + ': missing/out-of-order ' + marker);
    at = next + marker.length;
  }
}
function method(name, next) {
  const first = renderer.indexOf(name);
  assert(first >= 0, 'Missing implementation ' + name);
  const last = renderer.indexOf(next, first + name.length);
  assert(last > first, 'Missing next implementation ' + next);
  return renderer.slice(first, last);
}

check('Every C export has an exact cdecl Pascal declaration and matching Win64 primitive ABI', () => {
  const cTypes = {
    void: 'void', int32_t: 'i32', uint32_t: 'u32', float: 'f32',
    'void*': 'ptr', 'const void*': 'ptr', 'const GameImGuiHost*': 'ptr',
    GameImGuiHandle: 'ptr', 'GameImGuiHandle*': 'ptrptr', 'const char*': 'ptr'
  };
  const pTypes = {
    Integer: 'i32', Cardinal: 'u32', Single: 'f32', Pointer: 'ptr',
    PImGuiHost: 'ptr', TImGuiContext: 'ptr', PAnsiChar: 'ptr'
  };
  const cExports = new Map();
  for (const [, result, name, params] of cHeader.matchAll(/\b(void|int32_t|uint32_t)\s+GAME_IMGUI_CALL\s+(game_imgui_\w+)\(([^)]*)\)\s*GAME_IMGUI_NOEXCEPT\s*;/g)) {
    const args = params.trim() === 'void' ? [] : params.split(',').map(param => {
      const type = param.trim().replace(/\s*\b\w+$/, '').trim().replace(/\s*\*\s*/g, '*');
      assert(cTypes[type], 'Unknown C ABI type ' + type);
      return cTypes[type];
    });
    assert(!cExports.has(name), 'Duplicate C export ' + name);
    cExports.set(name, { result: cTypes[result], args });
  }
  const pExports = new Map();
  for (const [, kind, name, params, result, external] of pascal.matchAll(/\b(function|procedure)\s+(game_imgui_\w+)(?:\(([^)]*)\))?(?:\s*:\s*(\w+))?;\s*cdecl;\s*external\s+name\s+'([^']+)'\s*;/g)) {
    assert.equal(name, external, 'C link symbol mismatch');
    const args = [];
    for (const param of (params || '').split(';').filter(x => x.trim())) {
      const match = /^\s*(?:(out|var)\s+)?([\w,\s]+):\s*(\w+)\s*$/.exec(param);
      assert(match, 'Unknown Pascal parameter syntax: ' + param);
      let type = pTypes[match[3]];
      assert(type, 'Unknown Pascal ABI type ' + match[3]);
      if (match[1]) { assert.equal(type, 'ptr'); type = 'ptrptr'; }
      args.push(...match[2].split(',').map(() => type));
    }
    assert(!pExports.has(name), 'Duplicate Pascal export ' + name);
    pExports.set(name, { result: kind === 'procedure' ? 'void' : pTypes[result], args });
  }
  assert.equal(cExports.size, 21, 'Korean font creation, DPI and fixed-size GPU identity are additive C ABI extensions');
  assert.deepEqual(cExports.get('game_imgui_set_dpi'), { result: 'i32', args: ['ptr', 'f32'] });
  assert.deepEqual(pExports, cExports);
  assert.match(pascal, /TImGuiContext\s*=\s*Pointer\s*;/);
});

check('Host callback layout is versioned and checked before static-object creation', () => {
  const host = cHeader.match(/typedef\s+struct\s+GameImGuiHost\s*\{([\s\S]*?)\}\s*GameImGuiHost;/);
  assert(host);
  assert.deepEqual(host[1].trim().split(';').filter(x => x.trim()).map(x => x.trim().replace(/\s+/g, ' ')), [
    'uint32_t abi_version', 'uint32_t struct_size', 'GameImGuiGetProc get_proc',
    'GameImGuiAlloc alloc', 'GameImGuiFree free'
  ]);
  assert.match(cHeader, /typedef\s+void\*\s*\(GAME_IMGUI_CALL\s*\*GameImGuiGetProc\)\(int32_t\s+id\)/);
  assert.match(cHeader, /typedef\s+void\*\s*\(GAME_IMGUI_CALL\s*\*GameImGuiAlloc\)\(size_t\s+bytes\)/);
  assert.match(cHeader, /typedef\s+void\s*\(GAME_IMGUI_CALL\s*\*GameImGuiFree\)\(void\*\s+memory\)/);
  assert.match(pascal, /TImGuiHost\s*=\s*record\s+ABIVersion, StructSize:\s*Cardinal;\s+GetProc:\s*TImGuiGetProc;\s+Alloc:\s*TImGuiAlloc;\s+Free:\s*TImGuiFree;\s+end;/);
  assert.match(pascal, /TImGuiGetProc\s*=\s*function\(ID: Integer\): Pointer; cdecl;/);
  assert.match(pascal, /TImGuiAlloc\s*=\s*function\(Bytes: NativeUInt\): Pointer; cdecl;/);
  assert.match(pascal, /TImGuiFree\s*=\s*procedure\(Memory: Pointer\); cdecl;/);
  assert.match(pascal, /\{\$ALIGN 8\}/);
  assert.match(pascal, /ImGuiHostABIVersion\s*=\s*2;/);
  assert.match(pascal, /ImGuiHostBytes\s*=\s*32;/);
  const create = pascal.slice(pascal.indexOf('function ImGuiCreate(Window: NativeUInt): TImGuiContext;', pascal.indexOf('implementation')), pascal.indexOf('procedure ImGuiDestroy(var Context:', pascal.indexOf('implementation')));
  inOrder(create, ['SizeOf(TImGuiHost) <> ImGuiHostBytes', 'game_imgui_abi_version <> ImGuiHostABIVersion', 'not ApiPointerStorageIsSealed', 'FontBytes := ReadKoreanSystemFont;', 'CreateResult := game_imgui_create_korean_v1(Pointer(Window), @Host,', '@FontBytes[0], Length(FontBytes), Result)', 'FillChar(FontBytes[0], Length(FontBytes), 0)', 'FontBytes := nil;'], 'Host validation');
  assert.equal((pascal.match(/\{\$L\s+'[^']+'\}/g) || []).length, 2);
  const objectLinks = [...pascal.matchAll(/\{\$L\s+'[^']+'\}/g)];
  const firstExternal = pascal.indexOf('function game_imgui_create(');
  const initialization = pascal.indexOf('\ninitialization\n');
  assert(firstExternal >= 0 && initialization > firstExternal);
  for (const link of objectLinks) {
    assert(link.index < firstExternal && link.index < initialization,
      'Native object must be registered before external declarations; moving $L into initialization causes dcc64 E2065');
  }
  const productionLink = pascal.match(/\{\$ELSE\}\s*\{\$L\s+'([^']+)'\}/)?.[1];
  assert.equal(productionLink, '..\\..\\Cozy.BuildOutputs\\Cozy.ImGui\\Cozy.game_imgui_bridge.o',
    'Production object link must work when IDE object-search options are absent');
  assert.match(pascal, /\{\$IFDEF GAME_IMGUI_FAULT_TESTS\}\s*\{\$L 'Cozy.game_imgui_fault_test\.o'\}\s*\{\$ELSE\}\s*\{\$L '[^']+'\}\s*\{\$ENDIF\}/);
  assert.match(read("Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc"), /\{\$IFDEF GAME_IMGUI_FAULT_TESTS\}[\s\S]*?\{\$MESSAGE FATAL/);
  assert.equal(path.win32.basename(productionLink), 'Cozy.game_imgui_bridge.o');
  assert.doesNotMatch(pascal, /external\s+'[^']+\.dll'/i);
});

check('Native callback IDs resolve the intended API names through the existing encoded arena', () => {
  const names = [
    ['GI_PROC_D3D11_CREATE', 'd3d11.dll', 'D3D11CreateDeviceAndSwapChain'],
    ['GI_PROC_D3D_COMPILE', 'd3dcompiler_47.dll', 'D3DCompile'],
    ['GI_PROC_CRT_VSPRINTF', 'ucrtbase.dll', '__stdio_common_vsprintf'],
    ['GI_PROC_CRT_VSSCANF', 'ucrtbase.dll', '__stdio_common_vsscanf'],
    ...['strtod', 'acos', 'atan2', 'ceil', 'cos', 'fabs', 'floor', 'fmod', 'log', 'pow', 'sin', 'sqrt'].map(name => ['GI_PROC_' + name.toUpperCase(), 'ucrtbase.dll', name]),
    ['GI_PROC_THREAD_ID', 'kernel32.dll', 'GetCurrentThreadId']
  ];
  const ror13 = name => [...Buffer.from(name)].reduce((hash, value) => (((hash >>> 13) | (hash << 19)) + value) >>> 0, 0);
  const ids = new Map([...cHeader.matchAll(/\b(GI_PROC_\w+)\s*=\s*(\d+)/g)].map(m => [m[1], Number(m[2])]));
  const hashes = new Map([...read("Cozy.Source/Cozy.Platform/Cozy.Api.ROR13.pas").matchAll(/(HASH_\w+)\s*:\s*Cardinal\s*=\s*\$([0-9A-F]+);/gi)].map(m => [m[1], parseInt(m[2], 16)]));
  const slots = new Map([...pascal.matchAll(/BindApiPointer\(ImGuiApiSlots\[(\d+)\],\s*RequireProcAddressHash64\('([^']+)',\s*(HASH_\w+)\)\);/g)].map(m => [Number(m[1]), { module: m[2], symbol:m[3], hash:hashes.get(m[3]) }]));
  assert.equal(slots.size, names.length);
  for (let index = 0; index < names.length; index++) {
    const [id, module, api] = names[index];
    assert.equal(ids.get(id), index + 1, id);
    assert.deepEqual(slots.get(index + 1), { module, symbol:'HASH_'+api, hash: ror13(api) }, api);
  }
  assert.equal(ids.get('GI_PROC_LAST'), names.length);
  assert.match(pascal, /Result := DecodeApiPointer\(ImGuiApiSlots\[ID\]\)/);
  const rendererSlots=[...renderer.matchAll(/BindApiPointer\(Slot_(\w+),\s*RequireProcAddressHash64\('([^']+)',\s*(HASH_\w+)\)\);/g)];
  assert.ok(rendererSlots.length>=26,'Renderer checks must not pass with zero recognized bindings');
  for (const [, slot, module, symbol] of rendererSlots) {
    assert.equal(symbol,'HASH_'+slot,'Renderer symbol identity');
    assert.equal(hashes.get(symbol), ror13(slot), 'Renderer ' + module + '!' + slot);
  }
  assert.doesNotMatch(pascal+renderer,/RequireProcAddressHash64\('[^']+',\s*\$[0-9A-F]+/i);
});

check('Exact supplied Dear ImGui core, backend reference and MIT license match their SHA-512 provenance', () => {
  const source = JSON.parse(read("Cozy.ImGui/Cozy.Provenance/Cozy.SOURCE_PROVENANCE.txt"));
  assert.equal(source.source, 'User-supplied imgui-master.zip');
  assert.match(source.archiveSha512, /^[a-f0-9]{128}$/);
  const files = new Set(source.files.map(row => row.file));
  assert.equal(files.size, source.files.length, 'Duplicate vendor entries');
  for (const name of ['Cozy.Core/Cozy.imgui.cpp','Cozy.Drawing/Cozy.imgui_draw.cpp','Cozy.Tables/Cozy.imgui_tables.cpp','Cozy.Widgets/Cozy.imgui_widgets.cpp','Cozy.Core/Cozy.imgui.h','Cozy.Core/Cozy.imgui_internal.h','Cozy.Core/Cozy.imconfig.h','Cozy.ThirdParty/Cozy.imstb_rectpack.h','Cozy.ThirdParty/Cozy.imstb_textedit.h','Cozy.ThirdParty/Cozy.imstb_truetype.h','Cozy.Backends/Cozy.imgui_impl_dx11.cpp','Cozy.Backends/Cozy.imgui_impl_dx11.h','Cozy.Legal/Cozy.LICENSE.txt']) assert(files.has(name),name);
  for (const row of source.files) {
    assert(!path.isAbsolute(row.file) && !row.file.split(/[\\/]/).includes('..'), 'Unsafe vendor path');
    const bytes = fs.readFileSync(path.join(native, 'Cozy.ImGui/Cozy.Vendor', row.file));
    assert.equal(crypto.createHash('sha512').update(bytes).digest('hex'), row.sha512, row.file);
  }
  const publicHeader = read("Cozy.ImGui/Cozy.Vendor/Cozy.Core/Cozy.imgui.h");
  assert.equal(publicHeader.match(/^#define IMGUI_VERSION\s+"([^"]+)"/m)[1], source.version);
  assert.equal(Number(publicHeader.match(/^#define IMGUI_VERSION_NUM\s+(\d+)/m)[1]), source.versionNumber);
  assert.match(read("Cozy.ImGui/Cozy.Vendor/Cozy.Legal/Cozy.LICENSE.txt"), /Permission is hereby granted, free of charge/);
  const resource = fs.readFileSync(path.join(native, "Cozy.Projects/Cozy.Overlay/Cozy.OverlayResources.res"));
  const notices = [];
  for (let offset = 0; offset < resource.length;) {
    assert(offset + 32 <= resource.length, 'Complete RES header');
    const size = resource.readUInt32LE(offset), headerSize = resource.readUInt32LE(offset + 4);
    assert(headerSize >= 32 && offset + headerSize + size <= resource.length, 'Complete RES payload');
    if (resource.readUInt16LE(offset + 8) === 0xffff && resource.readUInt16LE(offset + 10) === 10 &&
        resource.readUInt16LE(offset + 12) === 0xffff && resource.readUInt16LE(offset + 14) === 310)
      notices.push(resource.subarray(offset + headerSize, offset + headerSize + size));
    offset = (offset + headerSize + size + 3) & ~3;
  }
  assert.equal(notices.length, 1, 'Single embedded MIT notice');
  assert.deepEqual(notices[0], fs.readFileSync(path.join(native, "Cozy.ImGui/Cozy.Vendor/Cozy.Legal/Cozy.LICENSE.txt")));
  assert.match(read("Cozy.Projects/Cozy.Overlay/Cozy.Overlay.rc"), /310\s+RCDATA\s+"\.\.\\\.\.\\Cozy\.ImGui\\Cozy\.Vendor\\Cozy\.Legal\\Cozy\.LICENSE\.txt"/);

});

check('B readiness remains downstream of a visible Present and a fresh authority check', () => {
  const paint = method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint, ['FRendered := False;', 'not AuthorityValid', 'ImGuiNewFrame(', 'ImGuiEndCanvas(', 'if not AuthorityValid then Exit;', 'ImGuiPresent(', 'IMGUI_PRESENT_FAILED', 'FRendered := PresentResult = IMGUI_PRESENT_VISIBLE;'], 'Frame');
  assert.match(pascal, /IMGUI_PRESENT_FAILED\s*=\s*-1;/);
  assert.match(pascal, /IMGUI_PRESENT_OCCLUDED\s*=\s*0;/);
  assert.match(pascal, /IMGUI_PRESENT_VISIBLE\s*=\s*1;/);
  const run = method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  inOrder(run, ['if not AuthorityValid then Exit;', 'ApiCreateWindowExW(', 'if not AuthorityValid then Exit;', 'ImGuiCreate(', 'if not AuthorityValid then Exit;', 'ApiShowWindow(', 'ApiGetMessageW(', 'if not AuthorityValid then Break;', 'ApiDispatchMessageW(', 'if FRendered and (FWindow <> 0)', '(Msg.message = WM_TIMER)', 'if not AuthorityValid then Break;', 'Tick();', 'if not AuthorityValid then Break;'], 'Dispatch and readiness');
  assert.equal((run.match(/\bTick\(\)/g) || []).length, 1, 'Only gated readiness callback');
  const authority = method('function TOverlayWindow.AuthorityValid:', 'function TOverlayWindow.Run(');
  inOrder(authority, ['not FFailed and Assigned(FShouldClose) and not FShouldClose()', 'FFailed := True;', 'CancelInteraction;', 'SW_HIDE', 'ApiPostQuitMessage(1)'], 'Authority expiry');
});

check('Optional capture privacy uses only owned HWND, authenticated lease and observed API result', () => {
  const apply = method('procedure TOverlayWindow.ApplyCapturePrivacy;', 'procedure TOverlayWindow.Paint;');
  inOrder(apply, ['RequireOwner;', 'FClosing or (FWindow = 0)', 'Assigned(FCapturePrivacy)',
    'At - FPrivacyCheckTick < 1000', 'ApiSetWindowDisplayAffinity(FWindow, Desired)',
    'ApiGetWindowDisplayAffinity(FWindow, Observed)',
    'OverlayCapturePrivacyStatus(Requested, SetOK, ReadOK, Observed)'], 'Own-window affinity');
  const run = method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  inOrder(run, ['AuthorizeBeforeShow();', 'if not AuthorityValid then Exit;', 'ApplyCapturePrivacy;',
    'ApiShowWindow(FWindow, SW_SHOWNORMAL)'], 'Privacy follows authorization');
  assert.match(renderer, /HASH_SetWindowDisplayAffinity/);
  assert.match(renderer, /HASH_GetWindowDisplayAffinity/);
  const close = method('procedure TOverlayWindow.BeginClosing;', 'destructor TOverlayWindow.Destroy;');
  inOrder(close, ['FClosingNotified := True;', 'FClosing := True;', 'try FOnClosing();',
    'except FFailed := True; end;', 'FOnClosing := nil;'], 'Closing failure remains terminal');
  assert.match(renderer, /ButtonBottom - ButtonTop\) \* FScale, False\);/);
  assert.doesNotMatch(renderer, /FActionRequested/);
});

check('Actual GPU identity and initial authority finish while the window is hidden', () => {
  const run = method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  inOrder(run, ['FContext := ImGuiCreate(', 'SetMitigationGpuIdentity(ImGuiGpuIdentity(FContext))',
    'if Assigned(AuthorizeBeforeShow) then AuthorizeBeforeShow();', 'if not AuthorityValid then Exit;', 'ApiShowWindow(FWindow, SW_SHOWNORMAL)'], 'Hidden GPU authorization');
  assert.match(run, /\{\$IFDEF GAME_APPLICATION_BUILD\}\s*if not Assigned\(AuthorizeBeforeShow\) then raise/);
  const bridge = cleanC(read("Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp"));
  const gpu = bridge.slice(bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_gpu_identity('),bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_last_error('));
  inOrder(gpu,['QueryInterface(__uuidof(IDXGIDevice)', 'GetAdapter(', 'GetDesc(', 'CheckInterfaceSupport(__uuidof(IDXGIDevice)', 'game_memcpy(output,&identity,sizeof(identity));return 1;'], 'Actual selected adapter');
  assert.doesNotMatch(gpu,/AdapterLuid|EnumAdapters|EnumDisplayDevices/);
  assert.match(pascal,/GAME-GPU-IDENTITY-V1/);
});

check('Native Present distinguishes occlusion/failure, and portable tests can never grant readiness', () => {
  const bridge = cleanC(read("Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp"));
  const start = bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_render_present(');
  const present = bridge.slice(start, bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_last_error(', start));
  assert(start >= 0);
  inOrder(present, ['game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;', 'ImGui::Render();', 'c->frame_started=false;', '#ifndef GAME_IMGUI_PORTABLE_TEST', 'ImGui_ImplDX11_RenderDrawData(', 'game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;', '->Present(1,0)', 'hr==DXGI_STATUS_OCCLUDED)return 0;', 'if(FAILED(hr))return -1;', 'return hr==S_OK?1:0;', '#else', 'return -1;', '#endif'], 'Bridge Present');
  const build = read("Cozy.ImGui/Cozy.Build/Cozy.Build_ImGui_Win64.bat");
  assert.doesNotMatch(build, /(?:-D|\/D)\s*GAME_IMGUI_PORTABLE_TEST/);
  inOrder(build, ['set "GAME_IMGUI_COMPILER=%BDS%\\bin\\bcc64.exe"', 'if not exist "%GAME_IMGUI_COMPILER%"', '"%GAME_IMGUI_COMPILER%" -c', 'Cozy.Audit-Object.ps1', 'move /y "%COZY_IMGUI_OBJECT_DIR%\\Cozy.game_imgui_bridge.pending.o" "%COZY_IMGUI_OBJECT_DIR%\\Cozy.game_imgui_bridge.o"'], 'Validated compiler and audited static build');
});

check('GPU failure HRESULT survives the C/Pascal boundary and failed frames cannot claim readiness', () => {
  const bridge = cleanC(read("Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp"));
  const backend = cleanC(read("Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp"));
  assert.match(bridge, /if \(game_imgui_dx11_error == 0\) game_imgui_dx11_error = result;/);
  assert.match(bridge, /if\(game_imgui_dx11_failed\)return game_imgui_dx11_error<0\?game_imgui_dx11_error:-3;/);
  assert.match(backend, /FAILED\(game_dx11_result\(bd->pd3dDevice->CreateBuffer/);
  assert.match(backend, /game_dx11_result\(device->Map/);
  assert.match(backend, /game_dx11_result\(bd->pd3dDevice->GetDeviceRemovedReason\(\)\)/);
  assert.match(pascal, /CreateResult := game_imgui_create_korean_v1\(Pointer\(Window\), @Host,\s*@FontBytes\[0\], Length\(FontBytes\), Result\);/);
  assert.match(pascal, /OverlayGraphicsFailure\(CreateResult, 'CREATE'\)/);
  assert.match(renderer, /OverlayGraphicsFailure\(ImGuiLastError\(FContext\), 'FRAME'\)/);
  assert.match(bridge, /ImGui_ImplDX11_NewFrame\(\);\s*if\(game_imgui_runtime_failed\|\|game_imgui_dx11_failed\)return 0;/);
});

check('Project generates one central object before Delphi and propagates all audited build failures', () => {
  const project=read("Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dproj"),build=read("Cozy.ImGui/Cozy.Build/Cozy.Build_ImGui_Win64.bat");
  const objectLink=pascal.match(/\{\$ELSE\}\s*\{\$L\s+'([^']+)'\}/)[1];
  const objectName=path.win32.basename(objectLink);
  // Resolve the actual $L argument without using DCC_ObjPath. The source and
  // project directory bases must both lead to the producer's one audited file.
  const producer=path.resolve(native,'Cozy.ImGui/Cozy.Build','../../Cozy.BuildOutputs/Cozy.ImGui',objectName);
  for(const relative of ['Cozy.Source/Cozy.Overlay','Cozy.Projects/Cozy.Overlay']){
    assert.equal(path.resolve(native,relative,...objectLink.split('\\')),producer);
  }
  for(const root of ['C:\\Source Tree\\Railway','D:\\한글 폴더\\cozy-peace\\Railway','\\\\build-host\\source share\\Railway']){
    const expected=path.win32.join(root,'Cozy.BuildOutputs','Cozy.ImGui',objectName);
    for(const relative of ['Cozy.Source\\Cozy.Overlay','Cozy.Projects\\Cozy.Overlay']){
      assert.equal(path.win32.resolve(root,relative,objectLink),expected);
    }
  }
  const objectDir=project.match(/<DCC_ObjPath>([^;<]+);\$\(DCC_ObjPath\)<\/DCC_ObjPath>/)[1];
  assert.equal(objectDir,'$(CozyNativeRoot)\\Cozy.BuildOutputs\\Cozy.ImGui');
  assert(build.includes('set "COZY_IMGUI_OBJECT_DIR=%~dp0..\\..\\Cozy.BuildOutputs\\Cozy.ImGui"'));
  const nativeTarget=project.match(/<Target Name="PrepareOverlayNative"[\s\S]*?<\/Target>/)?.[0];
  assert(nativeTarget,'Native preparation is an explicit build target');
  assert.match(project,/<BuildDependsOn>PrepareOverlayNative;/);assert.match(project,/<RebuildDependsOn>PrepareOverlayNative;/);
  assert.match(nativeTarget,/BeforeTargets="PreBuildEvent;CoreCompile"/);assert.match(nativeTarget,/DependsOnTargets="ValidateProductionIsolation"/);
  inOrder(nativeTarget,['Cozy.Build_ImGui_Win64.bat','GAME_OVERLAY_OBJECT_MISSING','<Delete Files=','brcc32.exe&quot; -fo','Cozy.Assert-OverlayManifest.ps1','-ResourcePath','<Move SourceFiles='],'Native compile/resource gates');
  const publish=project.match(/<Target Name="FinalizeProjectExecutable"[\s\S]*?<\/Target>/)?.[0];
  inOrder(publish,['Cozy.Normalize-PE-Unwind.ps1','Cozy.Assert-OverlayManifest.ps1','-ImagePath','<Message Importance='],'Actual EXE manifest gates finalization');
  assert.doesNotMatch(publish, /<(?:Move|Delete|RemoveDir)\b/);
  assert.match(project,/<PreBuildEventIgnoreExitCode>false<\/PreBuildEventIgnoreExitCode>/);
  inOrder(build,['DisableDelayedExpansion','if not "%~1"=="" set "BDS=%~1"','pushd "%~dp0.."','if errorlevel 1 goto directory_failed','if not defined BDS','"%GAME_IMGUI_COMPILER%" -c','if errorlevel 1 goto failed','if not exist "%COZY_IMGUI_OBJECT_DIR%\\Cozy.game_imgui_bridge.pending.o" goto failed','Cozy.Audit-Object.ps1','if errorlevel 1 goto failed','move /y','if errorlevel 1 goto failed','if not exist "%COZY_IMGUI_OBJECT_DIR%\\'+objectName+'" goto failed','exit /b 0'],'Object generation gates');
  assert.match(build.slice(build.indexOf(':failed\n')),/exit \/b 1/);
  // The explicit $L path resolves the single audited object directory even
  // without IDE search options. Adjacent source-tree object copies are forbidden.
  assert.doesNotMatch(build,/\bcopy\s+(?:\/b|\/y)/i);
  assert.doesNotMatch(build,/\.\.\\Cozy\.game_imgui_bridge(?:\.pending)?\.o/);
  assert(!fs.existsSync(path.join(native,'Cozy.Source/Cozy.Overlay/Cozy.game_imgui_bridge.o')));
  const failure=build.slice(build.indexOf('\n:failed\n'),build.indexOf('\n:find_rad_studio\n'));
  for(const file of ['%COZY_IMGUI_OBJECT_DIR%\\Cozy.game_imgui_bridge.o','%COZY_IMGUI_OBJECT_DIR%\\Cozy.game_imgui_bridge.pending.o']){
    assert(build.slice(0,build.indexOf('"%GAME_IMGUI_COMPILER%" -c')).includes('del /q "'+file+'"'),'Pre-build cleanup '+file);
    assert(failure.includes('del /q "'+file+'"'),'Failed-build cleanup '+file);
  }
});

check('O prepares its unsigned PE exception table before publishing the release executable', () => {
  const project = read("Cozy.Projects/Cozy.Overlay/Cozy.Overlay.dproj");
  const target = project.match(/<Target Name="FinalizeProjectExecutable"[\s\S]*?<\/Target>/)[0];
  assert.match(project, /<PostBuildEvent>[^<]*Normalize-PE-Unwind\.ps1[^<]*-ImagePath &quot;\$\(OUTPUTPATH\)&quot;<\/PostBuildEvent>/);
  assert.match(project, /<PostBuildEventIgnoreExitCode>false<\/PostBuildEventIgnoreExitCode>/);
  inOrder(target, ['<Error Condition="!Exists(\'$(CompiledArtifact)\')"',
    '<Exec Command=', 'Cozy.Normalize-PE-Unwind.ps1', '-ImagePath &quot;$(CompiledArtifact)&quot;',
    'Cozy.Assert-OverlayManifest.ps1', '<Message Importance="high"'], 'Post-link preparation');
  assert.doesNotMatch(target, /<(?:Move|Delete|RemoveDir)\b/);
  assert.doesNotMatch(target, /(?:IgnoreExitCode|ContinueOnError)="(?:true|WarnAndContinue)"/i);
  const normalizer = read("Cozy.ImGui/Cozy.Build/Cozy.Normalize-PE-Unwind.ps1");
  assert.match(normalizer, /SIGNED_IMAGE_REFUSED/);
  assert.match(normalizer, /DUPLICATE_OR_OVERLAPPING_FUNCTIONS/);
  inOrder(normalizer, ['PeUnwindNormalizer]::Normalize($bytes)',
    'if ($result.Changed)', '$output.Write($result.Bytes',
    '[IO.File]::Replace($temporary, $resolved, [System.Management.Automation.Language.NullString]::Value)',
    '$savedBytes = [IO.File]::ReadAllBytes($resolved)',
    'PeUnwindNormalizer]::Normalize($savedBytes)', 'PE_UNWIND_READBACK_MISMATCH',
    'ordering=PASS', 'PE unwind SHA-512:', 'exit 0', 'catch', 'exit 1'], 'Validate then atomic publish');
  assert.doesNotMatch(normalizer, /\[IO\.File\]::Replace\([^\n]*,\s*\$null\)/);
  const fileTests = read("Cozy.ImGui/Cozy.Tests/Cozy.Unwind/Cozy.Test-PE-Unwind.ps1");
  assert.match(fileTests, /Invoke-NormalizerProcess \$engine \$normalizerPath \$fixturePath/);
  assert.match(fileTests, /File wrapper did not save the expected normalized bytes/);
  // The corrective build step must not turn native/server admission into an
  // accept-unsorted path: malformed images still fail independently.
  assert.match(read("Cozy.Source/Cozy.Integrity/Cozy.CodeIntegrity.pas"), /BeginRVA >= PreviousEnd/);
  const server = fs.readFileSync(path.join(MODULE_RESOURCE_ROOT, "../services/cryptography/peace.crc-layers.js"), 'utf8');
  assert.match(server, /rva<previous/);
  assert(fs.existsSync(path.join(native, "Cozy.ImGui/Cozy.Tests/Cozy.Unwind/Cozy.Test-PE-Unwind.ps1")));
});

check('Intentional capture release preserves ImGui mouse-up; unexpected capture/focus loss cancels it', () => {
  const release = method('procedure TOverlayWindow.ReleaseOwnCapture;', 'procedure TOverlayWindow.CancelInteraction;');
  inOrder(release, ['ApiGetCapture <> FWindow', 'FReleasingCapture := True;', 'try', 'ApiReleaseCapture;', 'finally', 'FReleasingCapture := False;'], 'Release capture');
  const up = method('procedure TOverlayWindow.PointerUp(', 'function TOverlayWindow.Handle(');
  inOrder(up, ['FButtonTracking and (ApiGetCapture = FWindow)', 'ImGuiMousePos(', 'ImGuiMouseButton(FContext, 0, False);', 'FDragging := False;', 'FButtonTracking := False;', 'ReleaseOwnCapture;'], 'Mouse release event');
  assert.doesNotMatch(up, /ImGuiClearInput|CancelInteraction/);
  const cancel = method('procedure TOverlayWindow.CancelInteraction;', 'procedure TOverlayWindow.PointerDown(');
  inOrder(cancel, ['FDragging := False;', 'FButtonTracking := False;', 'ImGuiClearInput(', 'ReleaseOwnCapture;'], 'Cancellation');
  const handle = method('function TOverlayWindow.Handle(', 'function TOverlayWindow.AuthorityValid:');
  assert.match(handle, /WM_CAPTURECHANGED:\s*begin\s*if not FReleasingCapture then CancelInteraction;/);
  assert.match(handle, /WM_CANCELMODE:\s*begin CancelInteraction;/);
  assert.match(handle, /WM_KILLFOCUS:\s*begin\s*CancelInteraction;/);
  assert.match(handle, /WM_ACTIVATE:\s*if LOWORD\(WParam\) = WA_INACTIVE then CancelInteraction;/);
  const down = method('procedure TOverlayWindow.PointerDown(', 'procedure TOverlayWindow.PointerMove(');
  inOrder(down, ['ApiGetCursorPos(FDragAnchor)', 'ApiGetWindowRect(', 'ApiSetCapture(', 'if ApiGetCapture <> FWindow then Exit;', 'FButtonTracking := ButtonHit(X, Y);', 'FDragging := not FButtonTracking;'], 'Pointer selection');
  const move = method('procedure TOverlayWindow.PointerMove(', 'procedure TOverlayWindow.PointerUp(');
  assert.match(move, /FDragOrigin\.X \+ Cursor\.X - FDragAnchor\.X/);
  assert.match(move, /FDragOrigin\.Y \+ Cursor\.Y - FDragAnchor\.Y/);
});

console.log(`${checks} ImGui cross-language/provenance/renderer contracts passed (no Delphi or Windows execution).`);
