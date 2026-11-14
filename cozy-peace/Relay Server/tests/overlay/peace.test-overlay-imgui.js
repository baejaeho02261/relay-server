'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Cross-language/source contracts for the Delphi renderer replacement.
// These checks do not compile Delphi, exercise DXGI, or assert Windows runtime success.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const native = path.resolve(MODULE_RESOURCE_ROOT, '../../Railway');
// Relay-only repositories intentionally omit the private native tree. A tree
// that exists but is incomplete remains an error; do not silently skip files.
if (!fs.existsSync(native)) {
  console.log('SKIP ImGui native-source contracts: private Railway tree absent; Delphi/Windows NOT_RUN.');
  process.exit(0);
}
const read = name => ReadContractFile(path.join(native, name), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
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
  const abi = require(path.join(native, 'Cozy.ImGui/Cozy.Build/Cozy.Check-ImGui-Abi.js'));
  const schema = JSON.parse(ReadContractFile(abi.schemaPath, 'utf8'));
  assert.equal(abi.check(abi.loadSources(), schema).exports, 32);
  abi.verifyProbes(schema);
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
  assert.equal(cExports.size, 32, 'Reviewed product gallery and key-length-only license scene extend the existing ABI');
  assert.deepEqual(cExports.get('game_imgui_scene_v2'), {result:'i32',args:['ptr','i32','i32','u32','f32','f32']});
  assert.deepEqual(cExports.get('game_imgui_scene_v3'), {result:'i32',args:['ptr','i32','i32','u32','f32','f32','i32','f32']});
  assert.deepEqual(cExports.get('game_imgui_license_scene_v1'), {result:'i32',args:['ptr','i32','i32','f32']});
  assert.deepEqual(cExports.get('game_imgui_create_license_korean_v1'), {result:'i32',args:['ptr','ptr','ptr','u32','ptrptr']});
  assert.deepEqual(cExports.get('game_imgui_set_dpi'), { result: 'i32', args: ['ptr', 'f32'] });
  assert.deepEqual(pExports, cExports);
  assert.match(pascal, /TImGuiContext\s*=\s*Pointer\s*;/);
});

check('ABI comparator rejects independent declaration/layout/version mutations and build failure propagates', () => {
  const child = require('node:child_process');
  const env = {...process.env};
  // A surrounding `node --test` exports this private marker. Inheriting it
  // makes a nested test run return success after skipping its entire suite.
  delete env.NODE_TEST_CONTEXT;
  const proof = child.execFileSync(process.execPath, ['--test', '--test-reporter=tap', path.join(native,
    'Cozy.ImGui/Cozy.Tests/Cozy.Abi/Cozy.test_imgui_abi.js')], {encoding:'utf8', timeout:30000, env});
  assert.match(proof,/^# tests 42$/m,'ABI negative cases must actually execute');
  assert.match(proof,/^# pass 42$/m);
  for (const metric of ['fail','cancelled','skipped']) assert.match(proof,new RegExp('^# '+metric+' 0$','m'));
  const build = read('Cozy.ImGui/Cozy.Build/Cozy.Build_ImGui_Win64.bat');
  inOrder(build, [
    'set "GAME_IMGUI_STAGE=validate C/Pascal ABI source contract"',
    'where.exe node.exe', 'if errorlevel 1 (',
    'node "Cozy.Build\\Cozy.Check-ImGui-Abi.js"', 'if errorlevel 1 goto failed',
    'set "GAME_IMGUI_STAGE=compile ABI type and field layout assertions"',
    '"%GAME_IMGUI_COMPILER%" -std=c++11 -fsyntax-only',
    'Cozy.Tests\\Cozy.Abi\\Cozy.test_imgui_abi_layout.cpp', 'if errorlevel 1 goto failed',
    'set "GAME_IMGUI_STAGE=compile C++ bridge"',
    'Cozy.Audit-Object.ps1', 'move /y'
  ], 'Fail-closed ABI preflight');
  assert.doesNotMatch(build,/Cozy\.Check-ImGui-Abi\.js"?\s+--write-probes/,
    'Production preparation checks reviewed generated files; it never rewrites them');
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
  assert.match(pascal, /ImGuiHostABIVersion\s*=\s*3;/);
  assert.match(pascal, /ImGuiHostBytes\s*=\s*32;/);
  const create = pascal.slice(pascal.indexOf('function ImGuiCreate(Window: NativeUInt; LicenseOnly: Boolean): TImGuiContext;', pascal.indexOf('implementation')), pascal.indexOf('procedure ImGuiDestroy(var Context:', pascal.indexOf('implementation')));
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
    ['GI_PROC_D3D11_CREATE', 'd3d11.dll', 'D3D11CreateDevice'],
    ['GI_PROC_D3D_COMPILE', 'd3dcompiler_47.dll', 'D3DCompile'],
    ['GI_PROC_CRT_VSPRINTF', 'ucrtbase.dll', '__stdio_common_vsprintf'],
    ['GI_PROC_CRT_VSSCANF', 'ucrtbase.dll', '__stdio_common_vsscanf'],
    ...['strtod', 'acos', 'atan2', 'ceil', 'cos', 'fabs', 'floor', 'fmod', 'log', 'pow', 'sin', 'sqrt'].map(name => ['GI_PROC_' + name.toUpperCase(), 'ucrtbase.dll', name]),
    ['GI_PROC_THREAD_ID', 'kernel32.dll', 'GetCurrentThreadId'],
    ['GI_PROC_DCOMP_CREATE', 'dcomp.dll', 'DCompositionCreateDevice']
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
  inOrder(paint, ['FRendered := False;', 'not AuthorityValid', 'ImGuiNewFrame(', 'ImGuiEndCanvas(', 'if not AuthorityValid then Exit;', 'ImGuiPresent(', 'IMGUI_PRESENT_FAILED', 'FRendered := (PresentResult = IMGUI_PRESENT_VISIBLE) and', 'ApiIsWindowVisible(FWindow) and not FMinimized and not FSessionPaused;'], 'Frame');
  assert.match(pascal, /IMGUI_PRESENT_FAILED\s*=\s*-1;/);
  assert.match(pascal, /IMGUI_PRESENT_OCCLUDED\s*=\s*0;/);
  assert.match(pascal, /IMGUI_PRESENT_VISIBLE\s*=\s*1;/);
  const run = method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  inOrder(run, ['if not AuthorityValid then Exit;', 'ApiCreateWindowExW(', 'if not AuthorityValid then Exit;', 'ImGuiCreate(', 'if not AuthorityValid then Exit;', 'ApiShowWindow(', 'ApiPeekMessageW(', 'ApiDispatchMessageW(', 'if QuitSeen or FClosing or not AuthorityValid then Break;', 'Paint;', 'if FRendered and not FSessionPaused and not FMinimized and (FWindow<>0)', 'if not AuthorityValid then Break;', 'Tick();', 'if not AuthorityValid then Break;'], 'Dispatch and readiness');
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
  assert.match(nativeTarget,/BeforeTargets="PreBuildEvent;_PasCoreCompile"/);assert.match(nativeTarget,/DependsOnTargets="ValidateProductionIsolation"/);
  inOrder(nativeTarget,['Cozy.Build_ImGui_Win64.bat','GAME_OVERLAY_OBJECT_MISSING','<Delete Files=','brcc32.exe&quot; -fo','Cozy.Assert-OverlayManifest.ps1','-ResourcePath','<Move SourceFiles='],'Native compile/resource gates');
  const publish=project.match(/<Target Name="FinalizeProjectExecutable"[\s\S]*?<\/Target>/)?.[0];
  const finalEvent=project.match(/<PostBuildEvent>([\s\S]*?)<\/PostBuildEvent>/)?.[1];
  assert(finalEvent,'IDE/MSBuild finalization event exists');
  inOrder(finalEvent,['if not exist &quot;$(CompiledArtifact)&quot;','GAME_OVERLAY_COMPILED_OUTPUT_MISSING','exit /b 1','Cozy.Normalize-PE-Unwind.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;','if errorlevel 1 exit /b 1','Cozy.Assert-OverlayManifest.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;'],'Actual EXE missing-output, normalization and manifest gates');
  inOrder(publish,['<Error Condition="!Exists(\'$(CompiledArtifact)\')"','<Message Importance='],'Final build missing-output postcondition');
  assert.doesNotMatch(publish,/<Exec\b/,'Do not normalize the same executable twice');
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
  const event=project.match(/<PostBuildEvent>([\s\S]*?)<\/PostBuildEvent>/)[1];
  assert.doesNotMatch(event,/\$\(OUTPUTPATH\)/,'Command-line builds may leave OUTPUTPATH empty');
  const evaluated=project.slice(0,project.indexOf('<PostBuildEvent>'));
  assert(evaluated.includes('<CompiledArtifact>$(MSBuildProjectDirectory)\\Cozy.Overlay.exe</CompiledArtifact>'),'Image path must exist before event evaluation');
  assert.match(project, /<PostBuildEventIgnoreExitCode>false<\/PostBuildEventIgnoreExitCode>/);
  inOrder(event,['if not exist &quot;$(CompiledArtifact)&quot;','GAME_OVERLAY_COMPILED_OUTPUT_MISSING','exit /b 1',
    'Cozy.Normalize-PE-Unwind.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;','if errorlevel 1 exit /b 1',
    'Cozy.Assert-OverlayManifest.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;'],'Post-link preparation');
  inOrder(target, ['<Error Condition="!Exists(\'$(CompiledArtifact)\')"', '<Message Importance="high"'], 'Post-build existence check');
  assert.equal((project.match(/Cozy.Normalize-PE-Unwind\.ps1/g)||[]).length,1,'Normalize only once');
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
  const server = ReadContractFile(path.join(MODULE_RESOURCE_ROOT, "../services/cryptography/peace.crc-layers.js"), 'utf8');
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

check('Product START queues only after visible Present, exact entitlement and fresh authority', () => {
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['FScenePhase := ReadRunState;', 'FLicensedCard := -1;',
    'if Assigned(FGetLicensedCard) then FLicensedCard := FGetLicensedCard();',
    'if (FLicensedCard < -1) or (FLicensedCard > 17) then FLicensedCard := -1;',
    'ImGuiNewFrame(', 'ImGuiProductScene(FContext, FScenePhase, FSceneSelected, SceneFlags,',
    'FSceneSeconds, FCarouselPosition, FLicensedCard, RunProgress);',
    'SceneActions := SceneActions or Integer(FSceneKeyActions);','FSceneKeyActions := 0;',
    'ImGuiEndCanvas(', 'if not AuthorityValid then Exit;', 'ImGuiPresent(',
    'if FRendered and AuthorityValid then ApplySceneActions(Cardinal(SceneActions));'],'Visible scoped action gate');
  const actions=method('procedure TOverlayWindow.ApplySceneActions(', 'function TOverlayWindow.SceneKey(');
  inOrder(actions,['not AuthorityValid then Exit;', 'FScenePhase := ReadRunState;',
    'if FScenePhase<>0 then Exit;', 'Card := OverlayCategoryCard(FSceneCategory,FSceneSelected);',
    'if not OverlayProductCanStart(FLicensedCard,Card) or',
    'not Assigned(FRequestProductRun) or not Assigned(FProductRunState) then Exit;',
    'if not FRequestProductRun(Card) then Exit;', 'FScenePhase:=1; FRunStarted:=0; FRunDeadline:=0;', 'FRunDuration:=OverlayProductRunMilliseconds(Card);',
    'CancelInteraction; UpdateCursor;', 'Exit;'],'Queue scoped authorization without starting a local timer');
  assert.doesNotMatch(actions,/CreateProcess|ShellExecute|InvokeServerPolicy|\.Post\(/);
  for(const [name,category] of [['CLEANNER',0],['MOBILE',1],['SPOOFER',2]])assert(actions.includes('IMGUI_SCENE_TAB_'+name+')<>0 then FSceneCategory:='+category));
  assert.match(actions,/FSceneSelected:=\(FSceneSelected\+5\) mod 6/);
  assert.match(actions,/FSceneSelected:=\(FSceneSelected\+1\) mod 6/);
  assert.match(paint,/FCarouselPosition := FSceneSelected;/);
  assert.doesNotMatch(paint,/FCarouselPosition\s*:=.*\*Ease/,'Native pointer-follow owns the sole visual interpolation');
  const keyboard=method('function TOverlayWindow.SceneKey(', 'procedure TOverlayWindow.ReleaseOwnCapture;');
  assert.match(keyboard,/if not FSceneRevealComplete or SyncTextInput\s+or \(ReadRunState<>0\) then Exit/);
  assert.match(keyboard,/if Result and not Repeated then/);
  assert.doesNotMatch(keyboard,/VK_RETURN:/,'Enter belongs to the focused ImGui item');
  const cancel=method('procedure TOverlayWindow.CancelInteraction;', 'procedure TOverlayWindow.PointerDown(');
  inOrder(cancel,['FSceneKeyActions := 0;', 'ImGuiClearInput('],'Cancellation clears pending actions');
});

check('Only a fresh server product grant begins bounded product progress and restores controls',()=>{
  const state=method('function TOverlayWindow.ReadRunState:', 'procedure TOverlayWindow.ApplySceneActions(');
  inOrder(state,['if FScenePhase=1 then', 'State := 3;',
    'if Assigned(FProductRunState) then State := FProductRunState();', 'if State=2 then',
    'FScenePhase:=2; FRunStarted:=CozyTick;', 'FRunDeadline:=FRunStarted+FRunDuration+OverlayRunSettleMilliseconds;', 'else if State<>1 then',
    'FScenePhase:=0; FRunStarted:=0; FRunDeadline:=0; FRunDuration:=0; UpdateCursor;',
    'if (FScenePhase=2) and (CozyTick>=FRunDeadline) then', 'FScenePhase:=0; FRunStarted:=0; FRunDeadline:=0; FRunDuration:=0;',
    'CancelInteraction; UpdateCursor;', 'Result:=FScenePhase;'], 'Authorized monotonic progress and denial recovery');
  assert.doesNotMatch(renderer,/SceneCountdownMs|CountdownSeconds/);
  const productState=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.State.pas');
  assert.match(productState,/if \(Card < 0\) or \(Card > 17\) then Exit\(0\);/);
  assert.match(productState,/Result := 2400 \+ \(\(Card \* 7\) mod 18\) \* 110;/);
  assert.match(productState,/OverlayRunSettleMilliseconds = 160;/);
  assert.match(productState,/OverlayRunGrantMarginMilliseconds = 250;/);
  assert.doesNotMatch(renderer,/FToastDeadline|SceneToastMs|SceneLoadingMs/);
  assert.doesNotMatch(state,/Close|Shutdown/);
  const authority=method('function TOverlayWindow.AuthorityValid:', 'function TOverlayWindow.Run(');
  assert.doesNotMatch(authority,/FScenePhase|ReadRunState/,'Presentation progress cannot bypass session authority');
  const handle=method('function TOverlayWindow.Handle(', 'function TOverlayWindow.AuthorityValid:');
  inOrder(handle,['if not FSceneRevealComplete or (ReadRunState<>0) then', 'WM_LBUTTONDOWN,WM_LBUTTONUP,WM_RBUTTONDOWN,WM_RBUTTONUP,',
    'WM_MOUSEMOVE,WM_MOUSEWHEEL,WM_MOUSEHWHEEL,WM_KEYDOWN,WM_KEYUP,WM_CHAR,',
    'WM_IME_STARTCOMPOSITION,WM_IME_COMPOSITION,WM_IME_ENDCOMPOSITION,WM_IME_CHAR: Exit(0);'], 'Input isolation');
  assert.match(handle,/WM_SETCURSOR:[\s\S]*?if FScenePhase in \[1,2\] then ApiSetCursor\(FBusyCursor\)[\s\S]*?else ApiSetCursor\(FNormalCursor\)/);
  assert.match(renderer,/FBusyCursor:=ApiLoadCursorW\(0,PWideChar\(NativeUInt\(32648\)\)\)/);
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['SceneFlags := Cardinal(FSceneCategory) shl 4;', 'if FScenePhase=0 then SceneFlags := SceneFlags or IMGUI_SCENE_RUN_AVAILABLE;'], 'Only idle phase is actionable');
  inOrder(paint,['RunProgress := 0;', 'ProgressTick := CozyTick;',
    'if (FScenePhase=2) and (FRunDuration>0) and (ProgressTick>=FRunStarted) then',
    'RunProgress := (ProgressTick-FRunStarted)/FRunDuration;', 'if RunProgress>1 then RunProgress:=1;'], 'Progress is normalized, bounded and begins after approval');
  const controller=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas');
  const request=controller.slice(controller.indexOf('function TOverlayWorker.RequestProductRun('),controller.indexOf('function TOverlayWorker.ProductRunState:'));
  assert.match(request,/OverlayProductCanStart\(FProductCard, Card\)/);
  assert.doesNotMatch(request,/AuthorizeProductStart|\.Post\(/,'The UI callback only queues bounded work');
  const process=controller.slice(controller.indexOf('procedure TOverlayWorker.ProcessProductRun;'),controller.indexOf('function TOverlayWorker.ShouldClose:'));
  inOrder(process,['MaintainLease(False);', 'FClient.AuthorizeProductStart(FContext.Security, Card,',
    'not OverlayProductCanStart(FProductCard, Card)', '(GrantDeadline <= CozyTick +', 'OverlayProductRunMilliseconds(Card) + OverlayRunGrantMarginMilliseconds)',
    'FProductRunState := 3;', 'FProductGrantDeadline := GrantDeadline;', 'FProductRunState := 2;'],'Worker rejects denied or stale grants');
  const grant=controller.slice(controller.indexOf('function TOverlayWorker.ProductRunState:'),controller.indexOf('procedure TOverlayWorker.ProcessProductRun;'));
  assert.match(grant,/FProductGrantDeadline <= CozyTick \+\s*OverlayProductRunMilliseconds\(FRunProductCard\) \+ OverlayRunGrantMarginMilliseconds/);
  assert.match(grant,/if Result in \[2,3\] then/,'An accepted or rejected grant is consumed once');
  assert.doesNotMatch(controller,/RequestCohortShutdown|FRunRequestedAt/,'START has no cohort-shutdown path');
  const scene=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_scene.h');
  assert.match(scene,/const bool start_allowed=enabled&&licensed_card==cozy_scene_tab_base\(c->scene_tab\)\+selected&&/);
  assert.match(scene,/if\(run&&start_allowed\)actions=8/);
  assert.match(scene,/if\(phase==1\|\|phase==2\)\{[\s\S]*?scene_blur_active=true[\s\S]*?actions=0;/);
  assert.match(scene,/licensed_card< -1\|\|licensed_card>17/);
  assert.match(scene,/run_progress>=0&&run_progress<=1/);
  const legacy=scene.slice(scene.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_scene_v2('));
  assert.match(legacy,/carousel_position,-1,0,true\)/,'Legacy scene has no entitlement and cannot START');
});

check('Responsive scene uses only the empty header for window dragging and stays within work area', () => {
  const hit = method('function TOverlayWindow.ButtonHit(', 'procedure TOverlayWindow.ApplySceneActions(');
  inOrder(hit, ['X < 0', 'X >= Area.Right', 'Scale := Area.Right / SceneWidth;',
    'VerticalScale := Area.Bottom / SceneHeight;', 'if VerticalScale < Scale then Scale := VerticalScale;',
    'OriginX := (Area.Right-SceneWidth*Scale)/2;', 'OriginY := (Area.Bottom-SceneHeight*Scale)/2;',
    'Y >= OriginY+SceneHeaderHeight*Scale', 'X >= OriginX+180*Scale', 'Y >= OriginY+22*Scale'], 'Responsive header versus content hit test');
  assert.match(hit,/X < OriginX\+500\*Scale/);
  assert.match(hit,/Y < OriginY\+66\*Scale/);
  assert.match(renderer, /InitialWidth = 680;/);
  assert.match(renderer, /InitialHeight = 440;/);
  const display = method('procedure TOverlayWindow.FitToWorkArea;', 'procedure TOverlayWindow.ReconcileDisplay;');
  assert.match(display, /if Width > Info.Work.Right - Info.Work.Left then Width := Info.Work.Right - Info.Work.Left;/);
  assert.match(display, /if Height > Info.Work.Bottom - Info.Work.Top then Height := Info.Work.Bottom - Info.Work.Top;/);
  assert.match(display, /ApiSetWindowPos\(FWindow, 0, X, Y, Width, Height,/);
  assert.doesNotMatch(display, /\bSetDpi\(/, 'Work-area fitting must not recursively reapply DPI');
  const handle = method('function TOverlayWindow.Handle(', 'function TOverlayWindow.AuthorityValid:');
  inOrder(handle, ['DpiChangedMessage:', 'SetDpi(LOWORD(WParam), PRect(LParam));',
    'FitToWorkArea; Exit;'], 'Per-monitor DPI transition fits the OS suggestion');
});


check('Initial reveal advances only after showing, then latches full-size input after visible Present',()=>{
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['if not FWindowShown or (FWindow=0) or not ApiIsWindowVisible(FWindow) then',
    'begin FRendered:=False; Exit; end;', 'NowSeconds := CozyFrameSeconds;',
    'ImGuiProductScene(', 'ImGuiPresent(', 'FRendered := (PresentResult = IMGUI_PRESENT_VISIBLE)',
    'if FRendered and (FSceneSeconds>=SceneRevealSeconds) then FSceneRevealComplete:=True;',
    'if FRendered and AuthorityValid then ApplySceneActions'], 'Visible one-shot reveal');
  assert.match(renderer,/SceneRevealSeconds = 0\.45;/);
  assert.doesNotMatch(renderer,/FSceneRevealComplete\s*:=\s*False/i,'Phase changes cannot replay the initial reveal');
  const keys=method('function TOverlayWindow.SceneKey(', 'procedure TOverlayWindow.ReleaseOwnCapture;');
  assert.match(keys,/not FSceneRevealComplete/);
  const actions=method('procedure TOverlayWindow.ApplySceneActions(', 'function TOverlayWindow.SceneKey(');
  assert.match(actions,/not FSceneRevealComplete/);
  const probe=read('Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr');
  for(const name of ['INTRO_FIRST_VISIBLE_FRAME_IS_PARTIAL','INTRO_BLOCKS_HOST_AND_SCENE_INPUT',
    'INTRO_COMPLETES_BEFORE_INTERACTION_CONTRACT','START_DOES_NOT_RESTART_INTRO']) assert(probe.includes(name));
  inOrder(probe,['if not IntroChecked then begin IntroChecked:=True; IntroContract; end;',
    'if not OverlayTestEnvironment.RevealComplete then', 'INTRO_COMPLETION_DEADLINE',
    'if not ContractDone then begin ContractDone := True; Contract; end;'],'Probe waits for real render completion');
});

check('Rounded composition corners use soft clipping and a premultiplied transparent flip chain',()=>{
  const bridge=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp');
  const graphics=read('Cozy.ImGui/Cozy.Bridge/Cozy.Graphics/Cozy.game_imgui_dx11.cpp');
  assert.match(renderer,/OverlayNoRedirectionBitmap = \$00200000;/);
  assert.match(renderer,/ApiCreateWindowExW\(WS_EX_TOPMOST or WS_EX_TOOLWINDOW or OverlayNoRedirectionBitmap/);
  assert.doesNotMatch(renderer,/ApplyWindowShape|CreateRoundRectRgn|SetWindowRgn|Slot_DeleteObject/);
  for(const value of ['DXGI_FORMAT_B8G8R8A8_UNORM','DXGI_SCALING_STRETCH',
    'DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL','DXGI_ALPHA_MODE_PREMULTIPLIED',
    'SetBorderMode(DCOMPOSITION_BORDER_MODE_SOFT)', 'CreateSwapChainForComposition']) assert(bridge.includes(value),value);
  assert.match(bridge,/const float black\[\]=\{0,0,0,0\}/);
  assert.match(bridge,/ImGuiWindowFlags_NoBackground/);
  for(const corner of ['top_left','top_right','bottom_left','bottom_right']) for(const axis of ['x','y'])
    assert(bridge.includes('game_dcomp_clip_'+corner+'_radius_'+axis+'(clip,radius)'));
  assert.match(bridge,/game_dcomp_visual_clip\(c->composition_visual,c->composition_clip\)/);
  assert.doesNotMatch(bridge,/composition_visual->SetClip\(|clip->Set(?:Left|Top|Right|Bottom)/,
    'SDK overload layout must not dispatch DirectComposition clip calls');
  assert.match(bridge,/radius=6\.0f\*scale/);
  assert.match(bridge,/if\(!game_make_render_target\(c\)\|\|!game_composition_clip\(c,width,height\)\)return 0;/);
  inOrder(bridge.slice(bridge.indexOf('if(!ImGui_ImplDX11_Init(')),
    ['ImGui_ImplDX11_CreateDeviceObjects()', 'if(c->license_only)',
     'game_blur_prepare(c->scene_blur', 'if(FAILED(hr))return game_create_failure'],
    'B prepares the full-panel blur before authentication can begin');
  inOrder(bridge.slice(bridge.indexOf('static void game_destroy_context(')),
    ['composition_target->SetRoot(0)', 'composition->Commit()', 'composition_clip->Release()',
     'composition_visual->Release()', 'composition_target->Release()', 'composition->Release()',
     'swap_chain->Release()'], 'Composition ownership cleanup');
  assert.match(graphics,/SrcBlend = D3D11_BLEND_SRC_ALPHA/);
  assert.match(graphics,/DestBlend = D3D11_BLEND_INV_SRC_ALPHA/);
  assert.match(graphics,/SrcBlendAlpha = D3D11_BLEND_ONE/);
  assert.match(graphics,/DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA/);
});

check('Monitor-paced rendering uses QPC deltas without a second fixed timer',()=>{
  const bridge=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp');
  const clock=read('Cozy.Source/Cozy.Platform/Cozy.Clock.pas');
  const dispatch=method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  assert.doesNotMatch(renderer,/WM_TIMER|ApiSetTimer|ApiKillTimer|FrameIntervalMs|ApiGetMessageW/);
  inOrder(dispatch,['MessageCount:=0;', 'while (MessageCount<128) and ApiPeekMessageW(',
    'ApiTranslateMessage(Msg); ApiDispatchMessageW(Msg);', 'Paint;', 'Tick();', 'else if ApiWaitForInput=WAIT_FAILED'], 'Bounded input drain and visible-frame work');
  assert.match(renderer,/MsgWaitForMultipleObjectsEx[\s\S]*?50/);
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['NowSeconds := CozyFrameSeconds;', 'Elapsed := NowSeconds - FLastFrameSeconds;',
    'FSceneSeconds := FSceneSeconds + Delta;'], 'Independent high-resolution scene clock');
  assert.match(clock,/function CozyFrameSeconds: Double;[\s\S]*?ClockSlot_QueryPerformanceCounter/);
  assert.match(bridge,/dxgi->SetMaximumFrameLatency\(1\)/);
  assert.match(bridge,/swap_chain->Present\(1,0\)/);
});

console.log(`${checks} ImGui cross-language/provenance/renderer contracts passed (no Delphi or Windows execution).`);
