'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/spacex.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Cross-language/source contracts for the Delphi renderer replacement.
// These checks do not compile Delphi, exercise DXGI, or assert Windows runtime success.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const native = path.resolve(MODULE_RESOURCE_ROOT, '../../Desktop');
// Relay-only repositories intentionally omit the private native tree. A tree
// that exists but is incomplete remains an error; do not silently skip files.
if (!fs.existsSync(native)) {
  console.log('SKIP ImGui native-source contracts: private Railway tree absent; Delphi/Windows NOT_RUN.');
  process.exit(0);
}
const read = name => ReadContractFile(path.join(native, name), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
const pascal = read("SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.ImGui.pas");
const renderer = read("SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.Renderer.pas");
const header = read("SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.h");
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
  const abi = require(path.join(native, 'SpaceX.ImGui/SpaceX.Build/SpaceX.Check-ImGui-Abi.js'));
  const schema = JSON.parse(ReadContractFile(abi.schemaPath, 'utf8'));
  assert.equal(abi.check(abi.loadSources(), schema).exports, 35);
  abi.verifyProbes(schema);
  const cTypes = {
    void: 'void', int32_t: 'i32', uint32_t: 'u32', float: 'f32',
    'void*': 'ptr', 'const void*': 'ptr', 'const GameImGuiHost*': 'ptr',
    GameImGuiHandle: 'ptr', 'GameImGuiHandle*': 'ptrptr', 'const char*': 'ptr', 'const uint16_t*': 'ptr'
  };
  const pTypes = {
    Integer: 'i32', Cardinal: 'u32', Single: 'f32', Pointer: 'ptr',
    PImGuiHost: 'ptr', TImGuiContext: 'ptr', PAnsiChar: 'ptr', PWideChar: 'ptr'
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
  assert.equal(cExports.size, 35, 'The single desktop settings entry extends the existing scene ABI');
  assert.deepEqual(cExports.get('game_imgui_scene_v2'), {result:'i32',args:['ptr','i32','i32','u32','f32','f32']});
  assert.deepEqual(cExports.get('game_imgui_scene_v3'), {result:'i32',args:['ptr','i32','i32','u32','f32','f32','i32','f32']});
  assert.deepEqual(cExports.get('game_imgui_license_hit_v1'), {result:'i32',args:['ptr','i32','i32']});
  assert.deepEqual(cExports.get('game_imgui_license_scene_v1'), {result:'i32',args:['ptr','i32','i32','f32']});
  assert.deepEqual(cExports.get('game_imgui_license_scene_reveal_v1'), {result:'i32',args:['ptr','i32','i32','f32','ptr','i32']});
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
    'SpaceX.ImGui/SpaceX.Tests/SpaceX.Abi/SpaceX.test_imgui_abi.js')], {encoding:'utf8', timeout:30000, env});
  assert.match(proof,/^# tests 42$/m,'ABI negative cases must actually execute');
  assert.match(proof,/^# pass 42$/m);
  for (const metric of ['fail','cancelled','skipped']) assert.match(proof,new RegExp('^# '+metric+' 0$','m'));
  const build = read('SpaceX.ImGui/SpaceX.Build/SpaceX.Build_ImGui_Win64.bat');
  inOrder(build, [
    'set "GAME_IMGUI_STAGE=validate C/Pascal ABI source contract"',
    'where.exe node.exe', 'if errorlevel 1 (',
    'node "SpaceX.Build\\SpaceX.Check-ImGui-Abi.js"', 'if errorlevel 1 goto failed',
    'set "GAME_IMGUI_STAGE=compile ABI type and field layout assertions"',
    '"%GAME_IMGUI_COMPILER%" -std=c++11 -fsyntax-only',
    'SpaceX.Tests\\SpaceX.Abi\\SpaceX.test_imgui_abi_layout.cpp', 'if errorlevel 1 goto failed',
    'set "GAME_IMGUI_STAGE=compile C++ bridge"',
    'SpaceX.Audit-Object.ps1', 'move /y'
  ], 'Fail-closed ABI preflight');
  assert.doesNotMatch(build,/SpaceX\.Check-ImGui-Abi\.js"?\s+--write-probes/,
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
  inOrder(create, ['SizeOf(TImGuiHost) <> ImGuiHostBytes', 'game_imgui_abi_version <> ImGuiHostABIVersion', 'not ApiPointerStorageIsSealed', 'FontBytes := ReadSystemUiFont(LicenseOnly);', 'CreateResult := game_imgui_create_license_korean_v1(Pointer(Window), @Host,', '@FontBytes[0], Length(FontBytes), Result)', 'CreateResult := game_imgui_create_korean_v1(Pointer(Window), @Host,', '@FontBytes[0], Length(FontBytes), Result)', 'FillChar(FontBytes[0], Length(FontBytes), 0)', 'FontBytes := nil;'], 'Host validation');
  const fontReader = pascal.slice(pascal.indexOf('function ReadSystemUiFont('), pascal.indexOf('function ImGuiCreate(', pascal.indexOf('function ReadSystemUiFont(')));
  inOrder(fontReader, ['Target(@Buffer[0], Length(Buffer))', 'IncludeTrailingPathDelimiter(ExtractFileDir(Directory))', 'if LicenseOnly then', 'Fonts\\consola.ttf', 'else', 'Fonts\\malgun.ttf', 'TFileStream.Create(Directory', '16 * 1024 * 1024', 'Stream.ReadBuffer'], 'System-owned, bounded B and O fonts');
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
  assert.equal(productionLink, '..\\..\\SpaceX.ImGui\\SpaceX.Objects\\SpaceX.game_imgui_bridge.o',
    'Production object link must work when IDE object-search options are absent');
  assert.match(pascal, /\{\$IFDEF GAME_IMGUI_FAULT_TESTS\}\s*\{\$L 'SpaceX.game_imgui_fault_test\.o'\}\s*\{\$ELSE\}\s*\{\$L '[^']+'\}\s*\{\$ENDIF\}/);
  assert.match(read("SpaceX.Source/SpaceX.Configuration/SpaceX.Metadata.inc"), /\{\$IFDEF GAME_IMGUI_FAULT_TESTS\}[\s\S]*?\{\$MESSAGE FATAL/);
  assert.equal(path.win32.basename(productionLink), 'SpaceX.game_imgui_bridge.o');
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
  const hashes = new Map([...read("SpaceX.Source/SpaceX.Platform/SpaceX.Api.ROR13.pas").matchAll(/(HASH_\w+)\s*:\s*Cardinal\s*=\s*\$([0-9A-F]+);/gi)].map(m => [m[1], parseInt(m[2], 16)]));
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
  const source = JSON.parse(read("SpaceX.ImGui/SpaceX.Provenance/SpaceX.SOURCE_PROVENANCE.txt"));
  assert.equal(source.source, 'User-supplied imgui-master.zip');
  assert.match(source.archiveSha512, /^[a-f0-9]{128}$/);
  const files = new Set(source.files.map(row => row.file));
  assert.equal(files.size, source.files.length, 'Duplicate vendor entries');
  for (const name of ['SpaceX.Core/SpaceX.imgui.cpp','SpaceX.Drawing/SpaceX.imgui_draw.cpp','SpaceX.Tables/SpaceX.imgui_tables.cpp','SpaceX.Widgets/SpaceX.imgui_widgets.cpp','SpaceX.Core/SpaceX.imgui.h','SpaceX.Core/SpaceX.imgui_internal.h','SpaceX.Core/SpaceX.imconfig.h','SpaceX.ThirdParty/SpaceX.imstb_rectpack.h','SpaceX.ThirdParty/SpaceX.imstb_textedit.h','SpaceX.ThirdParty/SpaceX.imstb_truetype.h','SpaceX.Backends/SpaceX.imgui_impl_dx11.cpp','SpaceX.Backends/SpaceX.imgui_impl_dx11.h','SpaceX.Legal/SpaceX.LICENSE.txt']) assert(files.has(name),name);
  for (const row of source.files) {
    assert(!path.isAbsolute(row.file) && !row.file.split(/[\\/]/).includes('..'), 'Unsafe vendor path');
    const bytes = fs.readFileSync(path.join(native, 'SpaceX.ImGui/SpaceX.Vendor', row.file));
    assert.equal(crypto.createHash('sha512').update(bytes).digest('hex'), row.sha512, row.file);
  }
  const publicHeader = read("SpaceX.ImGui/SpaceX.Vendor/SpaceX.Core/SpaceX.imgui.h");
  assert.equal(publicHeader.match(/^#define IMGUI_VERSION\s+"([^"]+)"/m)[1], source.version);
  assert.equal(Number(publicHeader.match(/^#define IMGUI_VERSION_NUM\s+(\d+)/m)[1]), source.versionNumber);
  assert.match(read("SpaceX.ImGui/SpaceX.Vendor/SpaceX.Legal/SpaceX.LICENSE.txt"), /Permission is hereby granted, free of charge/);
  const resource = fs.readFileSync(path.join(native, "SpaceX.Projects/SpaceX.Overlay/SpaceX.OverlayResources.res"));
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
  assert.deepEqual(notices[0], fs.readFileSync(path.join(native, "SpaceX.ImGui/SpaceX.Vendor/SpaceX.Legal/SpaceX.LICENSE.txt")));
  assert.match(read("SpaceX.Projects/SpaceX.Overlay/SpaceX.Overlay.rc"), /310\s+RCDATA\s+"\.\.\\\.\.\\SpaceX\.ImGui\\SpaceX\.Vendor\\SpaceX\.Legal\\SpaceX\.LICENSE\.txt"/);

});

check('O visibility follows hidden authorization and keeps first-frame observation gated by Present', () => {
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
  const bridge = cleanC(read("SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.cpp"));
  const gpu = bridge.slice(bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_gpu_identity('),bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_last_error('));
  inOrder(gpu,['QueryInterface(__uuidof(IDXGIDevice)', 'GetAdapter(', 'GetDesc(', 'CheckInterfaceSupport(__uuidof(IDXGIDevice)', 'game_memcpy(output,&identity,sizeof(identity));return 1;'], 'Actual selected adapter');
  assert.doesNotMatch(gpu,/AdapterLuid|EnumAdapters|EnumDisplayDevices/);
  assert.match(pascal,/GAME-GPU-IDENTITY-V1/);
});

check('Native Present distinguishes occlusion/failure, and portable tests can never grant readiness', () => {
  const bridge = cleanC(read("SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.cpp"));
  const start = bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_render_present(');
  const present = bridge.slice(start, bridge.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_last_error(', start));
  assert(start >= 0);
  inOrder(present, ['game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;', 'ImGui::Render();', 'c->frame_started=false;', '#ifndef GAME_IMGUI_PORTABLE_TEST', 'ImGui_ImplDX11_RenderDrawData(', 'game_imgui_runtime_failed||game_imgui_dx11_failed)return -1;', '->Present(1,0)', 'hr==DXGI_STATUS_OCCLUDED)return 0;', 'if(FAILED(hr))return -1;', 'return hr==S_OK?1:0;', '#else', 'return -1;', '#endif'], 'Bridge Present');
  const build = read("SpaceX.ImGui/SpaceX.Build/SpaceX.Build_ImGui_Win64.bat");
  assert.doesNotMatch(build, /(?:-D|\/D)\s*GAME_IMGUI_PORTABLE_TEST/);
  inOrder(build, ['set "GAME_IMGUI_COMPILER=%BDS%\\bin\\bcc64.exe"', 'if not exist "%GAME_IMGUI_COMPILER%"', '"%GAME_IMGUI_COMPILER%" -c', 'SpaceX.Audit-Object.ps1', 'move /y "%SPACEX_IMGUI_OBJECT_DIR%\\SpaceX.game_imgui_bridge.pending.o" "%SPACEX_IMGUI_OBJECT_DIR%\\SpaceX.game_imgui_bridge.o"'], 'Validated compiler and audited static build');
});

check('GPU failure HRESULT survives the C/Pascal boundary and failed frames cannot claim readiness', () => {
  const bridge = cleanC(read("SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.cpp"));
  const backend = cleanC(read("SpaceX.ImGui/SpaceX.Bridge/SpaceX.Graphics/SpaceX.game_imgui_dx11.cpp"));
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
  const project=read("SpaceX.Projects/SpaceX.Overlay/SpaceX.Overlay.dproj"),build=read("SpaceX.ImGui/SpaceX.Build/SpaceX.Build_ImGui_Win64.bat");
  const objectLink=pascal.match(/\{\$ELSE\}\s*\{\$L\s+'([^']+)'\}/)[1];
  const objectName=path.win32.basename(objectLink);
  // Resolve the actual $L argument without using DCC_ObjPath. The source and
  // project directory bases must both lead to the producer's one audited file.
  const producer=path.resolve(native,'SpaceX.ImGui/SpaceX.Build','../SpaceX.Objects',objectName);
  for(const relative of ['SpaceX.Source/SpaceX.Overlay','SpaceX.Projects/SpaceX.Overlay']){
    assert.equal(path.resolve(native,relative,...objectLink.split('\\')),producer);
  }
  for(const root of ['C:\\Source Tree\\Desktop','D:\\한글 폴더\\SpaceX\\Desktop','\\\\build-host\\source share\\Desktop']){
    const expected=path.win32.join(root,'SpaceX.ImGui','SpaceX.Objects',objectName);
    for(const relative of ['SpaceX.Source\\SpaceX.Overlay','SpaceX.Projects\\SpaceX.Overlay']){
      assert.equal(path.win32.resolve(root,relative,objectLink),expected);
    }
  }
  const objectDir=project.match(/<DCC_ObjPath>([^;<]+);\$\(DCC_ObjPath\)<\/DCC_ObjPath>/)[1];
  assert.equal(objectDir,'$(SpaceXNativeRoot)\\SpaceX.ImGui\\SpaceX.Objects');
  assert(build.includes('set "SPACEX_IMGUI_OBJECT_DIR=%~dp0..\\SpaceX.Objects"'));
  const nativeTarget=project.match(/<Target Name="PrepareOverlayNative"[\s\S]*?<\/Target>/)?.[0];
  assert(nativeTarget,'Native preparation is an explicit build target');
  assert.match(project,/<BuildDependsOn>PrepareOverlayNative;/);assert.match(project,/<RebuildDependsOn>PrepareOverlayNative;/);
  assert.match(nativeTarget,/BeforeTargets="PreBuildEvent;_PasCoreCompile"/);assert.match(nativeTarget,/DependsOnTargets="ValidateProductionIsolation"/);
  inOrder(nativeTarget,['SpaceX.Build_ImGui_Win64.bat','GAME_OVERLAY_OBJECT_MISSING','<Delete Files=','brcc32.exe&quot; -fo','SpaceX.Assert-OverlayManifest.ps1','-ResourcePath','<Move SourceFiles='],'Native compile/resource gates');
  const publish=project.match(/<Target Name="FinalizeProjectExecutable"[\s\S]*?<\/Target>/)?.[0];
  const finalEvent=project.match(/<PostBuildEvent>([\s\S]*?)<\/PostBuildEvent>/)?.[1];
  assert(finalEvent,'IDE/MSBuild finalization event exists');
  inOrder(finalEvent,['if not exist &quot;$(CompiledArtifact)&quot;','GAME_OVERLAY_COMPILED_OUTPUT_MISSING','exit /b 1','SpaceX.Normalize-PE-Unwind.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;','if errorlevel 1 exit /b 1','SpaceX.Assert-OverlayManifest.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;'],'Actual EXE missing-output, normalization and manifest gates');
  inOrder(publish,['<Error Condition="!Exists(\'$(CompiledArtifact)\')"','<Message Importance='],'Final build missing-output postcondition');
  assert.doesNotMatch(publish,/<Exec\b/,'Do not normalize the same executable twice');
  assert.doesNotMatch(publish, /<(?:Move|Delete|RemoveDir)\b/);
  assert.match(project,/<PreBuildEventIgnoreExitCode>false<\/PreBuildEventIgnoreExitCode>/);
  inOrder(build,['DisableDelayedExpansion','if not "%~1"=="" set "BDS=%~1"','pushd "%~dp0.."','if errorlevel 1 goto directory_failed','if not defined BDS','"%GAME_IMGUI_COMPILER%" -c','if errorlevel 1 goto failed','if not exist "%SPACEX_IMGUI_OBJECT_DIR%\\SpaceX.game_imgui_bridge.pending.o" goto failed','SpaceX.Audit-Object.ps1','if errorlevel 1 goto failed','move /y','if errorlevel 1 goto failed','if not exist "%SPACEX_IMGUI_OBJECT_DIR%\\'+objectName+'" goto failed','exit /b 0'],'Object generation gates');
  assert.match(build.slice(build.indexOf(':failed\n')),/exit \/b 1/);
  // The explicit $L path resolves the single audited object directory even
  // without IDE search options. Adjacent source-tree object copies are forbidden.
  assert.doesNotMatch(build,/\bcopy\s+(?:\/b|\/y)/i);
  assert.doesNotMatch(build,/\.\.\\SpaceX\.game_imgui_bridge(?:\.pending)?\.o/);
  assert(!fs.existsSync(path.join(native,'SpaceX.Source/SpaceX.Overlay/SpaceX.game_imgui_bridge.o')));
  const failure=build.slice(build.indexOf('\n:failed\n'),build.indexOf('\n:find_rad_studio\n'));
  for(const file of ['%SPACEX_IMGUI_OBJECT_DIR%\\SpaceX.game_imgui_bridge.o','%SPACEX_IMGUI_OBJECT_DIR%\\SpaceX.game_imgui_bridge.pending.o']){
    assert(build.slice(0,build.indexOf('"%GAME_IMGUI_COMPILER%" -c')).includes('del /q "'+file+'"'),'Pre-build cleanup '+file);
    assert(failure.includes('del /q "'+file+'"'),'Failed-build cleanup '+file);
  }
});

check('O prepares its unsigned PE exception table before publishing the release executable', () => {
  const project = read("SpaceX.Projects/SpaceX.Overlay/SpaceX.Overlay.dproj");
  const target = project.match(/<Target Name="FinalizeProjectExecutable"[\s\S]*?<\/Target>/)[0];
  const event=project.match(/<PostBuildEvent>([\s\S]*?)<\/PostBuildEvent>/)[1];
  assert.doesNotMatch(event,/\$\(OUTPUTPATH\)/,'Command-line builds may leave OUTPUTPATH empty');
  const evaluated=project.slice(0,project.indexOf('<PostBuildEvent>'));
  assert(evaluated.includes('<CompiledArtifact>$(MSBuildProjectDirectory)\\SpaceX.Overlay.exe</CompiledArtifact>'),'Image path must exist before event evaluation');
  assert.match(project, /<PostBuildEventIgnoreExitCode>false<\/PostBuildEventIgnoreExitCode>/);
  inOrder(event,['if not exist &quot;$(CompiledArtifact)&quot;','GAME_OVERLAY_COMPILED_OUTPUT_MISSING','exit /b 1',
    'SpaceX.Normalize-PE-Unwind.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;','if errorlevel 1 exit /b 1',
    'SpaceX.Assert-OverlayManifest.ps1','-ImagePath &quot;$(CompiledArtifact)&quot;'],'Post-link preparation');
  inOrder(target, ['<Error Condition="!Exists(\'$(CompiledArtifact)\')"', '<Message Importance="high"'], 'Post-build existence check');
  assert.equal((project.match(/SpaceX.Normalize-PE-Unwind\.ps1/g)||[]).length,1,'Normalize only once');
  assert.doesNotMatch(target, /<(?:Move|Delete|RemoveDir)\b/);
  assert.doesNotMatch(target, /(?:IgnoreExitCode|ContinueOnError)="(?:true|WarnAndContinue)"/i);
  const normalizer = read("SpaceX.ImGui/SpaceX.Build/SpaceX.Normalize-PE-Unwind.ps1");
  assert.match(normalizer, /SIGNED_IMAGE_REFUSED/);
  assert.match(normalizer, /DUPLICATE_OR_OVERLAPPING_FUNCTIONS/);
  inOrder(normalizer, ['PeUnwindNormalizer]::Normalize($bytes)',
    'if ($result.Changed)', '$output.Write($result.Bytes',
    '[IO.File]::Replace($temporary, $resolved, [System.Management.Automation.Language.NullString]::Value)',
    '$savedBytes = [IO.File]::ReadAllBytes($resolved)',
    'PeUnwindNormalizer]::Normalize($savedBytes)', 'PE_UNWIND_READBACK_MISMATCH',
    'ordering=PASS', 'PE unwind SHA-512:', 'exit 0', 'catch', 'exit 1'], 'Validate then atomic publish');
  assert.doesNotMatch(normalizer, /\[IO\.File\]::Replace\([^\n]*,\s*\$null\)/);
  const fileTests = read("SpaceX.ImGui/SpaceX.Tests/SpaceX.Unwind/SpaceX.Test-PE-Unwind.ps1");
  assert.match(fileTests, /Invoke-NormalizerProcess \$engine \$normalizerPath \$fixturePath/);
  assert.match(fileTests, /File wrapper did not save the expected normalized bytes/);
  // The corrective build step must not turn native/server admission into an
  // accept-unsorted path: malformed images still fail independently.
  assert.match(read("SpaceX.Source/SpaceX.Integrity/SpaceX.CodeIntegrity.pas"), /BeginRVA >= PreviousEnd/);
  const server = ReadContractFile(path.join(MODULE_RESOURCE_ROOT, "../services/cryptography/spacex.crc-layers.js"), 'utf8');
  assert.match(server, /rva<previous/);
  assert(fs.existsSync(path.join(native, "SpaceX.ImGui/SpaceX.Tests/SpaceX.Unwind/SpaceX.Test-PE-Unwind.ps1")));
});

check('O workspace controls own their click and leave window drag capture separate', () => {
  const release = method('procedure TOverlayWindow.ReleaseOwnCapture;', 'procedure TOverlayWindow.CancelInteraction;');
  inOrder(release, ['ApiGetCapture <> FWindow', 'FReleasingCapture := True;', 'try', 'ApiReleaseCapture;', 'finally', 'FReleasingCapture := False;'], 'Release capture');
  const up = method('procedure TOverlayWindow.PointerUp(', 'function TOverlayWindow.Handle(');
  inOrder(up, ['if FThemePressed and (FContext <> nil) then', 'if AuthorityValid then',
    'ImGuiMousePos(FContext, X, Y);', 'ImGuiMouseButton(FContext, 0, False);',
    'else ImGuiClearInput(FContext);', 'FThemePressed := False;', 'FDragging := False;',
    'ReleaseOwnCapture;'], 'Owned theme release');
  const cancel = method('procedure TOverlayWindow.CancelInteraction;', 'procedure TOverlayWindow.PointerDown(');
  inOrder(cancel, ['FDragging := False;', 'FThemePressed := False;', 'ImGuiClearInput(', 'ReleaseOwnCapture;'], 'Cancellation');
  const handle = method('function TOverlayWindow.Handle(', 'function TOverlayWindow.AuthorityValid:');
  assert.match(handle, /WM_CAPTURECHANGED:\s*begin\s*if not FReleasingCapture then CancelInteraction;/);
  assert.match(handle, /WM_CANCELMODE:\s*begin CancelInteraction;/);
  assert.match(handle, /WM_KILLFOCUS:\s*begin\s*CancelInteraction;/);
  assert.match(handle, /WM_ACTIVATE:\s*if LOWORD\(WParam\) = WA_INACTIVE then CancelInteraction;/);
  const down = method('procedure TOverlayWindow.PointerDown(', 'procedure TOverlayWindow.PointerMove(');
  inOrder(down, ['not SurfaceHit(X, Y) then Exit;', 'ImGuiMousePos(FContext, X, Y);', 'if ThemeHit(X, Y) in [ThemePaletteHit, ThemeDismissHit] then',
    'ApiSetCapture(FWindow);', 'FThemePressed := ApiGetCapture = FWindow;',
    'if FThemePressed then ImGuiMouseButton(FContext, 0, True);', 'Exit;', 'ApiGetCursorPos(FDragAnchor)',
    'ApiGetWindowRect(', 'ApiSetCapture(', 'if ApiGetCapture <> FWindow then Exit;', 'FDragging := True;'], 'Selector or rounded surface drag');
  assert.equal((down.match(/ImGuiMouseButton\(/g)||[]).length,1);
  const move = method('procedure TOverlayWindow.PointerMove(', 'procedure TOverlayWindow.PointerUp(');
  assert.match(move, /FDragOrigin\.X \+ Cursor\.X - FDragAnchor\.X/);
  assert.match(move, /FDragOrigin\.Y \+ Cursor\.Y - FDragAnchor\.Y/);
});

check('O receives the entitlement and shared theme only after a valid signed transfer and lease', () => {
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['not AuthorityValid then Exit;', 'FLicensedCard := -1;',
    'if Assigned(FGetLicensedCard) then FLicensedCard := FGetLicensedCard();',
    'if (FLicensedCard < -1) or (FLicensedCard > 17) then FLicensedCard := -1;',
    'ImGuiNewFrame(', 'SceneAction := ImGuiProductScene(FContext, 0, Theme.Index, SceneFlags, FSceneSeconds,',
    'Usage.LicenseReference, FLicensedCard, Usage.RemainingFraction)', 'ImGuiEndCanvas(',
    'if not AuthorityValid then Exit;', 'ImGuiPresent('], 'Verified entitlement and shared palette');
  assert.match(renderer, /WorkspaceSceneFlag = \$1000;/);
  assert.doesNotMatch(renderer, /FRequestProductRun|FProductRunState|ReadRunState|FCarouselPosition|FBusyCursor/);

  const controller=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.pas');
  const lease=controller.slice(controller.indexOf('procedure TOverlayWorker.RenewLease('),
    controller.indexOf('function TOverlayWorker.LicensedCard:'));
  inOrder(lease,['Lease := FClient.Verify(', 'ProductCard := FClient.ProductCard;', 'Deadline := FClient.LeaseDeadlineTick;',
    'TransferConfirmed := FClient.TransferConfirmed;', 'TMonitor.Enter(FLock);',
    'FDeadline := Deadline;', 'FProductCard := ProductCard;', 'if TransferConfirmed and not FTransferred then',
    'FTransferred := True;'], 'Verified entitlement publication');
  const licensed=controller.slice(controller.indexOf('function TOverlayWorker.LicensedCard:'),
    controller.indexOf('function TOverlayWorker.RequestProductRun('));
  inOrder(licensed,['TMonitor.Enter(FLock);', 'Result := -1;', 'not Terminated and not FFailed and FTransferred and',
    '(FDeadline > SpaceXTick) then Result := FProductCard;', 'TMonitor.Exit(FLock);'], 'Expiring read-only entitlement');
  assert.match(controller,/Result\s*:=\s*Worker\.LicensedCard;/);
});

check('O has icon navigation, passive views and receipt-gated workspace interactions', () => {
  const scene=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_scene.h');
  const b=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_license.h');
  const palette=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_palette.h');
  const flight=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_spaceflight.h');
  const tabs=scene.slice(scene.indexOf('static constexpr SpaceXWorkspaceTabItem SpaceXWorkspaceTabs[]'),
    scene.indexOf('static void spacex_workspace_product('));
  inOrder(tabs,['{SpaceXWorkspacePlayer, SpaceXFaPixelAlienMesh, SpaceXWorkspaceRailX, 44.f}',
    '{SpaceXWorkspaceRage, SpaceXFaSkullMesh, SpaceXWorkspaceRailX, 82.f}',
    '{SpaceXWorkspaceAim, SpaceXFaSimpleReticleMesh, SpaceXWorkspaceRailX, 120.f}',
    '{SpaceXWorkspaceVirtuals, SpaceXFaEyeMesh, SpaceXWorkspaceRailX, 158.f}',
    '{SpaceXWorkspacePacket, SpaceXFaGlobeMesh, SpaceXWorkspaceRailX, 211.f}',
    '{SpaceXWorkspaceCodeAndMacros, SpaceXFaCurlyBracesMesh, SpaceXWorkspaceRailX, 264.f}',
    '{SpaceXWorkspaceSettings, SpaceXFaGearMesh, SpaceXWorkspaceRailX, 474.f}',
    '{SpaceXWorkspaceUsage, SpaceXFaBoltMesh, 284.f, 44.f}',
    '{SpaceXWorkspaceGames, SpaceXFaShuttleSpaceMesh, 332.f, 44.f}',
    'static void spacex_workspace_tabs('],
    'Filled icons with Settings at the bottom and Usage directly left of Shooting Game');
  const rail=tabs.slice(tabs.indexOf('static void spacex_workspace_tabs('));
  inOrder(rail,['spacex_palette_item(area,0x4800+tab.id,','v.context->overlay_tab=',
    'overlay_tab_reveal=0.f',
    'spacex_workspace_motion(', 'spacex_fontawesome_mesh(v.draw,tab.icon,v.at(tab.x,tab.y)'],
    'Keyboard targets and animated icon selection');
  assert.doesNotMatch(rail,/separator|AddImage|AddRect|v\.text\(|SetTooltip|PushFont/);
  assert.doesNotMatch(scene,/SpaceXWorkspaceProfile|spacex_workspace_profile\(/);

  const workspaceView=scene.slice(scene.indexOf('struct SpaceXWorkspaceView'),scene.indexOf('enum SpaceXWorkspaceTab'));
  inOrder(workspaceView,['spacex_appearance_caption','spacex_scene_font_size(size*scale)', 'CalcTextSizeA(',
    'ImFloor(start.x+.5f)', 'ImFloor(start.y+.5f)', 'clipped.ClipWith(clip)'],
    'Localized density-aware typography and viewport-bounded pointer targets');
  const checkbox=scene.slice(scene.indexOf('static bool spacex_workspace_checkbox('),
    scene.indexOf('static const char* const SpaceXWorkspaceCuratedNames[]'));
  inOrder(checkbox,['spacex_palette_item(row,label,interactive)','ImGuiItemStatusFlags_Checkable',
    'motion=spacex_workspace_motion(', 'spacex_appearance_check(',
    'v.box(324.f,center-8.f,340.f,center+8.f)', 'license_glass_contour(v.draw,checkbox.Min,checkbox.Max,',
    'PathStroke(mark,0,stroke);', 'return item.pressed;'], 'Checkbox clicks request an effect without applying it');
  assert.doesNotMatch(checkbox,/disabled=!disabled/);

  const settings=scene.slice(scene.indexOf('static int spacex_workspace_appearance('),
    scene.indexOf('static constexpr uint32_t SpaceXOverlayUsageStatus'));
  assert.equal((settings.match(/spacex_workspace_checkbox\(/g)||[]).length,2);
  assert.match(scene,/ImFont\* const readable=selected==v\.context->desktop_locale_font\?selected:v\.context->bounded_font;/);
  inOrder(settings,['"Checkbox color"','"Text color"','"Language"',
    'SpaceXAppearanceLocaleCount','io.MouseWheel','SpaceXWorkspaceAppearanceAction|(selected+1)',
    'render_selector(theme_selector','render_selector(font_selector','"Theme"','"Typeface"',
    'return SpaceXOverlayUsageAction+1','return SpaceXOverlayUsageAction+2',
    'spacex_workspace_appearance(v,','requested=(value+1)|(font_menu?SpaceXWorkspaceFontAction:0);'],
    'Appearance options share fixed primitives and explicit interactions');
  assert.match(settings,/pending_field==SpaceXPreferenceCheckboxColor\+field/);
  assert.match(settings,/pending_field==\(is_font\?SpaceXPreferenceTypeface:SpaceXPreferenceTheme\)/);
  assert.match(settings,/v\.at\(128\.f,293\.f\),v\.at\(168\.f,293\.f\)/);
  assert.match(settings,/v\.at\(128\.f,411\.f\),v\.at\(168\.f,411\.f\)/);
  assert.doesNotMatch(settings,/scroll\.held|lane_top|lane_bottom/);
  const choices=scene.slice(scene.indexOf('static const char* const SpaceXWorkspaceCuratedNames[]'),
    scene.indexOf('static ImU32 spacex_workspace_theme_swatch('));
  inOrder(choices,['"Pure Black"', '"Eclipse"', '"Aurora"', '"Pulsar"', '"Deep Space"', '"Supernova"',
    'SpaceXPalettePresetCount+IM_ARRAYSIZE(SpaceXCuratedPalettes)',
    'SpaceXCuratedPalettes[row-SpaceXPalettePresetCount].theme',
    'return SpaceXWorkspaceCuratedNames[i];', 'return "Saved Theme";'],
    'Existing off-list persisted RGB can be replaced using any named fixed palette');

  const usage=scene.slice(scene.indexOf('static void spacex_workspace_usage('),
    scene.indexOf('static bool spacex_workspace_checkbox('));
  inOrder(usage,['spacex_workspace_product(v,licensed_card);','spacex_workspace_license_key(v,license_suffix_hint);',
    'if(amount<0.f)','"Usage unavailable"','static_cast<unsigned>(amount*100.f+.5f)',
    '"Remaining"','AddRectFilled(track.Min','ImLerp(112.f,337.f,amount)'],
    'One authenticated usage value with an explicit unavailable state');
  assert.doesNotMatch(usage,/Preview|Current session|Rolling window|\.hit\(|spacex_palette_item/);
  const product=scene.slice(scene.indexOf('static void spacex_workspace_product('),
    scene.indexOf('static void spacex_workspace_license_key('));
  assert.match(product,/licensed_card<0\|\|!SpaceXOverlayTitles\[licensed_card\]/);
  assert.doesNotMatch(product,/AddLine|AddCircle|AddImage|\.hit\(/);
  const key=scene.slice(scene.indexOf('static void spacex_workspace_license_key('),
    scene.indexOf('static void spacex_workspace_usage('));
  inOrder(key,['if(!license_suffix_hint)return','key_length=64','suffix_length=6',
    'game_memset(masked,\'*\',key_length-suffix_length);','license_suffix_hint-1',
    'CalcTextSizeA(', 'ink,masked,masked+line_length)', 'ink,masked+line_length,masked+key_length)'],
    'The usage view draws the 64-position masked display from an authorized suffix');
  assert.doesNotMatch(key,/Clipboard|license_form|\.hit\(|spacex_palette_item/);
  const scroll=scene.slice(scene.indexOf('static void spacex_workspace_scroll('),
    scene.indexOf('static int spacex_overlay_workspace('));
  assert.match(scroll,/main_top=60\.f/);
  inOrder(scroll,['overlay_tab_scroll[tab]', 'content.clip.Contains(io.MousePos)', 'io.MouseWheel',
    'content.origin.y-=offset*outer.scale'], 'Viewport scrolling remains active');
  assert.doesNotMatch(scroll,/AddRect|AddLine|spacex_palette_item/);
  const receipt=scene.slice(scene.indexOf('static void spacex_workspace_usage_receipt('),
    scene.indexOf('static void spacex_workspace_scroll('));
  inOrder(receipt,['if(!c->overlay_usage_requested)return','kind==c->overlay_usage_action',
    'status==SpaceXOverlayUsageApproved','if(kind==0)spacex_flight_begin(c)',
    'c->overlay_usage_requested=false;'], 'Local effects require the matching approval');
  assert.match(flight,/ImGui::IsKeyDown\(ImGuiKey_Space\)/);
  assert.match(flight,/c->flight_score=ImMin\(999999u,c->flight_score\+100u\)/);
  inOrder(flight,['const bool was_flying=c->flight_lives>0;', 'if(c->flight_lives>0)return false;',
    'if(was_flying)ImGui::SetKeyboardFocusHere();','replay?0x4511:0x4510','return item.pressed;'],
    'Restore keyboard focus and identity on the replay control after death');
  assert.doesNotMatch(flight,/v\.heading\(/);
  assert.doesNotMatch(flight,/CreateProcess|ReadProcessMemory|SendInput|Clipboard/);
  const workspace=scene.slice(scene.indexOf('static int spacex_overlay_workspace('),
    scene.indexOf('static int32_t spacex_scene_frame('));
  inOrder(workspace,['spacex_palette_apply_theme(c,selected,','spacex_workspace_usage_receipt(c,flags);',
    'spacex_palette_panel(','!c->overlay_stars_hidden','spacex_workspace_tabs(v,popover,reduced_motion);',
    'spacex_workspace_scroll(v,content,tab,popover);','ImGui::PushClipRect(content.clip.Min',
    'spacex_workspace_settings(content,selected','spacex_workspace_usage(content,remaining,licensed_card,license_suffix_hint)',
    'spacex_workspace_flight(content,usage_ready','ImGui::PopClipRect();','c->overlay_usage_requested=true;'],
    'Scroll, usage, and flight remain within the existing authorized scene');
  assert.doesNotMatch(settings,/rgb_slider|color_editor|Custom color|Saving theme/i);
  assert.match(scene,/if \(!reduced_motion && \(!workspace \|\| !c->overlay_stars_paused\)\) c->license_elapsed \+= io\.DeltaTime;/);
  assert.doesNotMatch(scene,/AddImage|game_cover|game_mark/);
  assert.doesNotMatch(workspace,/spacex_palette_controls\(/);
  assert.match(b,/spacex_palette_apply_theme\(c,theme,true\);/);
  assert.match(b,/spacex_palette_panel\(v\.draw,origin,scale,c->license_elapsed,opacity,v\.palette,true,true,\s*c->desktop_star_percent\);/);
  assert.doesNotMatch(b,/spacex_palette_controls\(|spacex_palette_hsv\(|game_cover|game_mark/);
  assert.match(palette,/SpaceXPalettePresetCount = 4;/);
  assert.match(palette,/if\s*\(show_stars\)\s*spacex_palette_stars\(draw,origin,scale,elapsed,opacity,palette\.stars,density\);/);
  assert.doesNotMatch(method('function TOverlayWindow.ThemeHit(', 'procedure TOverlayWindow.RecordRuntimeFailure;'),
    /FLicensedCard|FGetLicensedCard|Authorize|\.Post\(/);
  const legacy=scene.slice(scene.indexOf('extern "C" int32_t GAME_IMGUI_CALL game_imgui_scene_v2('));
  assert.match(legacy,/spacex_scene_frame\(game_context\(handle\),phase,selected,flags,-1,\s*animation_seconds,carousel_position,0\.f\)/);
  const names=['PUBG','TALESRUNNER','LOST_SAGA','APEX_LEGENDS','OVERWATCH','COUNTER_STRIKE_2',
    'ROBLOX','BRAWL_STARS','PUBG_MOBILE','GENSHIN_IMPACT','POKEMON_GO','CLASH_ROYALE'];
  const rawScene=fs.readFileSync(path.join(native,'SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_scene.h'),'utf8');
  const titles=rawScene.match(/static const char\* const SpaceXOverlayTitles\[\] = \{([\s\S]*?)\};/)[1];
  assert.deepEqual([...titles.matchAll(/SPACEX_TEXT_GAME_IMGUI_SCENE_([A-Z_0-9]+)_[0-9A-F]{8}/g)].map(match=>match[1]), names);
  assert.match(titles,/nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,/,
    'Retired indices do not shift the canonical product mapping');
});

check('B and O use the authenticated claim theme and only a visible O edit can commit a preference',()=>{
  const bootstrap=read('SpaceX.Source/SpaceX.Application/SpaceX.Bootstrap.pas');
  const session=read('SpaceX.Source/SpaceX.License/SpaceX.License.Session.pas');
  const client=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.Client.pas');
  const controller=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.pas');
  assert.match(bootstrap,/BootstrapDesktopSettings\(Data, False, Result\);/);
  assert.match(bootstrap,/Body\.AddPair\('themeVersion', TJSONNumber\.Create\(4\)\);/);
  assert.match(session,/RunLicenseWindow\([\s\S]*?Session\.ThemeIndex,\s*function: Boolean\s*begin Result := Worker\.RequestPreparation; end,\s*function: Boolean\s*begin Result := Worker\.RequestCommit; end,\s*@Session\.DesktopStage, Session\.FontIndex\);/);
  assert.match(client,/BootstrapDesktopSettings\(Reply, True, FSession\);/);
  assert.match(client,/Body\.AddPair\('themeVersion', TJSONNumber\.Create\(4\)\);/);
  assert.match(controller,/TOverlayWorker\.Create\(Context, Client, Image, Guard,\s*@Session\.DesktopStage, Session\.ThemeIndex, Session\.FontIndex\)/);
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['Theme := FReadTheme()', 'ImGuiProductScene(FContext, 0, Theme.Index,',
    'not BootstrapThemeValid(ChosenTheme) or (ChosenFont < 0)',
    'PresentResult := ImGuiPresent(FContext);', 'FRendered := (PresentResult = IMGUI_PRESENT_VISIBLE)',
    'if FRendered and FSceneRevealComplete and (SceneAction > 0) and',
    'AuthorityValid then', 'FQueueTheme(ChosenTheme, ChosenFont, ChosenAppearance);'], 'Visible edit dispatch');
  const worker=controller.slice(controller.indexOf('function TOverlayWorker.ProcessThemeSave('),
    controller.indexOf('function TOverlayWorker.ShouldClose:'));
  const execute=controller.slice(controller.indexOf('procedure TOverlayWorker.Execute;'));
  inOrder(execute,['else if (SpaceXTick >= NextCheck) or SnapshotDue then','Refresh;',
    'if not SnapshotDue then', 'if not ProcessUsage(NextCheck) then ProcessThemeSave(ThemeWriteBudgetMs);'],
    'Pending lease and inventory work takes priority over a theme write');
  assert.equal((execute.match(/ProcessThemeSave\(ThemeWriteBudgetMs\)/g)||[]).length,1);
  assert.match(worker,/FDeadline - At < RenewalReserve \+ ThemeMinimumWriteMs/);
  assert.match(worker,/WriteDeadline := At \+ WriteBudget/);
  assert.doesNotMatch(worker,/NextCheck/);
  assert.match(controller,/not FThemeSaving and\s*\(SpaceXTick >= FThemeQueueDeadline\)/);
  const themeView=controller.slice(controller.indexOf('function TOverlayWorker.ReadTheme:'),
    controller.indexOf('function TOverlayWorker.ProcessThemeSave('));
  inOrder(themeView,['Result := FTheme;', 'if Result.Status = otsPending then',
    'Result.Index := FPendingTheme;', 'Result.FontIndex := FPendingFont;',
    'Result.DesktopStage.Appearance := FPendingAppearance;'],
    'Pending settings are visible immediately and a failed save returns the acknowledged snapshot');
  inOrder(worker,['Saved := FClient.SaveTheme(FContext.Security, Index, Font, Appearance, WriteDeadline, Retryable)',
    'if not Terminated and not FFailed and FTransferred and (FDeadline > At) then',
    'if Saved then', 'FTheme.Index := Index;', 'FTheme.FontIndex := Font;',
    'FTheme.DesktopStage.Appearance := Appearance;', 'FTheme.Status := otsIdle;',
    'if Retryable and not FThemeRetried', 'FThemeRetried := True;', 'FTheme.Status := otsFailed;'],
    'Confirmation and one bounded retry are both subordinate to the existing grant');
  const save=client.slice(client.indexOf('function TOverlayClient.SaveTheme('),client.indexOf('function TOverlayClient.InvokeServerPolicy('));
  inOrder(save,['not FTransferConfirmed', "if (FThemePendingRequestID = '') or (FThemePendingIndex <> Index) or",
    '(FThemePendingFont <> Font) or (FThemePendingAppearance <> Appearance) then',
    "'COZY-OVERLAY-THEME-V2'", "'COZY-OVERLAY-THEME-V3'", '#10 + IntToStr(Font);',
    'if FThemeAppearanceSupported then Canonical := Canonical + #10 + IntToStr(Appearance);',
    'Security.Sign(Canonical)', 'FThemePendingRequestID := RequestID;',
    "Body.AddPair('requestId', FThemePendingRequestID);", "Reply := Post('overlayTheme', Body, Deadline)",
    "BootstrapValidateObject(Reply, '|version|sessionId|requestId|sequence|theme|font|', 6)",
    "BootstrapInteger(Reply, 'version') <> 1", "BootstrapString(Reply, 'sessionId', 24) <> FSession.SessionID",
    "BootstrapString(Reply, 'requestId', 80) <> FThemePendingRequestID", "BootstrapInteger(Reply, 'sequence') <> FThemeSequence",
    "BootstrapInteger(Reply, 'theme') <> Index", "BootstrapInteger(Reply, 'font') <> Font",
    'then InvalidResponse;', 'ClearThemeRequest;',
    'on E: EConnectTransport do', 'if not Retryable then ClearThemeRequest;'],
    'An uncertain transport result preserves the exact signed request for an idempotent retry');
});

check('Existing worker product authorization still rejects denied, stale and mismatched grants',()=>{
  const productState=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.State.pas');
  assert.match(productState,/if OverlayProductID\(Card\) = '' then Exit\(0\);/);
  assert.match(productState,/Result := 2400 \+ \(\(Card \* 7\) mod 18\) \* 110;/);
  assert.match(productState,/OverlayRunSettleMilliseconds = 160;/);
  assert.match(productState,/OverlayRunGrantMarginMilliseconds = 250;/);
  const controller=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.pas');
  const request=controller.slice(controller.indexOf('function TOverlayWorker.RequestProductRun('),controller.indexOf('function TOverlayWorker.ProductRunState:'));
  assert.match(request,/OverlayProductCanStart\(FProductCard, Card\)/);
  assert.doesNotMatch(request,/AuthorizeProductStart|\.Post\(/,'The UI callback only queues bounded work');
  const process=controller.slice(controller.indexOf('procedure TOverlayWorker.ProcessProductRun;'),controller.indexOf('function TOverlayWorker.ShouldClose:'));
  inOrder(process,['MaintainLease(False);', 'FClient.AuthorizeProductStart(FContext.Security, Card,',
    'not OverlayProductCanStart(FProductCard, Card)', '(GrantDeadline <= SpaceXTick +', 'OverlayProductRunMilliseconds(Card) + OverlayRunGrantMarginMilliseconds)',
    'FProductRunState := 3;', 'FProductGrantDeadline := GrantDeadline;', 'FProductRunState := 2;'],'Worker rejects denied or stale grants');
  const grant=controller.slice(controller.indexOf('function TOverlayWorker.ProductRunState:'),controller.indexOf('procedure TOverlayWorker.ProcessProductRun;'));
  assert.match(grant,/FProductGrantDeadline <= SpaceXTick \+\s*OverlayProductRunMilliseconds\(FRunProductCard\) \+ OverlayRunGrantMarginMilliseconds/);
  assert.match(grant,/if Result in \[2,3\] then/,'An accepted or rejected grant is consumed once');
  assert.doesNotMatch(controller,/RequestCohortShutdown|FRunRequestedAt/,'START has no cohort-shutdown path');
});

check('O rounds the surface and uses native scene hit testing for tabs, settings and dismissal', () => {
  const point = method('function TOverlayWindow.ScenePoint(', 'function TOverlayWindow.SurfaceHit(');
  inOrder(point, ['Scale := Area.Right / SceneWidth;', 'VerticalScale := Area.Bottom / SceneHeight;',
    'if VerticalScale < Scale then Scale := VerticalScale;', 'OriginX := (Area.Right-SceneWidth*Scale)/2;',
    'OriginY := (Area.Bottom-SceneHeight*Scale)/2;', 'LocalX := (X + 0.5 - OriginX)/Scale;',
    'LocalY := (Y + 0.5 - OriginY)/Scale;'], 'Shared scaled coordinates');
  const hit = method('function TOverlayWindow.SurfaceHit(', 'function TOverlayWindow.ThemeHit(');
  inOrder(hit, ['if not ScenePoint(X, Y, LocalX, LocalY) then Exit;', 'LocalX := LocalX - PanelInset;',
    'LocalY := LocalY - PanelInset;',
    'if (LocalX < 0) or (LocalX >= Width) or (LocalY < 0) or (LocalY >= Height) then Exit;',
    'Result := DX*DX + DY*DY <= Sqr(PanelRadius);'], 'Rounded hit geometry');
  const theme = method('function TOverlayWindow.ThemeHit(', 'procedure TOverlayWindow.RecordRuntimeFailure;');
  inOrder(theme, ['(FContext <> nil) and FRendered and FSceneRevealComplete and',
    'not FResizePending and not FSessionPaused then',
    'Result := ImGuiLicenseHit(FContext, X, Y);'], 'Theme controls share the rendered hit regions');
  assert.match(renderer,/ThemePaletteHit = 7;/);
  assert.match(renderer, /SceneWidth = 380;/);
  assert.match(renderer, /SceneHeight = 520;/);
  assert.match(renderer, /InitialWidth = SceneWidth;/);
  assert.match(renderer, /InitialHeight = SceneHeight;/);
  assert.match(renderer, /PanelInset = 20;/);
  assert.match(renderer, /PanelRadius = 12;/);
  const display = method('procedure TOverlayWindow.FitToWorkArea(', 'procedure TOverlayWindow.ReconcileDisplay;');
  assert.match(display, /if Width > Info.Work.Right - Info.Work.Left then Width := Info.Work.Right - Info.Work.Left;/);
  assert.match(display, /if Height > Info.Work.Bottom - Info.Work.Top then Height := Info.Work.Bottom - Info.Work.Top;/);
  assert.match(display, /ApiSetWindowPos\(FWindow, 0, X, Y, Width, Height,/);
  assert.doesNotMatch(display, /\bSetDpi\(/, 'Work-area fitting must not recursively reapply DPI');
  inOrder(display, ['Monitor := Target(FWindow, 2);', 'if CenterAtOpening then',
    'FitScale := FScale;', 'Width := Round(InitialWidth * FitScale);',
    'X := Area.Left; Y := Area.Top;', 'if CenterAtOpening then',
    'X := Info.Work.Left + (WorkWidth - Width) div 2;',
    'Y := Info.Work.Top + (WorkHeight - Height) div 2;', 'ApiSetWindowPos(FWindow, 0, X, Y, Width, Height,'],
    'Opening uses the monitor work-area midpoint and ordinary fitting keeps the current location');
  const run = method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  inOrder(run, ['FSystemCursor := ApiLoadCursorW(0, IDC_ARROW);',
    'LoadThemeCursors(BootstrapPureBlack);',
    'ApiGetCursorPos(StartPoint)', 'StartPoint.X, StartPoint.Y, 1, 1,',
    'SetDpi(DpiProc(FWindow), nil, True);', 'ImGuiCreate('],
    'Hidden pointer-monitor anchor centers O before GPU creation and loads the paired cursor resources');
  const cursor = method('procedure TOverlayWindow.UpdateCursor(', 'procedure TOverlayWindow.PointerDown(');
  inOrder(cursor, ['not SurfaceHit(X, Y) then ApiSetCursor(FSystemCursor)',
    'ThemeHit(X, Y) = ThemePaletteHit', 'ApiSetCursor(FThemeCursor)', 'ApiSetCursor(FNormalCursor)'],
    'Cursor selection follows the same rounded hit mask and actual controls');
  const cursorLoad = method('procedure TOverlayWindow.LoadThemeCursors(', 'procedure TOverlayWindow.UpdateCursor(');
  inOrder(cursorLoad, ['ResourceID := BootstrapCursorResource(Theme);',
    'if ResourceID = FCursorResource then Exit;',
    'FNormalCursor := ApiLoadCursorW(HInstance, PWideChar(NativeUInt(ResourceID)));',
    'FThemeCursor := ApiLoadCursorW(HInstance, PWideChar(NativeUInt(ResourceID + 1)));'],
    'The acknowledged palette selects the matching pointer pair');
  assert.match(renderer, /if FRendered then LoadThemeCursors\(Theme.Index\);/);
  const handle = method('function TOverlayWindow.Handle(', 'function TOverlayWindow.AuthorityValid:');
  assert.match(handle,/WM_NCHITTEST:[\s\S]*?SurfaceHit\([\s\S]*?Exit\(HTTRANSPARENT\)/);
  inOrder(handle, ['DpiChangedMessage:', 'SetDpi(LOWORD(WParam), PRect(LParam));',
    'FitToWorkArea; Exit;'], 'Per-monitor DPI transition fits the OS suggestion');
});

check('Intro runs after showing and drag unlocks once a complete frame has visibly presented',()=>{
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['if not FWindowShown or (FWindow=0) or not ApiIsWindowVisible(FWindow) then',
    'begin FRendered:=False; Exit; end;', 'NowSeconds := SpaceXFrameSeconds;',
    'if not FSceneRevealComplete then FSceneSeconds := FSceneSeconds + Delta;',
    'ImGuiProductScene(', 'ImGuiPresent(', 'FRendered := (PresentResult = IMGUI_PRESENT_VISIBLE)',
    'if FRendered and (FSceneSeconds >= SceneRevealSeconds) then', 'FSceneRevealComplete := True;'], 'Visible one-shot reveal');
  assert.match(renderer,/SceneRevealSeconds = 0\.50;/);
  assert.doesNotMatch(renderer,/FSceneRevealComplete\s*:=\s*False/i,'Phase changes cannot replay the initial reveal');
  const handle = method('function TOverlayWindow.Handle(', 'function TOverlayWindow.AuthorityValid:');
  assert.match(handle,/if not FSceneRevealComplete then\s*case Msg of\s*WM_LBUTTONDOWN,[\s\S]*?Exit\(0\);/);
  const probe=read('SpaceX.Tests/SpaceX.Overlay/SpaceX.OverlayEnvironmentProbe.dpr');
  assert.match(probe,/OverlayTestSurfaceHit\(X,Y\)/);
  assert.match(probe,/INTRO_COMPLETION_DEADLINE/);
});

check('B and O clip their full-bleed composition surface with one soft DPI-scaled outer edge',()=>{
  const bridge=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.cpp');
  const graphics=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Graphics/SpaceX.game_imgui_dx11.cpp');
  const contour=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_license_glass.h');
  const palette=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_palette.h');
  inOrder(contour,['const int rings=continuous_rim?4:3;', 'continuous_rim?-.65f:-.5f',
    'ImMin(continuous_rim?0.f:.5f,half)', 'ImU32 ink=outline;',
    'if(ring==0)ink&=~IM_COL32_A_MASK;', 'if(ring==rings-1)ink=spacex_scene_mix(top,bottom,',
    'draw->PrimWriteVtx(p,uv,ink);'],
    'The continuous curve and straight edge share rim RGB, with coverage outside the same stroke');
  assert.match(palette,/bool license_rim=true/);
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
  assert.match(bridge,/if\(SUCCEEDED\(hr\)\)hr=c->composition->CreateRectangleClip/);
  assert.doesNotMatch(bridge,/DCOMPOSITION_BORDER_MODE_HARD/);
  assert.match(bridge,/return 12\.0f \* ImMin\(width \/ 380\.0f, height \/ 520\.0f\)/);
  assert.match(bridge,/const float radius=license_corner_radius\(static_cast<float>\(width\),static_cast<float>\(height\)\)/);
  assert.match(bridge,/const float radius = license_corner_radius\(w, h\)/);
  assert.match(bridge,/ClearRenderTargetView\(c->render_target,black\)/);
  assert.match(bridge,/if\(!game_make_render_target\(c\)\|\|!game_composition_clip\(c,width,height\)\)return 0;/);
  assert.doesNotMatch(bridge.slice(bridge.indexOf('static int32_t game_create('),bridge.indexOf('int32_t GAME_IMGUI_CALL game_imgui_set_dpi(')),/game_blur_prepare/);
  assert.doesNotMatch(bridge,/game_blur_prepare|scene_blur_active/);
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
  const bridge=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.cpp');
  const clock=read('SpaceX.Source/SpaceX.Platform/SpaceX.Clock.pas');
  const dispatch=method('function TOverlayWindow.Run(', 'function RunOverlayUI(');
  assert.doesNotMatch(renderer,/WM_TIMER|ApiSetTimer|ApiKillTimer|FrameIntervalMs|ApiGetMessageW/);
  inOrder(dispatch,['MessageCount:=0;', 'while (MessageCount<128) and ApiPeekMessageW(',
    'ApiTranslateMessage(Msg); ApiDispatchMessageW(Msg);', 'Paint;', 'Tick();', 'else if ApiWaitForInput=WAIT_FAILED'], 'Bounded input drain and visible-frame work');
  assert.match(renderer,/MsgWaitForMultipleObjectsEx[\s\S]*?50/);
  const paint=method('procedure TOverlayWindow.Paint;', 'procedure TOverlayWindow.Resize;');
  inOrder(paint,['NowSeconds := SpaceXFrameSeconds;', 'Elapsed := NowSeconds - FLastFrameSeconds;',
    'FSceneSeconds := FSceneSeconds + Delta;'], 'Independent high-resolution scene clock');
  assert.match(clock,/function SpaceXFrameSeconds: Double;[\s\S]*?ClockSlot_QueryPerformanceCounter/);
  assert.match(bridge,/dxgi->SetMaximumFrameLatency\(1\)/);
  assert.match(bridge,/swap_chain->Present\(1,0\)/);
});

console.log(`${checks} ImGui cross-language/provenance/renderer contracts passed (no Delphi or Windows execution).`);
