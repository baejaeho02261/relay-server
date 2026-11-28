'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/spacex.native-string-contract");
const test=require('node:test'),assert=require('node:assert/strict');
const path=require('node:path');
const native=path.resolve(__dirname,'../../../Desktop');
const read=p=>ReadContractFile(path.join(native,p),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n');
const renderer=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.Renderer.pas');
const bridge=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_bridge.cpp');
const wrapper=read('SpaceX.Source/SpaceX.Overlay/SpaceX.Overlay.ImGui.pas');
const state=read('SpaceX.ImGui/SpaceX.Bridge/SpaceX.Core/SpaceX.game_imgui_text_input.h');
function section(source,startMarker,endMarker){
  const start=source.indexOf(startMarker);
  assert(start>=0,startMarker);
  const end=source.indexOf(endMarker,start+startMarker.length);
  assert(end>start,endMarker);
  return source.slice(start,end);
}

test('The passive O host neither enables a native editor nor invokes legacy text callbacks',()=>{
  assert.doesNotMatch(renderer,/ImGuiTextInput|SyncTextInput|NotifyTextInput|FTextInputActive|FOnTextInput/);
  assert.match(bridge,/SpaceXTextInput\* text_input/);
  const create=section(bridge,'static int32_t game_create(','extern "C" int32_t GAME_IMGUI_CALL game_imgui_create(');
  assert(!create.includes('sizeof(SpaceXTextInput)'),'display-only creation must not allocate input state');
});

test('O forwards only the vertical wheel inside its authorized surface and consumes text/IME messages',()=>{
  const handler=section(renderer,'function TOverlayWindow.Handle(','function TOverlayWindow.AuthorityValid:');
  const wheel=section(handler,'    WM_MOUSEWHEEL:\n','    WM_MOUSEHWHEEL, WM_CHAR,');
  assert.match(wheel,/FSessionPaused or FMinimized or FDragging or\s*not FWindowShown or not AuthorityValid/);
  assert.match(wheel,/if SurfaceHit\(X, Y\) then\s*begin\s*ImGuiMousePos\(FContext, X, Y\);\s*ImGuiMouseWheel\(FContext, 0, SmallInt\(HIWORD\(WParam\)\) \/ WHEEL_DELTA\);/);
  assert.match(handler,/WM_MOUSEHWHEEL, WM_CHAR,\s*WM_IME_STARTCOMPOSITION, WM_IME_COMPOSITION,\s*WM_IME_ENDCOMPOSITION, WM_IME_CHAR: Exit\(0\);/);
  assert.match(handler,/WM_KEYDOWN:\s*begin\s*if FSessionPaused or not AuthorityValid then Exit;\s*if WParam = VK_ESCAPE then/);
  assert.match(handler,/if ThemePickerOpen then ImGuiKey\(FContext, VK_ESCAPE, True\)\s*else RequestUserClose;/);
  assert.match(handler,/VK_TAB, VK_RETURN, VK_SPACE, VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN, VK_SHIFT:\s*ImGuiKey\(FContext, Integer\(WParam\), True\);/);
  assert.match(handler,/WM_KEYUP:[\s\S]*?VK_ESCAPE, VK_TAB, VK_RETURN, VK_SPACE, VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN, VK_SHIFT:\s*ImGuiKey\(FContext, Integer\(WParam\), False\);/);
  assert.doesNotMatch(renderer,/ImmGetCompositionString|SetWindowsHook|GetAsyncKeyState|GetKeyboardState/);
});

test('Focus loss retires owned input and the explicit native editor still wipes its backing storage',()=>{
  const loss=section(renderer,'    WM_KILLFOCUS:','    WM_ACTIVATE:');
  assert.match(loss,/CancelInteraction;[\s\S]*ImGuiFocus\(FContext, False\);/);
  const cancel=section(renderer,'procedure TOverlayWindow.CancelInteraction;','procedure TOverlayWindow.PointerDown(');
  assert.match(cancel,/FDragging := False;[\s\S]*ImGuiClearInput\(FContext\);[\s\S]*ReleaseOwnCapture;/);
  assert.match(bridge,/game_destroy_context[\s\S]*?spacex_text_wipe\(c->text_input,sizeof\(\*c->text_input\)\)/);
  assert.match(state,/volatile unsigned char\*/);
  assert.match(wrapper,/finally\s*FillChar\(Bytes, SizeOf\(Bytes\), 0\)/);
});

test('Bounded UTF8, UTF16 and glyph admission remain available through the separate native ABI',()=>{
  assert.match(state,/SpaceXTextBytes = 512/);
  assert.match(state,/s->high_surrogate=0/);
  assert.match(state,/cp>0x10FFFF/);
  assert.match(state,/cp>=0xD800 && cp<=0xDFFF/);
  assert.match(bridge,/count\+c->extra_glyph_count>=128/);
  assert.match(bridge,/Flags\|=ImFontFlags_NoLoadGlyphs/);
  assert.match(wrapper,/game_imgui_text_input_version <> 1/);
  assert.match(read('SpaceX.ImGui/SpaceX.Build/SpaceX.Audit-Object.ps1'),/all \{0\} C ABI entries[^\n]+ -f \$required\.Count/);
});

test('The Windows probe tests callback isolation for Latin and Korean input on a licensed O window',()=>{
  const probe=read('SpaceX.Tests/SpaceX.Overlay/SpaceX.OverlayEnvironmentProbe.dpr');
  const contract=section(probe,'procedure Contract;','procedure Run;');
  for(const finding of [
    "SendMessage(W,WM_CHAR,Ord('x'),0);",
    'SendMessage(W,WM_IME_CHAR,$AE00,0);',
    'SendMessage(W,WM_IME_STARTCOMPOSITION,0,0);',
    'SendMessage(W,WM_IME_COMPOSITION,0,0);',
    'SendMessage(W,WM_IME_ENDCOMPOSITION,0,0);',
    'Require((TextCallbackCalls=0) and (InputActivationReads=0),',
    'Require((S.LicensedCard=5) and (S.ScenePhase=0) and (ProductStartCalls=0) and',
  ]) assert(contract.includes(finding),finding);
});
