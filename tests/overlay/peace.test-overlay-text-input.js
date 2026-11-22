'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const test=require('node:test'),assert=require('node:assert/strict');
const path=require('node:path');
const native=path.resolve(__dirname,'../../../Railway');
const read=p=>ReadContractFile(path.join(native,p),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n');
const renderer=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas');
const bridge=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp');
const wrapper=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.ImGui.pas');
const state=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_text_input.h');
function section(source,startMarker,endMarker){
  const start=source.indexOf(startMarker);
  assert(start>=0,startMarker);
  const end=source.indexOf(endMarker,start+startMarker.length);
  assert(end>start,endMarker);
  return source.slice(start,end);
}

test('The passive O host neither enables a native editor nor invokes legacy text callbacks',()=>{
  assert.doesNotMatch(renderer,/ImGuiTextInput|SyncTextInput|NotifyTextInput|FTextInputActive|FOnTextInput/);
  assert.match(bridge,/CozyTextInput\* text_input/);
  const create=section(bridge,'static int32_t game_create(','extern "C" int32_t GAME_IMGUI_CALL game_imgui_create(');
  assert(!create.includes('sizeof(CozyTextInput)'),'display-only creation must not allocate input state');
});

test('Passive O consumes character, wheel and IME messages without forwarding text',()=>{
  const handler=section(renderer,'function TOverlayWindow.Handle(','function TOverlayWindow.AuthorityValid:');
  assert.match(handler,/WM_MOUSEWHEEL, WM_MOUSEHWHEEL, WM_CHAR,\s*WM_IME_STARTCOMPOSITION, WM_IME_COMPOSITION,\s*WM_IME_ENDCOMPOSITION, WM_IME_CHAR: Exit\(0\);/);
  assert.match(handler,/WM_KEYDOWN:\s*begin\s*if \(WParam = VK_ESCAPE\) and not FSessionPaused and AuthorityValid then/);
  assert.doesNotMatch(renderer,/ImmGetCompositionString|SetWindowsHook|GetAsyncKeyState|GetKeyboardState/);
});

test('Focus loss retires owned input and the explicit native editor still wipes its backing storage',()=>{
  const loss=section(renderer,'    WM_KILLFOCUS:','    WM_ACTIVATE:');
  assert.match(loss,/CancelInteraction;[\s\S]*ImGuiFocus\(FContext, False\);/);
  const cancel=section(renderer,'procedure TOverlayWindow.CancelInteraction;','procedure TOverlayWindow.PointerDown(');
  assert.match(cancel,/FDragging := False;[\s\S]*ImGuiClearInput\(FContext\);[\s\S]*ReleaseOwnCapture;/);
  assert.match(bridge,/game_destroy_context[\s\S]*?cozy_text_wipe\(c->text_input,sizeof\(\*c->text_input\)\)/);
  assert.match(state,/volatile unsigned char\*/);
  assert.match(wrapper,/finally\s*FillChar\(Bytes, SizeOf\(Bytes\), 0\)/);
});

test('Bounded UTF8, UTF16 and glyph admission remain available through the separate native ABI',()=>{
  assert.match(state,/CozyTextBytes = 512/);
  assert.match(state,/s->high_surrogate=0/);
  assert.match(state,/cp>0x10FFFF/);
  assert.match(state,/cp>=0xD800 && cp<=0xDFFF/);
  assert.match(bridge,/count\+c->extra_glyph_count>=128/);
  assert.match(bridge,/Flags\|=ImFontFlags_NoLoadGlyphs/);
  assert.match(wrapper,/game_imgui_text_input_version <> 1/);
  assert.match(read('Cozy.ImGui/Cozy.Build/Cozy.Audit-Object.ps1'),/all \{0\} C ABI entries[^\n]+ -f \$required\.Count/);
});

test('The Windows probe tests callback isolation for Latin and Korean input on a licensed O window',()=>{
  const probe=read('Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr');
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
