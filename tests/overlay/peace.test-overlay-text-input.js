'use strict';
// Source integration contracts complement the executable C++ state/core tests.
// Actual Windows message delivery, Korean IME and GPU presentation are NOT_RUN.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../../Railway');
const read=p=>fs.readFileSync(path.join(native,p),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n');
const renderer=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.Renderer.pas');
const bridge=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_bridge.cpp');
const wrapper=read('Cozy.Source/Cozy.Overlay/Cozy.Overlay.ImGui.pas');
const state=read('Cozy.ImGui/Cozy.Bridge/Cozy.Core/Cozy.game_imgui_text_input.h');
function section(s,a,b){const start=s.indexOf(a);assert(start>=0);const end=s.indexOf(b,start+a.length);assert(end>start);return s.slice(start,end);}
test('input requires explicit callback, active editor, focus and authority',()=>{
  const sync=section(renderer,'function TOverlayWindow.SyncTextInput:','procedure TOverlayWindow.NotifyTextInput(');
  for(const x of ['FFocused','not FSessionPaused','not FClosing','Assigned(FTextInputActive)','Assigned(FOnTextInput)','FTextInputActive() and AuthorityValid','ImGuiTextInputEnable(FContext, Enabled)'])assert(sync.includes(x),x);
  assert.match(renderer,/const TextInputActive: TFunc<Boolean> = nil;\s*const OnTextInput: TOverlayTextInputCallback = nil/);
  assert.match(bridge,/CozyTextInput\* text_input/);
  const create=section(bridge,'static int32_t game_create(','extern "C" int32_t GAME_IMGUI_CALL game_imgui_create(');
  assert(!create.includes('sizeof(CozyTextInput)'),'default display-only creation must not allocate input state');
});
test('IME result goes through one WM_CHAR consumer and composition remains OS-owned',()=>{
  const ime=section(renderer,'    WM_IME_CHAR:','    WM_CHAR:');
  assert(ime.includes('ApiDefWindowProcW('));assert(!ime.includes('ImGuiTextInputUtf16'));
  const character=section(renderer,'    WM_CHAR:','    WM_KEYDOWN, WM_KEYUP:');
  assert.equal((character.match(/ImGuiTextInputUtf16\(/g)||[]).length,1);
  assert(character.indexOf('itiaCancel')<character.indexOf('NotifyTextInput(otieBackspace)'));
  assert(character.includes('(WParam > $FFFF)')); 
  assert(!renderer.includes('ImmGetCompositionString'),'no second GCS_RESULTSTR consumer');
  assert(!/SetWindowsHook|GetAsyncKeyState|GetKeyboardState/.test(renderer));
  assert.match(renderer,/WM_IME_COMPOSITION:[\s\S]*?\(NativeUInt\(LParam\) and \$1FFF\) = 0[\s\S]*?itiaCancel/);
});
test('focus retirement clears and releases input before invoking external callback',()=>{
  const loss=section(renderer,'    WM_KILLFOCUS:','    WM_ACTIVATE:');
  assert(loss.indexOf('CancelInteraction;')<loss.indexOf('NotifyTextInput(otieFocusLost)'));
  assert(loss.indexOf('SyncTextInput;')<loss.indexOf('NotifyTextInput(otieFocusLost)'));
  assert.match(bridge,/game_destroy_context[\s\S]*?cozy_text_wipe\(c->text_input,sizeof\(\*c->text_input\)\)/);
  assert.match(state,/volatile unsigned char\*/);
  assert.match(wrapper,/finally\s*FillChar\(Bytes, SizeOf\(Bytes\), 0\)/);
});
test('bounded UTF8, UTF16 and glyph admission are independent of the old display vocabulary',()=>{
  assert.match(state,/CozyTextBytes = 512/);
  assert.match(state,/s->high_surrogate=0/);
  assert.match(state,/cp>0x10FFFF/);
  assert.match(state,/cp>=0xD800 && cp<=0xDFFF/);
  assert.match(bridge,/count\+c->extra_glyph_count>=128/);
  assert.match(bridge,/Flags\|=ImFontFlags_NoLoadGlyphs/);
  assert.match(wrapper,/game_imgui_text_input_version <> 1/);
  assert.match(read('Cozy.ImGui/Cozy.Build/Cozy.Audit-Object.ps1'),/all 28 C ABI entries/);
});
test('owned Windows probe includes duplicate, cancel, focus, UTF16 and opt-out cases without attesting them here',()=>{
  const probe=read('Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr');
  for(const x of ['WM_IME_CHAR default processing commits exactly once','composition cancel never fabricates committed text','focus loss wipes pending UTF16','editor opt-out immediately disables text transport','physical IME typing NOT_RUN','Backspace retires a pending surrogate','Enter retires a pending surrogate','out-of-range WM_CHAR retires a pending surrogate'])assert(probe.includes(x),x);
});
