'use strict';
// Static invariants for native interactions, flat content cards and soft input/action surfaces.
// This reads the shipped Delphi source; it does not simulate FMX input delivery.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
function Check(apk = path.resolve(__dirname, '../../MoaPlayApp_Android64')) {
  const read = name => fs.readFileSync(path.join(apk, name), 'utf8');
  const touch = read('MoaPlayMemberTouch.pas');
  const widgets = read('MoaPlayApp.Member.Widgets.inc');
  const method = name => {
    const start = touch.search(new RegExp('procedure TMoaPlayTapRectangle\\.' + name + '[;(]'));
    assert.ok(start >= 0, 'Missing touch procedure ' + name);
    const rest = touch.slice(start);
    return rest.slice(0, rest.slice(1).search(/\n(?:procedure|function|constructor|destructor) /) + 1 || undefined);
  };
  // Press feedback must not add a hit-test child, resize the target or mutate
  // its opacity. A held press has no duration limit; only release fades.
  assert.doesNotMatch(touch, /FPressOverlay|TFloatAnimation|Self\.Opacity\s*:=/);
  assert.match(touch, /procedure Paint; override;/);
  assert.match(touch, /Canvas\.SaveState[\s\S]*finally Canvas\.RestoreState\(Saved\)/);
  const tick = method('PressTick');
  assert.ok(tick.indexOf('if FTouchDown and not FCanceled') < tick.indexOf('Elapsed:='), 'Hold checked before elapsed release fade');
  assert.match(tick, /if FTouchDown and not FCanceled then begin\s*FPressTimer\.Enabled:=False;[\s\S]*?Exit;\s*end;/);
  assert.match(method('ShowPress'), /if FTouchDown and not FCanceled then Exit;/);
  assert.match(method('ShowPress'), /if Assigned\(FPressTimer\) then FPressTimer\.Enabled:=False;/, 'New press cancels old fade');
  assert.match(touch, /destructor TMoaPlayTapRectangle\.Destroy;\s*begin\s*if Assigned\(FPressTimer\) then begin FPressTimer\.Enabled:=False;FPressTimer\.OnTimer:=nil;end;/);
  assert.match(method('CancelTouch'), /FPressLevel:=0;FReleasing:=False;FRepeatDoublePending:=False;/);
  assert.match(method('MouseUp'), /if not PointInObjectLocal\(X,Y\) then CancelTouch;/);
  assert.match(method('CheckMovement'), /if Assigned\(FScope\) and FScope\.FGestureMoved and/);
  assert.match(touch, /FGestureMoved:=False;FMovingUntil:=0;/, 'A fresh down does not inherit an old scroll');
  assert.match(touch, /Result:=\(X>=0\) and \(Y>=0\) and \(X<=Width\) and \(Y<=Height\);/);
  assert.match(touch, /FDownAt:=TStopwatch\.GetTimeStamp;FTouchDown:=True;FHadDown:=True;FCanceled:=False/);
  assert.match(touch, /if FRepeatClicks and FRepeatDoublePending then Click;/);
  assert.match(touch, /FRepeatClickDownAt=FDownAt/, 'Repeated chip clicks retain gesture-specific deduplication');
  assert.match(touch, /Rejected:=\(FCanceled and FHadDown\)/);
  assert.match(touch, /if not Rejected then inherited Click;/, 'A canceled gesture never reaches the application handler');
  // Explicit quote/feature decoration retains its existing native brush.
  // Default content cards are now flat; button/input chrome is a solid soft fill.
  // Neither styling helper changes passive wrappers into active input targets.
  const glass = widgets.split('procedure HubGlassCardStyle')[1].split('function TMoaPlayForm.HubCard')[0];
  assert.match(glass, /Fill\.Kind:=TBrushKind\.Solid;Card\.Fill\.Color:=MemberSurface/);
  assert.doesNotMatch(glass, /Gradient|MemberGlass/);
  assert.doesNotMatch(glass, /\.Create\(|HitTest|AutoCapture|OnClick|\.Opacity\s*:=/);
  const card = widgets.split('function TMoaPlayForm.HubCard')[1].split('procedure HubActionPanelStyle')[0];
  assert.match(card, /TMoaPlayTapRectangle.Create\(FHubPage\)/);
  assert.match(card, /TouchScope:=FHubTouch/,'flat surfaces retain gesture cancellation');
  assert.match(card, /Result.XRadius:=0;Result.YRadius:=0/);
  assert.match(card, /Result.Fill.Kind:=TBrushKind.None;Result.Stroke.Kind:=TBrushKind.None/);
  assert.doesNotMatch(card, /HubGlassCardStyle\(/,'default cards no longer inherit a bordered panel');
  assert.match(card, /if Dark then begin Result.Fill.Kind:=TBrushKind.Solid;Result.Fill.Color:=MemberPrimary/,'explicit primary cards retain their semantic color');
  assert.match(card, /FHubY:=FHubY\+Height\+16/,'changing surface style cannot change the shared spacing contract');
  for (const name of ['HubActionPanelStyle', 'HubInputPanelStyle']) {
    const part = widgets.split('procedure ' + name)[1].split(/\n(?:procedure|function) /)[0];
    assert.match(part, /Panel.Fill.Color:=MemberSoft;Panel.Fill.Kind:=TBrushKind.Solid/);
    assert.match(part, /Panel.Stroke.Kind:=TBrushKind.None/);
    assert.doesNotMatch(part, /Gradient|\.Create\(|OnClick|\.Opacity\s*:=/);
    assert.doesNotMatch(part, /HubGlassCardStyle/);
  }
  const inputPanel = widgets.split('procedure HubInputPanelStyle')[1].split(/\n(?:procedure|function) /)[0];
  assert.match(inputPanel,/Panel.HitTest:=False;Panel.AutoCapture:=False/,'input wrapper never steals focus or the keyboard tap');
  // FIX68 intentionally replaces the news glass fill with a transparent,
  // rounded rectangle. Styling must retain its outline without introducing
  // another gesture target or changing the existing card's handler.
  const newsStyle = read('MoaPlayApp.Member.NewsShop.inc')
    .split('procedure HubContentReadStyle(Card:TRectangle);')[1]?.split(/\n(?:procedure|function) /)[0];
  assert.ok(newsStyle, 'News card surface helper exists');
  assert.match(newsStyle, /Card.Fill.Kind:=TBrushKind.None/);
  assert.match(newsStyle, /Card.XRadius:=12;Card.YRadius:=12/);
  assert.match(newsStyle, /Card.Stroke.Kind:=TBrushKind.Solid;Card.Stroke.Color:=MemberBorder/);
  assert.match(newsStyle, /Card.Stroke.Thickness:=MemberBorderWidth/);
  assert.doesNotMatch(newsStyle, /HubGlassCardStyle|MemberFrostedCard|\.Create\(|HitTest|AutoCapture|OnClick|\.Opacity\s*:=/);
  const theme = read('MoaPlayMemberTheme.pas').split(/\bimplementation\b/i)[1];
  const role = (name, dark) => {
    const body = new RegExp('function ' + name + ':TAlphaColor;\\s*begin ([^\\n]+)end;', 'i').exec(theme)?.[1];
    assert.ok(body, 'Missing palette role ' + name);
    const pair = /if DarkValue then Result:=\$([\da-f]{8}) else Result:=\$([\da-f]{8});/i.exec(body);
    assert.ok(pair, 'Expected theme pair for ' + name);
    return parseInt(pair[dark ? 1 : 2], 16);
  };
  const rgb = c => [16, 8, 0].map(s => (c >>> s) & 255);
  const luma = c => rgb(c).map(v => (v /= 255) <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4).reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
  const contrast = (a, b) => (Math.max(luma(a), luma(b)) + .05) / (Math.min(luma(a), luma(b)) + .05);
  let samples = 0;
  for (const dark of [false, true]) {
    for (const color of ['MemberBackground', 'MemberSurface', 'MemberSoft']) {
      const fill = role(color, dark);
      assert.equal(fill >>> 24, 255, 'Underlying page and explicit control fills remain opaque');
      for (const ink of ['MemberText', 'MemberMuted', 'MemberLink']) {
        assert.ok(contrast(role(ink, dark), fill) >= 4.5, `${dark ? 'dark' : 'light'} ${ink} on ${color}`);
        samples++;
      }
    }
    assert.equal(contrast(role('MemberFloatingInk', dark), role('MemberFloatingFill', dark)), 21);
  }
  for (const name of ['MoaPlayMemberInput.pas', 'MoaPlayMemberMemo.pas']) {
    const input = read(name);
    const caption = input.split('if FFloatingLabel then begin').at(-1)?.split('end else begin')[0];
    assert.ok(caption, 'Caption branch ' + name);
    assert.match(caption, /State:=2;/);
    assert.doesNotMatch(caption, /IsFocused|State:=1|SetFocus|ApplyStyleLookup/);
  }
  const indicators = read('MoaPlayCasinoIndicators.pas');
  assert.doesNotMatch(indicators, /FStats|FStatLines|bestStreak|matched|'played'/);
  const feedback = read('MoaPlayUiFeedback.pas');
  assert.match(feedback, /Fill.Kind:=TBrushKind.Solid;FPanel.Fill.Color:=MemberFloatingFill/);
  assert.match(feedback, /FText.TextSettings.FontColor:=MemberFloatingInk/);
  return samples;
}
if (require.main === module) console.log(`Native touch/flat-card source guard passed (${Check()} palette contrast samples; Delphi/device input not executed).`);
module.exports = { Check };
