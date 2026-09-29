'use strict';
// Production geometry/state source checks; Delphi/Android execution is separate.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(root,name),'utf8');
const ui=read('MoaPlayApp.Support.Ui.inc'),flow=read('MoaPlayApp.Support.Flow.inc'),messages=read('MoaPlayApp.Support.Messages.inc');
const protocol=read('MoaPlayApp.Support.Protocol.inc'),permissions=read('MoaPlayApp.Support.Permissions.inc'),shared=read('MoaPlayChatLayout.pas'),dm=read('MoaPlayDirectMessages.pas');
assert.match(dm,/TDirectMessageText = class\(TMoaPlayChatText\)/);
assert.match(dm,/MemberAttachMentions\(Self,FLayout,Members/,'mentions use the shared painted layout');
assert.match(messages,/Text:=TMoaPlayChatText.Create\(Row\)/);
assert.doesNotMatch(messages,/TSupportMessageText|\.TextWidth|\.TextRect/,'support cannot diverge into an independent text measurement path');
assert.match(shared,/FLayout\.Font\.Size:=15/);
assert.match(shared,/FLayout\.MaxSize:=PointF\(100000,100000\)/,'intrinsic measurement is independent of the available paragraph allocation');
assert.match(shared,/FLayout\.WordWrap:=False[\s\S]*ContentWidth:=[\s\S]*FLayout\.WordWrap:=True/);
assert.match(shared,/FLayout\.RenderLayout\(Canvas\)/,'measurement and painting share one layout');
assert.doesNotMatch(shared,/TextRect\.Right/);
const assignment=(source,key)=>{const match=source.match(new RegExp('\\b'+key+':=([^;]+);'));assert.ok(match,key);return match[1];};
const evaluate=(expression,values)=>Function(...Object.keys(values),'return '+expression.replace(/\bMax\(/g,'Math.max(').replace(/\bMin\(/g,'Math.min(').replace(/\bCeil\(/g,'Math.ceil('))(...Object.values(values));
const intrinsic=assignment(shared,'ContentWidth'),body=assignment(shared,'BodyWidth');
for(const W of [180,240,320,360,412,600,1024])for(const glyphWidth of [7,14,28,88.2,1400]){
 const MaxWidth=Math.min(420,W-104),FLayout={TextWidth:glyphWidth};
 const ContentWidth=evaluate(intrinsic,{MaxWidth,FLayout});
 const bodyWidth=evaluate(body,{ContentWidth});
 const bubbleWidth=Math.min(W-76,bodyWidth+24),ownLeft=W-bubbleWidth-12,staffLeft=44;
 assert.ok(ownLeft>=12&&ownLeft+bubbleWidth<=W-12,'own bubble stays inside the right gutter');
 assert.ok(staffLeft+bubbleWidth<=W-12,'staff bubble stays inside the transcript');
 assert.ok(bodyWidth<=bubbleWidth-24,'the measured layout fits its actual child bounds');
 if(glyphWidth===14)assert.ok(bubbleWidth<60,'one Korean glyph cannot become a paragraph-width bubble');
 assert.ok(ContentWidth<=MaxWidth&&ContentWidth>=8);
}
assert.match(messages,/Bubble\.SetBounds\(W-BodyW-12,0,BodyW,RowH\)/);
assert.match(messages,/Bubble\.SetBounds\(44,0,BodyW,RowH\)/);
assert.match(messages,/Text\.SetBounds\(12,8,BodyW-24,BodyH\)/);
assert.match(messages,/Gap:=16;if Continues then Gap:=10/);
assert.match(messages,/Caption:='이전 자동 안내'/,'retained historical automation is not attributed to staff');
assert.match(ui,/FSupportInput:=TSupportComposerMemo.Create/);
assert.match(ui,/FSupportInput\.OnChangeTracking:=SupportInputChanged/);
assert.match(ui,/EnsureRange\(FSupportInput.ContentTextHeight\+12,48.0,112.0\)/);
for(const W of [180,240,360,600])for(const H of [160,240,600])for(const FSupportComposerHeight of [48,80,112]){
 const ComposerH=evaluate(assignment(ui,'ComposerH'),{FSupportComposerHeight,H}),FooterH=ComposerH+16;
 const boxWidth=Math.max(136,W-24),inputRight=10+Math.max(68,boxWidth-66),sendLeft=boxWidth-46;
 assert.ok(H-56-FooterH>=12,'IME leaves visible transcript space');
 assert.ok(inputRight<=sendLeft,'multiline editor and send control never overlap');
 assert.ok(sendLeft+40<=boxWidth,'send stays inside composer');
}
assert.match(ui,/FSupportRenderedScale-MemberDisplayScale\(FRoot\)/,'density changes invalidate retained rows');
assert.match(messages,/FSupportRenderedScale:=MemberDisplayScale\(FRoot\)/);
assert.match(flow,/FSupportHistoryRequested:=FRuntime.SendLine\('SUPPORT_SYNC\|'/);
assert.match(flow,/FSupportPendingText<>MessageText/,'only changed text receives a new idempotency ID');
assert.match(protocol,/if Trim\(FSupportInput.Text\) = FSupportPendingText then FSupportInput.Text := ''/,'receipt preserves a newly edited draft');
assert.equal((protocol.match(/FSupportMessagePage.Visible:=False/g)||[]).length,2,'epoch changes and deletion receipts hide old painted content before deferred rebuild');
assert.match(protocol,/if not SupportAvailable then Exit/,'delayed revoked-session frames cannot restore cleared private data');
assert.equal((protocol.match(/FSupportPendingID := ''/g)||[]).length,1,'only matching receipt clears pending ID; resets preserve retry identity');
assert.match(dm,/if DMSharedProjectionWithdrawn\(FThread,Snapshot\) and Assigned\(FPage\) then FPage.Visible:=False/,'revoked shared previews hide before a gesture-delayed render');
assert.match(dm,/Reason='DM_DELETED'[^\n]+FPage.Visible:=False/,'authoritative deletion errors hide old pixels immediately');
assert.match(dm,/DMBool\(Thread,'deleted'\) or DMBool\(Thread,'unavailable'\) then begin if Assigned\(FPage\) then FPage.Visible:=False/);
assert.match(protocol,/if Seq > FSupportLastSeq \+ 1 then[\s\S]*FSupportNextSyncAt:=0/,'live replies cannot skip unread history pages');
assert.match(permissions,/FSupportReady:=False;FSupportSend.Enabled:=False/);
assert.match(permissions,/PermissionsReady and \(FAuthResumePending or FTransportOffline\)/);
assert.match(flow,/procedure TMoaPlayForm.SupportResetSession;[\s\S]*FSupportInput.Text:=''[\s\S]*FSupportMessages.Clear[\s\S]*FreeAndNil\(FSupportSettings\)/);
assert.doesNotMatch(ui+flow+messages+protocol,/FAQ|SupportStartBot|SupportRenderHelp|SUPPORT_BOT_OPEN|SUPPORT_HELP\|/);
for(const source of [ui,flow,messages,protocol,permissions,shared,dm]){
 assert.equal(source.charCodeAt(0),0xFEFF,'UTF-8 BOM remains present');
 assert.ok(!source.replace(/\r\n/g,'').includes('\n'),'Delphi files retain CRLF');
}
console.log('FIX75 SUPPORT NATIVE PASS: one shared glyph layout, compact Korean widths, gutters/grouping, IME composer bounds, DPI invalidation, sequenced history, draft dedupe and reconnect/revocation guards. Native runtime not executed.');
