'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const read=name=>fs.readFileSync(path.join(root,name),'utf8');
const dm=read('MoaPlayDirectMessages.pas'),bridge=read('MoaPlayApp.Member.DirectMessages.inc'),window=read('MoaPlayPassWindow.pas'),dock=read('MoaPlayApp.Member.GameWindow.inc');
function routine(text,name){const all=[...text.matchAll(/^(?:procedure|function|constructor|destructor)\s+([\w.]+)/gm)],at=all.findIndex(m=>m[1]===name);assert.ok(at>=0,name);return text.slice(all[at].index,all[at+1]?.index??text.length).replace(/\{[\s\S]*?\}/g,'');}
const request=routine(dm,'TMoaPlayDirectMessages.SendRequest');
assert.ok(request.indexOf('FPendingAction:=Action')<request.indexOf('FOnRequest(Action'),'a synchronous transport acknowledgement sees the submitted operation');
assert.ok(request.indexOf('FReadBusy:=True')<request.indexOf('FOnRequest(Action'),'a synchronous read error cannot leave a newly set busy flag behind');
assert.match(request,/if not Result then begin[\s\S]*FPendingAction=Action/,'only the unaccepted matching operation is released');
for(const name of ['ShowList','OpenMember','Reply'])assert.doesNotMatch(routine(dm,'TMoaPlayDirectMessages.'+name),/(?:;Render;|PaintTick\(nil\))/,'callbacks cannot destroy their native click sender');
assert.match(routine(dm,'TMoaPlayDirectMessages.QueuePaint'),/FPaintTimer.Enabled:=True/);
assert.match(routine(dm,'TMoaPlayDirectMessages.RenderThread'),/Snapshot:=DMCopy\(FThread\);[\s\S]*DMObj\(Snapshot,'thread'\)[\s\S]*finally Snapshot.Free/);
const share=routine(bridge,'TMoaPlayForm.HubDirectMessagesPostCard');
assert.match(share,/Snapshot:=TJSONObject.ParseJSONValue\(Post.ToJSON\)/);
assert.match(share,/HubFillPostCard\(Card,Snapshot,True,0,True\)/,'the canonical full post card remains, including poll/media/quotes/reactions');
assert.match(share,/TouchScope:=nil/,'retained read-only children cannot join the replaceable feed gesture scope');
assert.match(share,/not\(Child is TStyledControl\) and not\(Child is TSkSvg\)/,'never walk native style implementation children');
assert.match(share,/csDestroying in Card.ComponentState/);
const merge=routine(dm,'TMoaPlayDirectMessages.MergeThread');
assert.match(merge,/if SeqA=SeqB then Inc\(I\)/,'same sequence is deduplicated');
assert.match(merge,/DMCopyMessage\(Item,SeqA>=SeqB\)/,'old off-page shares lose private stale previews');
const reply=routine(dm,'TMoaPlayDirectMessages.Reply');
assert.match(reply,/if not PendingMutation then begin FPendingAction:=''/,'a transport retry retains its durable send identity');
assert.match(reply,/if ID<>FThreadID then Exit/,'old replies cannot cross threads');
assert.match(reply,/DMNum\(Thread,'revision'\)<DMNum\(DMObj\(FThread,'thread'\),'revision'\)/,'metadata cannot move backwards');
assert.match(reply,/FInput.Text=SubmittedText/,'acknowledging an old draft does not delete a newer edit');
assert.match(window,/FTabs:array\[0\.\.3\]/);assert.match(window,/FGameKey='VALORANT'/);
assert.match(window,/FPassID:=PassText\(Game,'id'\)/);assert.match(dock,/PassID=SelectedID/,'window identity is the pass, not the game/list position');
assert.match(window,/XRadius:=12;YRadius:=12/);
assert.match(window,/if FFullscreen then begin Stroke.Kind:=TBrushKind.None;XRadius:=0;YRadius:=0/);
assert.match(window,/if FFullscreen then begin SetBounds\(0,0,Host.Width,Host.Height\);Exit/);
assert.match(window,/FRestore:=RectF\(Position.X,Position.Y,Position.X\+Width,Position.Y\+Height\)/);
assert.match(window,/SetBounds\(FRestore.Left,FRestore.Top,FRestore.Width,FRestore.Height\)/);
for(const control of ['FHeader','FClose','FScroll','FContent','FGrip','FTabs[I]'])assert.ok(window.includes(control+'.OnDblClick:=ToggleFullscreen'),control+' expands/restores');
assert.match(window,/B.OnClick:=Handler;B.OnDblClick:=ToggleFullscreen/);
assert.match(routine(window,'TMoaPlayPassWindow.ToggleFullscreen'),/FActionTimer.Enabled:=False;FPendingAction:=''/,'double tap cancels a queued download/link');
assert.match(routine(window,'TMoaPlayPassWindow.TransferClick'),/FPendingAction:=TControl\(Sender\).TagString/);
assert.match(routine(window,'TMoaPlayPassWindow.ActionTick'),/Target:=TRectangle.Create\(nil\)/,'external routing uses an independent token, never a soon-freed button');
assert.match(routine(window,'TMoaPlayPassWindow.Resize'),/QueueContent/);assert.doesNotMatch(routine(window,'TMoaPlayPassWindow.Resize'),/RenderContent;/);
assert.match(dock,/SupportReady:=False;FHubDockSupport.Visible:=False/);assert.doesNotMatch(window,/ShellExecute|CreateProcess|Runtime\.exec/);
// Execute actual scalar resize/drag formulae across phones and window restores.
function expression(source){return new Function('ctx','with(ctx){return '+source.replace(/\bMax\(/g,'Math.max(').replace(/\bMin\(/g,'Math.min(').replace(/TControl\(Parent\)/g,'Host')+';}');}
const bounds=routine(window,'TMoaPlayPassWindow.KeepOnScreen');
const width=expression(/Width:=([^;]+);/.exec(bounds)[1]),height=expression(/Height:=([^;]+);/.exec(bounds)[1]);
const xpos=expression(/Position.X:=([^;]+);/.exec(bounds)[1]),ypos=expression(/Position.Y:=([^;]+);/.exec(bounds)[1]);
const ensure=(v,min,max)=>Math.min(max,Math.max(min,v));let cases=0;
for(const hostW of [240,320,360,412,480,900])for(const hostH of [320,640,860])for(const oldW of [120,330,700])for(const oldH of [200,400,1000]){
 const c={Width:oldW,Height:oldH,Host:{Width:hostW},FAvailableBottom:hostH,Position:{X:700,Y:900},EnsureRange:ensure};
 c.Width=width(c);c.Height=height(c);c.MaxY=Math.max(8,hostH-c.Height-8);c.Position.X=xpos(c);c.Position.Y=ypos(c);
 assert.ok(c.Position.X>=8&&c.Position.X+c.Width<=hostW-8);assert.ok(c.Position.Y>=8&&c.Position.Y+c.Height<=hostH-8);cases++;
}
for(const text of [dm,bridge,window,dock])assert.ok(!text.replace(/\r\n/g,'').includes('\n'),'native changes use CRLF');
console.log(`FIX71 CHAT/WINDOW PASS: render lifetime/ack/identity/privacy guards, four per-game top tabs, deferred control dispatch, ${cases} executed production viewport bounds, fullscreen restore, resize/drag and support-dock removal. Native runtime not executed.`);
