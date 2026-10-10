'use strict';
// Textual scope/contracts only; this is not a Pascal parser or a Windows test.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../..'),c=name=>fs.readFileSync(path.join(root,'GameConnect_Win64',name),'utf8'),s=name=>fs.readFileSync(path.join(root,'GameWeb',name),'utf8');
let count=0;function test(name,fn){fn();count++;console.log('PASS '+name);}
const native=c('Game.ServerAuthority.pas'),transport=c('GameConnectTransport.pas');
test('Bounded read-only API metadata survives unit finalization until process exit',()=>{
 const p=c('Game.Api.Pointer.pas');
 const code=p.replace(/\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\r\n]*/g,'');
 assert.match(code,/MaxApiSlots\s*=\s*1024;/);assert.match(code,/ArenaBytes\s*=\s*65536;/);
 assert.match(code,/if not CodecReady or \(Arena <> nil\) then/);
 assert.match(code,/SizeOf\(TApiArena\) > ArenaBytes/);
 assert.equal((code.match(/Allocate\(nil, ArenaBytes, MemCommitReserve, PageReadWrite\)/g)||[]).length,1);
 assert.match(code,/Arena\^\.Protect\(Arena, ArenaBytes, PageReadOnly, Previous\)/);
 assert.match(code,/Info\.AllocationBase = Arena/);assert.match(code,/Info\.Protect = PageReadOnly/);
 assert.match(code,/finalization\s+end\.\s*$/i);
 assert.doesNotMatch(code,/\bReleaseApiPointerStorage\b|\bFreePages\s*\(|\bVirtualFree\s*\(|Arena\^\.Release\s*\(/i);
 assert.ok(p.includes('Windows reclaims the pages at'));assert.ok(p.includes('process exit, together with the pinned API modules'));
});
test('API module ownership precedes parsing and target pinning precedes application work',()=>{
 const p=c('PEB_Export_x64.pas'),startup=c('Game.Startup.pas');
 const required=p.slice(p.indexOf('{ ROR13 REQUIRE BEGIN }'),p.indexOf('{ ROR13 REQUIRE END }'));
 assert.match(required,/Handle := LoadSystemModule64\(ModuleName\);[\s\S]*?Result := GetProcAddressHash64\(Base, ProcHash\)/);
 const pin=p.slice(p.lastIndexOf('procedure RetainApiTargetModule('),p.lastIndexOf('function OptionalSystemProcAddressHash64('));
 assert.match(pin,/PEBGetModuleHandleExW\(\$00000004 or \$00000001,\s*PWideChar\(Address\), Module\)/);
 assert.match(pin,/Address = nil/);assert.match(pin,/Module = 0/);assert.doesNotMatch(pin,/\$00000002/);
 const optional=p.slice(p.lastIndexOf('function OptionalSystemProcAddressHash64('),p.lastIndexOf('initialization'));
 assert.match(optional,/Module := LoadSystemModule64\(ModuleName\);\s*Result := GetProcAddressHash64\(Pointer\(Module\), ProcHash\)/);
 assert.match(startup,/if Address = nil then Continue;\s*RetainApiTargetModule\(Address\);[\s\S]*?ApiPointerTargetsMatch\(Targets\)/);
 const resolverFinal=p.slice(p.lastIndexOf('finalization')).replace(/\{[\s\S]*?\}/g,'');
 assert.doesNotMatch(resolverFinal,/\b(?:PEB)?FreeLibrary\s*\(/i);
 for(const [file,role,run] of [['GameLauncher.dpr','gcrLauncher','RunLauncher'],['GameConnect.dpr','gcrConnect','RunGameConsole'],['GameOverlay.dpr','gcrOverlay','RunOverlay']]){
  const dpr=c(file),seal=dpr.indexOf('SealApiPointerStorage;'),gate=dpr.indexOf('RequireNativeStartup('+role+');'),work=dpr.indexOf('ExitCode := '+run+';');
  assert.ok(seal>=0&&gate>seal&&work>gate,file+' must seal and validate/pin before application work');
 }
});
test('Two attempts share one monotonic budget and fresh observations',()=>{assert.ok(native.includes('ObservationBudgetMs = 25000'));assert.match(native,/Clock := TStopwatch\.StartNew;[\s\S]*?for Attempt := 1 to 2/);assert.ok(native.includes('WaitBeforeRetry(Clock, Cancelled, OperationKey)'));assert.ok(native.includes("BindContext(Body, 'challenge')"));assert.ok(native.includes("BindContext(SubmitBody, 'submit')"));assert.ok(native.includes("(Attempt = 2) or not E.Retryable"));});
test('Concurrent same-operation guard is bounded and removed in finally',()=>{assert.ok(native.includes('ActiveObservations.Count >= 128'));assert.ok(native.includes('ActiveObservations.ContainsKey(OperationKey)'));assert.match(native,/finally\s+EndObservation\(OperationKey\);\s+WipeText\(OperationKey\);/);assert.ok(native.includes("SessionID + '|' + Intent + '|' + Binding"));});
test('Cancellation is wired to the existing atomic B stop flag',()=>{assert.ok(native.includes('if Assigned(Cancelled) and Cancelled() then'));assert.ok(native.includes('TThread.Sleep(Piece)'));assert.ok(c('Game.Api.pas').includes('Result := InterlockedCompareExchange(FStopRequested, 0, 0) <> 0;'));});
test('Only explicit callers get preparation-inclusive transport budgets',()=>{assert.ok(transport.includes('RequestBudgetMs: Cardinal = 0'));assert.ok(transport.includes('BoundedBudget := RequestBudgetMs <> 0;'));assert.ok(transport.includes('if not BoundedBudget then RequestBudgetMs := RequestTimeoutMs;'));assert.match(transport,/SocketBudget := RequestBudgetMs;\s+if BoundedBudget then\s+Dec\(SocketBudget, RequestClock.ElapsedMilliseconds\);/);assert.ok(native.includes("Transport.PostJSON('security', Body, RemainingBudget(Clock, Cancelled))"));});
test('No new local policy file / registry / persistence is added to observation code or UI',()=>{for(const text of [native,s('public/admin-desktop-security.js')])assert.ok(!/(?:localStorage|sessionStorage|indexedDB)\s*[.(]|\b(?:SaveToFile|WriteAllText|WriteAllBytes|TRegistry)\b/i.test(text));assert.ok(!native.includes("'trustedReleaseKeys'"));});
test('New UI script belongs to the actual HTML and integrity bundle manifest',()=>{assert.ok(s('public/index.html').includes('/admin-desktop-security.js'));assert.ok(s('web/uiBundle.js').includes('admin-desktop-security.js'));assert.ok(s('web/ui-bundle.json').includes('admin-desktop-security.js'));});
test('Raw uploads are independently authenticated / CSRF guarded and stage only',()=>{const text=s('web/routes/desktopBootstrapRoutes.js');const authAt=text.indexOf('CheckSession(session,pathname)'),readAt=text.indexOf('await ReadBytes(req)');assert.ok(authAt>=0&&readAt>=0&&authAt<readAt);assert.ok(text.includes('ValidateCsrf(req,session)'));assert.ok(text.includes('ops.Stage(component,version,bytes,approval,session.id,releaseManifestId)'));assert.ok(text.includes("url.searchParams.get('releaseManifestId')"));assert.ok(text.includes("...(releaseManifestId?{releaseManifestId}:{})"));assert.ok(!text.includes('bootstrap.Publish('));assert.ok(text.includes("disposition:'CANDIDATE',activeUnchanged:true"));});
console.log(`Native / integration textual contracts: ${count} passed; dcc64, Windows ABI and browser behavior NOT tested here`);
