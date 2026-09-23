'use strict';
// FIX66 intentionally removes avatar notes. Keep the old suite entry as an
// absence guard so no stale route, acknowledgement or timer unit reappears.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const native=path.resolve(__dirname,'../../MoaPlayApp_Android64');
const server=path.resolve(__dirname,'../services/member');
function removedNoteContract(source,label){
 assert.doesNotMatch(source,/\bMoaPlayProfileNoteSheet\b|\bTMoaPlayProfileNoteSheet\b|\bHubProfileNote\w*\b|\bHubResizeProfileNote\b|\bHubResetProfileNoteFocus\b/,label+' retains removed native note machinery');
 assert.doesNotMatch(source,/['"]profile\.note(?:\.save)?['"]/,label+' retains a removed note route');
 assert.doesNotMatch(source,/메모 남기기|메모를 남겨보세요/,label+' still offers the removed feature');
}
let files=0;
for(const name of fs.readdirSync(native).filter(x=>/\.(?:pas|inc|dpr|dproj)$/.test(x))){
 removedNoteContract(fs.readFileSync(path.join(native,name),'utf8'),name);files++;
}
for(const name of fs.readdirSync(server).filter(x=>x.endsWith('.js'))){
 removedNoteContract(fs.readFileSync(path.join(server,name),'utf8'),name);files++;
}
assert.equal(fs.existsSync(path.join(native,'MoaPlayProfileNoteSheet.pas')),false,'the removed UI unit must not be packaged');
assert.throws(()=>removedNoteContract("FMember.Request('profile.note',Body.ToJSON,True);",'regression'));
assert.throws(()=>removedNoteContract('HubProfileNoteReply(True);','regression'));
assert.throws(()=>removedNoteContract('MoaPlayProfileNoteSheet in old.pas','regression'));
console.log(`FIX65/FIX66 PROFILE NOTE REMOVAL PASS: ${files} native/server files have no note UI, route, callback or unit; deliberate reintroductions rejected.`);
