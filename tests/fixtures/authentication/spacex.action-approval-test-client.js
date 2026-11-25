"use strict";
const assert=require('node:assert/strict');
async function Approved(send,route,body,actor,headers={}){
 const pending=await send(route,body,actor,headers);
 if(pending.data?.error!=='ADMIN_ACTION_REQUIRED')return pending;
 const action=pending.data.action;assert.match(action.id,/^[a-f0-9]{48}$/);assert.equal(action.path,route.split('?')[0]);
 const auth=await send('/api/session/reauthenticate',{password:process.env.ADMIN_SECRET,actionId:action.id},actor);
 assert.equal(auth.status,200,JSON.stringify(auth.data));
 return send(route,body,actor,{...headers,'X-Admin-Action':action.id});
}
module.exports={Approved};
