'use strict';
// A shop action belongs to the authenticated account. Call inside the same
// Operation transaction as the real comment/repost/message, after validation.
const s=require('./store');
const actions={COMMENT:{inventory:'commentTickets',error:'COMMENT_TICKET_REQUIRED'},REPOST:{inventory:'repostTickets',error:'REPOST_TICKET_REQUIRED'},SHARE:{inventory:'shareTickets',error:'SHARE_TICKET_REQUIRED'}};
function Consume(p,kind,postId,reference){
 const action=actions[kind];if(!action)s.Fail('INPUT_INVALID');
 const inventory=require('./customization').Inventory(p);
 if(inventory[action.inventory]<1)s.Fail(action.error);
 p.inventoryRevision=s.DB().revision+1;
 p.inventory={...(p.inventory||{}),[action.inventory]:inventory[action.inventory]-1};
 const id=s.Id('USE');s.DB().socialUses[id]={id,accountId:p.id,kind,postId,reference,at:Date.now()};
 return id;
}
module.exports={Consume};
