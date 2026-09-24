'use strict';
const s=require('./store');
// Private wallet projection, independent of any discontinued game feature.
function Read(p){return {accountId:p.id,revision:s.DB().revision,balance:p.balance,points:p.points||0,eventSpins:p.eventSpins||0};}
module.exports={Read};
