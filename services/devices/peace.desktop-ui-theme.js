'use strict';

const registry=require('./peace.desktop-device-registry');
const store=require('../bootstrap/peace.desktop-bootstrap-store');

const DEFAULT=0;
function Valid(theme){return Number.isInteger(theme)&&theme>=0&&theme<=3;}
function Binding(row,db){return registry.State(db).bindings[registry.BindingId(row.machineId,db)];}

// Only successful native claims call this projection; clients never supply the
// binding id. New launch keys use the same registered installation preference.
function Projection(row,version){
 if(version!==1)return {};
 const binding=Binding(row,store.Load());
 return {theme:binding?.status==='REGISTERED'?binding.uiTheme??DEFAULT:DEFAULT};
}

function Write(db,row,theme){
 const binding=Binding(row,db);
 if(!Valid(theme)||binding?.status!=='REGISTERED'){
  require('../bootstrap/peace.desktop-bootstrap').Fail('BOOTSTRAP_SESSION_INVALID',403);
 }
 binding.uiTheme=theme;
}

module.exports={Valid,Projection,Write};
