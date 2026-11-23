'use strict';

const registry=require('./peace.desktop-device-registry');
const store=require('../bootstrap/peace.desktop-bootstrap-store');

const DEFAULT=0;
const LAST_PRESET=3;
const FIRST_RGB=0x1000000;
const LAST_RGB=0x1ffffff;
function ValidVersion(version){return version===1||version===2;}
function ValidPreset(theme){return Number.isInteger(theme)&&theme>=DEFAULT&&theme<=LAST_PRESET;}
function ValidRgb(theme){return Number.isInteger(theme)&&theme>=FIRST_RGB&&theme<=LAST_RGB;}
function Valid(theme){return ValidPreset(theme)||ValidRgb(theme);}
function Binding(row,db){return registry.State(db).bindings[registry.BindingId(row.machineId,db)];}

// Only successful native claims call this projection; clients never supply the
// binding id. New launch keys use the same registered installation preference.
function Projection(row,version){
 if(!ValidVersion(version))return {};
 const binding=Binding(row,store.Load());
 if(binding?.status!=='REGISTERED')return {theme:DEFAULT};
 return {theme:binding.uiTheme??(version===2?binding.uiThemeRgb:undefined)??DEFAULT};
}

function Write(db,row,theme){
 const binding=Binding(row,db);
 if(!Valid(theme)||binding?.status!=='REGISTERED'){
  require('../bootstrap/peace.desktop-bootstrap').Fail('BOOTSTRAP_SESSION_INVALID',403);
 }
 if(ValidPreset(theme)){
  binding.uiTheme=theme;
  delete binding.uiThemeRgb;
 }else{
  // Older servers fall back to preset 0. A subsequent preset write by an
  // older server recreates uiTheme and takes priority over the stored RGB.
  binding.uiThemeRgb=theme;
  delete binding.uiTheme;
 }
}

module.exports={ValidVersion,ValidPreset,ValidRgb,Valid,Projection,Write};
