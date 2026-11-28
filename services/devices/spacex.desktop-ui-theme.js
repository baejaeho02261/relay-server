'use strict';

const registry=require('./spacex.desktop-device-registry');
const store=require('../bootstrap/spacex.desktop-bootstrap-store');

const DEFAULT=0;
const LAST_PRESET=3;
const FIRST_RGB=0x1000000;
const LAST_RGB=0x1ffffff;
const PURE_BLACK=FIRST_RGB;
const DEFAULT_FONT=0;
const LAST_FONT=4;
const ORBITRON_FONT=1;
const LAST_LOCALE=249;
function ValidVersion(version){return version===1||version===2||version===3||version===4;}
function ValidPreset(theme){return Number.isInteger(theme)&&theme>=DEFAULT&&theme<=LAST_PRESET;}
function ValidRgb(theme){return Number.isInteger(theme)&&theme>=FIRST_RGB&&theme<=LAST_RGB;}
function Valid(theme){return ValidPreset(theme)||ValidRgb(theme);}
function ValidFont(font){return Number.isInteger(font)&&font>=DEFAULT_FONT&&font<=LAST_FONT;}
function ValidAppearance(value){return Number.isInteger(value)&&value>=0&&value<=0xffff&&(value&0x88)===0&&(value>>>8)<=LAST_LOCALE;}
function Binding(row,db){return registry.State(db).bindings[registry.BindingId(row.machineId,db)];}

// Only successful native claims call this projection; clients never supply the
// binding id. New launch keys use the same registered installation preference.
function Projection(row,version){
 if(!ValidVersion(version))return {};
 const db=store.Load(),registered=Binding(row,db);
 const binding=registered?.status==='REGISTERED'?registered:undefined;
 const theme=binding?.uiTheme??(version>=2?binding?.uiThemeRgb:undefined)??(version>=3?PURE_BLACK:DEFAULT);
 if(version<3)return {theme};
 const font=binding?.uiFont??(version===4?ORBITRON_FONT:DEFAULT_FONT);
 const desktopDesign=require('./spacex.desktop-ui-design').Read(db);
 return {theme,font,desktopDesign,...(version===4?{appearance:binding?.uiAppearance??0}:{})};
}

function Write(db,row,theme,font,appearance){
 const binding=Binding(row,db);
 if(!Valid(theme)||font!==undefined&&!ValidFont(font)||
    appearance!==undefined&&(!ValidAppearance(appearance)||!ValidFont(font))||binding?.status!=='REGISTERED'){
  require('../bootstrap/spacex.desktop-bootstrap').Fail('BOOTSTRAP_SESSION_INVALID',403);
 }
 const changed=theme!==(binding.uiTheme??binding.uiThemeRgb??PURE_BLACK)||
  font!==undefined&&font!==(binding.uiFont??ORBITRON_FONT)||
  appearance!==undefined&&appearance!==(binding.uiAppearance??0);
 if(ValidPreset(theme)){
  binding.uiTheme=theme;
  delete binding.uiThemeRgb;
 }else{
  // Older servers fall back to preset 0. A subsequent preset write by an
  // older server recreates uiTheme and takes priority over the stored RGB.
  binding.uiThemeRgb=theme;
  delete binding.uiTheme;
 }
 if(font!==undefined)binding.uiFont=font;
 if(appearance!==undefined)binding.uiAppearance=appearance;
 return changed;
}

module.exports={ValidVersion,ValidPreset,ValidRgb,Valid,ValidFont,ValidAppearance,Projection,Write};
