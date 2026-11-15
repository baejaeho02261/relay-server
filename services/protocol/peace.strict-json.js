'use strict';
// Reject ambiguous JSON BEFORE ordinary JSON.parse can discard duplicate keys.
const {TextDecoder}=require('node:util');
const utf8=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
function Parse(input,{maxBytes=1024*1024,maxDepth=32,maxNodes=32768}={}){
 let text;if(typeof input==='string'){if(Buffer.byteLength(input)>maxBytes)throw Error('JSON_SIZE');text=input;}
 else {if(!(input instanceof Uint8Array)||input.byteLength>maxBytes)throw Error('JSON_SIZE');text=utf8.decode(input);}
 let i=0,nodes=0;
 function bad(code='JSON_INVALID'){throw Error(code);}
 function ws(){while(i<text.length&&/[ \t\r\n]/.test(text[i]))i++;}
 function scalar(s){for(let j=0;j<s.length;j++){const c=s.charCodeAt(j);if(c>=0xd800&&c<=0xdbff){const next=s.charCodeAt(++j);if(!(next>=0xdc00&&next<=0xdfff))bad('JSON_UNICODE');}else if(c>=0xdc00&&c<=0xdfff)bad('JSON_UNICODE');}return s;}
 function string(){const start=i;if(text[i++]!=='"')bad();let escaped=false;while(i<text.length){const c=text[i++];if(escaped){escaped=false;continue;}if(c==='\\'){escaped=true;continue;}if(c==='"'){let value;try{value=JSON.parse(text.slice(start,i));}catch(_){bad();}return scalar(value);}if(c<' ')bad();}bad();}
 function value(depth){if(depth>maxDepth)bad('JSON_DEPTH');if(++nodes>maxNodes)bad('JSON_NODES');ws();const c=text[i];
  if(c==='{'){i++;ws();const seen=new Set();if(text[i]==='}'){i++;return;}for(;;){ws();const key=string();if(seen.has(key))bad('JSON_DUPLICATE_FIELD');if(['__proto__','constructor','prototype'].includes(key))bad('JSON_RESERVED_FIELD');seen.add(key);ws();if(text[i++]!==':')bad();value(depth+1);ws();const sep=text[i++];if(sep==='}')return;if(sep!==',')bad();}}
  if(c==='['){i++;ws();if(text[i]===']'){i++;return;}for(;;){value(depth+1);ws();const sep=text[i++];if(sep===']')return;if(sep!==',')bad();}}
  if(c==='"'){string();return;}
  for(const token of ['true','false','null'])if(text.startsWith(token,i)){i+=token.length;return;}
  const match=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
  if(!match)bad();const v=Number(match[0]);if(!Number.isFinite(v)||Number.isInteger(v)&&!Number.isSafeInteger(v))bad('JSON_NUMBER_RANGE');i+=match[0].length;
 }
 value(0);ws();if(i!==text.length)bad();return JSON.parse(text);
}
function SecretEqual(a,b){const crypto=require('node:crypto');if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a),y=Buffer.from(b);try{return x.length===y.length&&crypto.timingSafeEqual(x,y);}finally{x.fill(0);y.fill(0);}}
module.exports={Parse,SecretEqual};
