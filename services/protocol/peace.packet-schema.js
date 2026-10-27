'use strict';
// Shape/version/range admission is shared with Delphi. This never substitutes
// for current session, signature, expiry, role or nested domain authorization.
const generated=require('./peace.packet-schema.generated'),strict=require('./peace.strict-json');
const schema=generated.schema,plain=v=>!!v&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype;
const commands=new Map(schema.commands.map(c=>[c.operation+':'+c.action,c.body]));
function Invalid(){throw Error('PROTOCOL_SCHEMA_INVALID');}
function Validate(node,value,depth=0){
 if(depth>32)Invalid();
 if(node.$ref)return Validate(schema.definitions[node.$ref],value,depth+1);
 if(node.enum&&!node.enum.some(x=>typeof x===typeof value&&x===value))Invalid();
 if(node.type==='string'){
  if(typeof value!=='string'||node.minLength!==undefined&&value.length<node.minLength||node.maxLength!==undefined&&value.length>node.maxLength||node.maxBytes!==undefined&&Buffer.byteLength(value,'utf8')>node.maxBytes)Invalid();
  if(node.pattern){const m=new RegExp(node.pattern).exec(value);if(!m||m.index!==0||m[0].length!==value.length)Invalid();}
 }else if(node.type==='integer'){
  if(!Number.isSafeInteger(value)||value<node.minimum||value>node.maximum)Invalid();
 }else if(node.type==='array'){
  if(!Array.isArray(value)||value.length>node.maxItems)Invalid();for(const v of value)Validate(node.items,v,depth+1);
 }else if(node.type==='object'){
  if(!plain(value))Invalid();
  if(node.properties){for(const key of Object.keys(value)){if(!Object.hasOwn(node.properties,key))Invalid();Validate(node.properties[key],value[key],depth+1);}for(const key of node.required)if(!Object.hasOwn(value,key))Invalid();}
  if(node.allOrNone){const n=node.allOrNone.filter(k=>Object.hasOwn(value,k)).length;if(n!==0&&n!==node.allOrNone.length)Invalid();}
  if(node.exactlyOne&&node.exactlyOne.filter(k=>Object.hasOwn(value,k)).length!==1)Invalid();
 }
 return value;
}
function ValidateRequest(operation,body){const rule=commands.get(operation+':'+body?.action);if(!rule)Invalid();Validate(rule,body);return body;}
function ValidateEnvelope(value){Validate(schema.envelope,value);ValidateRequest(value.operation,value.body);return value;}
function ParseRequest(input,{maxBytes=schema.maximumRequestBytes}={}){if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>schema.maximumRequestBytes)Invalid();return ValidateEnvelope(strict.Parse(input,{maxBytes}));}
module.exports={ValidateRequest,ValidateEnvelope,ParseRequest,sha512:generated.sha512,version:schema.schemaVersion,maximumRequestBytes:schema.maximumRequestBytes};
