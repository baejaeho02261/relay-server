"use strict";
const fs=require('node:fs'),tls=require('node:tls'),crypto=require('node:crypto');
function Pem(file){if(typeof file!=='string'||!require('node:path').isAbsolute(file))throw Error('SERVER_PEER_PEM_PATH');return require("../storage/peace.durable-file").ReadRegular(file,262144);}
const Digest=raw=>crypto.createHash('sha512').update(new crypto.X509Certificate(raw).publicKey.export({format:'der',type:'spki'})).digest('hex');
function Pin(value){if(typeof value!=='string'||!/^[a-f0-9]{128}$/.test(value))throw Error('SERVER_PEER_PIN_INVALID');return value;}
function Same(a,b){return typeof a==='string'&&typeof b==='string'&&a.length===b.length&&crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));}
function Peer(socket,pin){return !!socket?.authorized&&!!socket.getPeerCertificate()?.raw&&Same(Digest(socket.getPeerCertificate().raw),Pin(pin));}
function Client({ca,cert,key,pin}){Pin(pin);return {ca:Pem(ca),cert:Pem(cert),key:Pem(key),minVersion:'TLSv1.2',rejectUnauthorized:true,agent:false,
 checkServerIdentity(host,cert){const e=tls.checkServerIdentity(host,cert);if(e)return e;try{if(!Same(Digest(cert.raw),pin))return Error('SERVER_PEER_PIN_MISMATCH');}catch(_){return Error('SERVER_PEER_CERT_INVALID');}}
 };}
function Server({ca,cert,key}){return {ca:Pem(ca),cert:Pem(cert),key:Pem(key),minVersion:'TLSv1.2',requestCert:true,rejectUnauthorized:true,handshakeTimeout:5000};}
function Endpoint(raw){let u;try{u=new URL(raw);}catch(_){throw Error('SERVER_PEER_URL_INVALID');}if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('SERVER_PEER_URL_INVALID');return u;}
module.exports={Pem,Pin,Digest,Same,Peer,Client,Server,Endpoint};
