"use strict";
const tls=require("../../services/network/peace.server-peer-tls"),net=require('node:net');
function Origin(req,env=process.env){
 if(env.WEB_ADMIN_GATEWAY!=='1')return null;
 let valid=false,ip='';try{valid=tls.Peer(req.socket,env.WEB_ADMIN_CLIENT_SPKI_SHA512);ip=req.headers['x-game-client-ip'];valid=valid&&typeof ip==='string'&&!!net.isIP(ip)&&req.headers['x-game-client-proto']==='https'&&req.headers.host===new URL(env.WEBAUTHN_ORIGIN).host;}catch(_){}
 return {https:!!valid,ip:valid?ip:'INVALID_GATEWAY',trusted:!!valid};
}
module.exports={Origin};
