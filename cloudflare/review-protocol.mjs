// Python ensure_ascii canonical JSON, including lexicographically sorted PCR keys.
export {need,sha,hex64} from './hss-guard.mjs';
import {need} from './hss-guard.mjs';
const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
export const text=bytes=>decoder.decode(bytes);
export function canonicalProtocol(value){
 const encode=(v,depth)=>{
  need(depth<=24,'JSON_DEPTH');
  if(v===null||typeof v==='boolean')return JSON.stringify(v);
  if(typeof v==='number'){need(Number.isSafeInteger(v)&&!Object.is(v,-0),'JSON_INTEGER');return JSON.stringify(v);}
  if(typeof v==='string')return JSON.stringify(v).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
  if(Array.isArray(v)){need(v.length<=1024,'JSON_ARRAY');return '['+v.map(x=>encode(x,depth+1)).join(',')+']';}
  need(v&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype,'JSON_OBJECT');
  need(Object.keys(v).length<=1024,'JSON_FIELDS');return '{'+Object.keys(v).sort().map(k=>encode(k,depth+1)+':'+encode(v[k],depth+1)).join(',')+'}';
 };return encoder.encode(encode(value,0));
}
export function exact(value,fields,code){need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===fields.length&&fields.every(k=>Object.hasOwn(value,k)),code);}
export function equal(a,b){return a.length===b.length&&a.every((v,i)=>v===b[i]);}
export function parseCanonical(raw,cap){need(raw instanceof Uint8Array&&raw.length>0&&raw.length<=cap,'BODY_SIZE');const x=JSON.parse(text(raw));need(equal(raw,canonicalProtocol(x)),'JSON_CANONICAL');return x;}
export function unbase64(value,cap){need(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(cap/3)*4,'BASE64_SIZE');const x=Uint8Array.from(atob(value),c=>c.charCodeAt(0));need(x.length>0&&x.length<=cap&&btoa(String.fromCharCode(...x))===value,'BASE64_ENCODING');return x;}
export function message(domain,value){const d=encoder.encode(domain+'\0'),body=canonicalProtocol(value),out=new Uint8Array(d.length+body.length);out.set(d);out.set(body,d.length);return out;}
export function window(value,now,maximum){need(Number.isSafeInteger(now)&&now>0&&Number.isSafeInteger(value.issued_at)&&Number.isSafeInteger(value.expires_at)&&0<value.issued_at&&value.issued_at<=now&&now<value.expires_at&&value.expires_at-value.issued_at<=maximum,'TIME_WINDOW');}
export const snapshot=value=>JSON.parse(text(canonicalProtocol(value)));
