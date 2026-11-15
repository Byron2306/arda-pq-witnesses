// This low-level primitive has no authority to decide whether a leaf may be used.
const need=(x,c)=>{if(!x)throw Error(c);};
const prefix=new Uint8Array([0,0,0,1,0,0,0,6,0,0,0,4]);
export class HssEngine {
 constructor(module){this.module=module;}
 static async fromBytes(bytes){return new HssEngine(await WebAssembly.compile(bytes));}
 async instance(){
  for(const i of WebAssembly.Module.imports(this.module))need((i.module==='env'&&i.name==='random_fill')||
    (i.module==='wasi_snapshot_preview1'&&['proc_exit','fd_write','fd_close','fd_seek'].includes(i.name)),'WASM_IMPORT_REFUSED');
  let instance;
  const trap=()=>{throw Error('HSS_WASM_TRAP');};
  instance=await WebAssembly.instantiate(this.module,{env:{random_fill:(ptr,n)=>{
    need(Number.isInteger(ptr)&&Number.isInteger(n)&&n>0&&n<=65536&&ptr>=0&&ptr+n<=instance.exports.memory.buffer.byteLength,'RNG_BOUNDS');
    crypto.getRandomValues(new Uint8Array(instance.exports.memory.buffer,ptr,n));return 1;
  }},wasi_snapshot_preview1:{proc_exit:trap,fd_write:trap,fd_close:trap,fd_seek:trap}});
  instance.exports._initialize?.();return instance;
 }
 leaf(state){need(state instanceof Uint8Array&&state.length===64,'HSS_STATE_SIZE');const n=new DataView(state.buffer,state.byteOffset,8).getBigUint64(0);
  need(n<=1024n,'HSS_STATE_COUNTER');return Number(n);}
 async generate(){const i=await this.instance();const x=i.exports;
  try {need(x.arda_generate()===1,'HSS_KEYGEN_REFUSED');const memory=x.memory.buffer;
   return {privateState:new Uint8Array(memory,x.arda_private_ptr(),64).slice(),publicKey:new Uint8Array(memory,x.arda_public_ptr(),60).slice()};
  }finally{x.arda_clear();}
 }
 async sign(state,pub,message){need(state instanceof Uint8Array&&state.length===64&&this.leaf(state)<1024,'HSS_STATE_REFUSED');
  need(pub instanceof Uint8Array&&pub.length===60&&prefix.every((n,i)=>pub[i]===n),'HSS_PUBLIC_KEY');
  need(message instanceof Uint8Array&&message.length>0&&message.length<=16384,'HSS_MESSAGE');
  const i=await this.instance(),x=i.exports;
  try {new Uint8Array(x.memory.buffer,x.arda_private_ptr(),64).set(state);
   new Uint8Array(x.memory.buffer,x.arda_public_ptr(),60).set(pub);new Uint8Array(x.memory.buffer,x.arda_message_ptr(),message.length).set(message);
   need(x.arda_sign(message.length)===1,'HSS_SIGN_REFUSED');
   const signature=new Uint8Array(x.memory.buffer,x.arda_signature_ptr(),1456).slice(),privateState=new Uint8Array(x.memory.buffer,x.arda_private_ptr(),64).slice();
   return {signature,privateState,leaf:new DataView(signature.buffer).getUint32(4)};
  }finally{x.arda_clear();}
 }
}
