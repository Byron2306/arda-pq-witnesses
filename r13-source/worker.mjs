import { DurableObject } from 'cloudflare:workers';
import { handle, ingress, Ledger } from './verifier.mjs';

export class ChallengeLedger extends DurableObject {
  fetch(request) {
    return handle(request,this.env,()=>this.ledger ??= new Ledger(this.ctx.storage));
  }
}
export default {
  fetch(request,env) {
    return ingress(request,env,(req)=>env.CHALLENGE_LEDGER.getByName('r13-v2').fetch(req));
  },
};
