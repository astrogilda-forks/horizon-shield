// make_pinned.mjs : builds the pinned edge bundles in pinned/fixtures/. These are the rules VERIFIER.md section 5 (and
// the clarified steps) pin from the 2026-10-12 triage, S1 to S12: each bundle is validly signed and reaches exactly one
// rule. Keys are fresh on every run, so running this again writes different bytes; the committed fixtures are the
// frozen ones, and pinned/expected.json holds the verdict signature both reference verifiers (npm and PyPI) gave on
// them. Rebuild only to add cases, then run pin_expected.py, which refuses to write a signature the two disagree on.
//   node make_pinned.mjs && python3 pin_expected.py
import { mkdirSync, writeFileSync } from "node:fs";
import { evidenceId } from "../task-delegation-bind-v0/bind.mjs";
import { newAgentKey, signObservation, signEdge } from "../task-delegation-bind-v0/sign.mjs";
import { grantRef, receiptId, actionBinding } from "../task-execution-bind-v0/bind_exec.mjs";
import { signGrant, signReceipt } from "../task-execution-bind-v0/sign_exec.mjs";
import { intentId, signIntent } from "../task-execution-bind-v0/preflight.mjs";
import { didKeyEncode, rawFromKeyObject } from "../task-delegation-bind-v0/verify_fixture.mjs";
const REF="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ACTION={tool:"a2a.invoke",target:"/task",args_sha256:"x"};
function did(){const k=newAgentKey();return {k,id:didKeyEncode(rawFromKeyObject(k.publicKey))};}
const A=did(),B=did(),C=did(),W1=did(),W2=did();const P={};for(const x of [A,B,C,W1,W2])P[x.id]=x.k.privateKey;
const T="task_pinned";
function mk(o={}){
  const g={schema:"task-execution-bind-v0/grant",task_id:T,action:o.gaction===undefined?ACTION:o.gaction,caller_id:(o.selfauth?B:A).id,provider_id:o.provider===undefined?B.id:o.provider,nonce:"n",not_before:o.nb===undefined?"2026-10-04T00:00:00Z":o.nb,not_after:o.na===undefined?"2026-10-04T01:00:00Z":o.na};
  if(o.delprov) delete g.provider_id; if(o.delnb) delete g.not_before;
  g.grant_ref=grantRef(g); const grant=signGrant(g,(o.selfauth?B:A).k.privateKey);
  const r={schema:"task-execution-bind-v0/receipt",task_id:T,grant_ref:grant.grant_ref,executed_action:o.raction===undefined?ACTION:o.raction,outcome:{status:"completed",result_sha256:"r"},provider_id:B.id,executed_at:o.at===undefined?"2026-10-04T00:30:00Z":o.at};
  if(o.ev!==undefined) r.outcome.evidence=o.ev; else r.outcome.evidence={kind:"ledger_record",ref:REF,system:"s"};
  if(o.delat) delete r.executed_at; if(o.outcome!==undefined) r.outcome=o.outcome; if(o.ab!==undefined) r.action_binding=o.ab;
  r.receipt_id=receiptId(r); const receipt=signReceipt(r,B.k.privateKey);
  const ob=(x)=>{const q={task_id:T,hop:{seq:x.seq,from:x.from,to:x.to},prev_evidence_id:x.prev===undefined?null:x.prev,conduct:{verdict:x.v,detail_ref:x.ref===undefined?null:x.ref},witness_id:x.w,observed_at:"2026-10-04T00:30:00Z"}; if(x.delprev) delete q.prev_evidence_id; if(x.delv) delete q.conduct.verdict; if(x.mod) x.mod(q); q.evidence_id=evidenceId(q); return signEdge(signObservation(q,P[x.w]),P[x.from]);};
  const h0=ob({seq:o.seq0===undefined?0:o.seq0,from:A.id,to:B.id,w:W1.id,v:"pass",ref:o.linkfn?o.linkfn(receipt.receipt_id):(o.link===undefined?"nenrin-exec://"+receipt.receipt_id:o.link),delprev:o.delprev,delv:o.delv,mod:o.mod0});
  const extra=[]; if(o.w2){const x=o.w2; extra.push(ob({seq:0,from:A.id,to:B.id,w:W2.id,v:x.v,ref:"nenrin-exec://"+receipt.receipt_id,delv:x.delv}));}
  const h1=ob({seq:1,from:B.id,to:C.id,w:W2.id,v:"pass",prev:h0.evidence_id});
  const b={task_id:T,observations:[h0,...extra,h1],grant,receipt};
  if(o.intent){const i={schema:"task-execution-bind-v0/intent",task_id:T,grant_ref:grant.grant_ref,proposed_action:o.iaction===undefined?ACTION:o.iaction,provider_id:B.id,declared_at:o.dat===undefined?"2026-10-04T00:20:00Z":o.dat}; i.intent_id=intentId(i); b.intent=signIntent(i,B.k.privateKey);}
  return b;
}
const OUT=[];const add=(name,intent,o,f)=>{const b=mk(o);if(f)f(b);OUT.push({name,intent,bundle:b});};
const up=(rec,key)=>{const ab=actionBinding(rec[key]);ab.digest=Object.assign({},ab.digest,{value:ab.digest.value.toUpperCase()});return ab;};
const nosig=b=>{b.require_signatures=false;};
add("s00_base","the clean bundle every case below changes in one place",{});
add("s01_open_grant_null_with_receipt","S1: grant.provider_id null with a receipt: open_grant with execution_unreconciled (step 2d)",{provider:null});
add("s01_open_grant_absent_with_receipt","S1: grant.provider_id absent, the same as null (section 5)",{delprov:true});
add("s01_open_grant_intent_only","S1: open grant with an intent and no receipt: open_grant with execution_incomplete_pair",{provider:null,intent:true},b=>{delete b.receipt;});
add("s02_r1_witness_and_from_missing_nosig","S2: witness_id and hop.from both missing are equal, R1 fails",{mod0:q=>{delete q.witness_id;delete q.hop.from;}},nosig);
add("s02_r1_witness_missing_from_null_nosig","S2: missing differs from null, R1 passes",{mod0:q=>{delete q.witness_id;q.hop.from=null;}},nosig);
add("s02_r1_both_null_nosig","S2: witness_id null and hop.from null are equal, R1 fails",{mod0:q=>{q.witness_id=null;q.hop.from=null;}},nosig);
add("s02_r1_witness_and_to_missing_nosig","S2: witness_id and hop.to both missing are equal, R1 fails",{mod0:q=>{delete q.witness_id;delete q.hop.to;}},nosig);
add("s03_abind_lower_grant","S3: a correct lowercase action_binding on the grant changes nothing",{},b=>{b.grant.action_binding=actionBinding(b.grant.action);});
add("s03_abind_upper_grant","S3: uppercase digest on the grant is action_binding_mismatch",{},b=>{b.grant.action_binding=up(b.grant,"action");});
add("s03_abind_upper_receipt","S3: uppercase digest on the receipt is action_binding_mismatch",{},b=>{b.receipt.action_binding=up(b.receipt,"executed_action");});
add("s03_abind_upper_intent","S3: uppercase digest on the intent is action_binding_mismatch under preflight_invalid",{intent:true},b=>{b.intent.action_binding=up(b.intent,"proposed_action");});
add("s04_window_zero_width","S4: not_before = not_after = executed_at is inside the window",{nb:"2026-10-04T00:30:00Z",na:"2026-10-04T00:30:00Z",at:"2026-10-04T00:30:00Z"});
add("s04_window_inverted","S4: not_before after not_after holds no instant (outside_authorization_window)",{nb:"2026-10-04T00:30:01Z",na:"2026-10-04T00:30:00Z",at:"2026-10-04T00:30:00Z"});
add("s05_intent_declared_after_exec","S5: declared_at after executed_at is not checked",{intent:true,dat:"2026-10-04T00:40:00Z"});
add("s06_obs_reversed","S6: the order of observations changes no code",{},b=>{b.observations.reverse();});
add("s06_obs_duplicate_h0","S6: an observation presented twice adds nothing",{},b=>{b.observations.splice(1,0,JSON.parse(JSON.stringify(b.observations[0])));});
add("s07_outcome_array","S7: an array outcome means E is absent",{outcome:[]});
add("s07_outcome_string","S7: a string outcome means E is absent",{outcome:"done"});
add("s08_evidence_kind_other","S8: a kind outside the closed list is evidence_invalid",{ev:{kind:"ledger_recordx",ref:REF,system:"s"}});
add("s09_link_upper_hex","S9: the real receipt_id in uppercase is linkage_receipt_mismatch",{linkfn:id=>"nenrin-exec://"+id.toUpperCase()});
add("s09_link_upper_prefix","S9: an uppercase prefix is not a link (no_digest_link)",{linkfn:id=>"NENRIN-EXEC://"+id});
add("s10_raction_nfd_vs_nfc","S10: NFC against NFD is action_diverged, no normalization",{gaction:{tool:"café"},raction:{tool:"café"}});
add("s12_r4_both_missing","S12: two missing verdicts at one seq are one value",{delv:true,w2:{delv:true}});
add("s12_r4_missing_vs_pass","S12: missing against pass disagrees",{delv:true,w2:{v:"pass"}});
add("s12_r4_missing_vs_null","S12: missing against null disagrees",{delv:true,w2:{v:null}});
add("s12_r4_int_vs_string","S12: 1 against \"1\" disagrees",{mod0:q=>{q.conduct.verdict=1;},w2:{v:"1"}});
add("s12_r4_int_vs_int","S12: 1 against 1 agrees",{mod0:q=>{q.conduct.verdict=1;},w2:{v:1}});
add("s12_r4_null_vs_null","S12: null against null agrees",{mod0:q=>{q.conduct.verdict=null;},w2:{v:null}});
add("s12_r4_object_vs_object","S12: equal object verdicts still disagree (identity, the known weakness in section 5)",{mod0:q=>{q.conduct.verdict={};},w2:{v:{}}});
mkdirSync(new URL("./pinned/fixtures/",import.meta.url),{recursive:true});
for(const c of OUT) writeFileSync(new URL("./pinned/fixtures/"+c.name+".json",import.meta.url),JSON.stringify(c.bundle,null,2)+"\n");
writeFileSync(new URL("./pinned/cases.json",import.meta.url),JSON.stringify(OUT.map(c=>({name:c.name,intent:c.intent})),null,2)+"\n");
console.log("wrote "+OUT.length+" pinned bundles to pinned/fixtures/");
