[@@@warning "-4-40-41-42"]
module G=Scanned_gateway_dependencies
let prepare ?observe_read bridge ~call_site boundary=
 G.gateway216 ?observe_read bridge ~handler:(K216_complete.handler bridge) ~call_site boundary
let eligible bridge ~call_site boundary=
 match prepare bridge ~call_site boundary with
 |_->true
 |exception G.Outside_scope _->false
 |exception Invalid_argument text when List.mem text[
  "k216 complete: entry/frame";"k216 complete: software continuation";
  "k216 nested front: hardware/software ancestry";
  "k216 +6792 front: entry/stack";"k216 +6792 front: table index";
  "k216 +6792 front: unproved other selector arm";
  "k216 nested front: unproved carry-clear +66A0 route";
  "k216 return-side: sentinel/code/frame alias";
  "k27 segments: unproved +2303 carry-set route";
  "k27 extended prefix: unproved k27 +36E0 error branch";
  "k27 extended prefix: unproved k27 nonzero AE04";
  "k27 extended prefix: unproved k27 index6 publication";
  "selected k84: unsupported non1 software selector";
  "selected k84: unproved nonzero mapped high byte";
  "selected k84: unproved matched table arm";
  "selected k84: unproved wrapped scan";
  "selected k84: unproved +3731 error branch";
  "selected k84: unproved +375D diagnostic branch";
  "selected k84: own frame/code/table alias";
  "k123 +75CE: unsupported output state";
  "k123 +73A7: inherited output scope";
  "k123 +785C: pointer, output or alias scope";
  "k123 +77CC: active pointer/stack alias"]->false
