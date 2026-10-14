[@@@warning "-4-40-41-42"]
module G=Scanned_gateway_dependencies
let prepare ?observe_read bridge ~call_site boundary=
 G.gateway27 ?observe_read bridge ~handler:(K27_k84_composition.prefix ~complete:true bridge) ~call_site boundary
let eligible bridge ~call_site boundary=
 match prepare bridge ~call_site boundary with
 |_->true
 |exception G.Outside_scope _->false
 |exception Invalid_argument text when List.mem text[
  "k27 segments: entry/frame";"k27 segments: software continuation";
  "k27 segments: unproved +2303 carry-set route";
  "k27 extended prefix: unproved k27 +36E0 error branch";
  "k27 extended prefix: unproved k27 nonzero AE04";
  "k27 extended prefix: unproved k27 index6 publication"]->false
