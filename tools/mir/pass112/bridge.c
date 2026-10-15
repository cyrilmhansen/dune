/* Optional semantic experiment. Fixed reviewed MIR only; no runtime linkage.
   Rejections precede context creation. MIR errors remain process-fatal in this
   isolated proof executable, as in Pass106; no untrusted MIR is accepted. */
#include <stdint.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include "mir.h"
#include "mir-gen.h"
#include "mod_text.h"

/* Pass113 reuses this exact lifecycle with a signed-domain build. Defaults
   retain Pass112's public symbol and rejection domain. */
#ifdef RUNES_SIGNED_MOD
#define RUNES_MOD_MIN -32768
#define RUNES_MOD_ENTRY runes_mir_mod_signed
#define RUNES_MOD_LABEL "Pass113"
#else
#define RUNES_MOD_MIN 0
#define RUNES_MOD_ENTRY runes_mir_mod_positive
#define RUNES_MOD_LABEL "Pass112"
#endif
CAMLprim value RUNES_MOD_ENTRY(value numerator, value divisor, value jit) {
  CAMLparam3(numerator, divisor, jit);
  intnat a = Long_val(numerator), b = Long_val(divisor);
  if (a < RUNES_MOD_MIN || a > 32767 || (b != 3 && b != 5 && b != 15))
    caml_invalid_argument(RUNES_MOD_LABEL ": unsupported FIXED BINARY(15) MOD domain");
  /* Only semantic integer values cross the boundary. No OCaml heap pointer,
     historical scratch/stack state, callbacks or imported arithmetic helper. */
  MIR_context_t ctx = MIR_init();
  MIR_scan_string(ctx, mod_text);
  MIR_module_t module = DLIST_TAIL(MIR_module_t, *MIR_get_module_list(ctx));
  MIR_item_t function = DLIST_TAIL(MIR_item_t, module->items);
  MIR_load_module(ctx, module);
  int64_t answer;
  if (Bool_val(jit)) {
    MIR_gen_init(ctx);
    MIR_gen_set_optimize_level(ctx, 0);
    MIR_link(ctx, MIR_set_gen_interface, NULL);
    int64_t (*fn)(int64_t, int64_t) = (int64_t (*)(int64_t, int64_t)) MIR_gen(ctx, function);
    answer = fn((int64_t) a, (int64_t) b);
    MIR_gen_finish(ctx);
  } else {
    MIR_val_t result, args[2];
    args[0].i = (int64_t) a;
    args[1].i = (int64_t) b;
    MIR_link(ctx, MIR_set_interp_interface, NULL);
    MIR_interp_arr(ctx, function, &result, 2, args);
    answer = result.i;
  }
  MIR_finish(ctx);
  if (answer < 0 || answer >= b)
    caml_failwith(RUNES_MOD_LABEL ": MIR result violates the supported semantic range");
  CAMLreturn(Val_long((intnat) answer));
}
