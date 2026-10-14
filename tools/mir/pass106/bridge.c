/* Optional Pass106 experiment; no runtime controller linkage.
   Only fixed, reviewed MIR text is accepted. Upstream MIR errors are fatal in
   this isolated proof process; this is not an API for untrusted MIR programs. */
#include <stdint.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "mir.h"
#include "mir-gen.h"
#include "transfer_text.h"

CAMLprim value runes_mir_transfer(value input, value source, value destination, value jit) {
  CAMLparam4(input, source, destination, jit);
  CAMLlocal1(output);
  intnat src = Long_val(source), dst = Long_val(destination);
  if (caml_string_length(input) != 16 || src < 0 || src >= 8 || dst < 0 || dst >= 8)
    caml_invalid_argument("Pass106: bank width or unsupported index");
  /* No OCaml heap pointer crosses into MIR. Context and generated code have
     one synchronous call lifetime. No callbacks, exports or external symbols. */
  uint8_t bank[16], publications[2] = {0xa5, 0x5a};
  memcpy(bank, Bytes_val(input), sizeof bank);
  MIR_context_t ctx = MIR_init();
  MIR_scan_string(ctx, transfer_text);
  MIR_module_t module = DLIST_TAIL(MIR_module_t, *MIR_get_module_list(ctx));
  MIR_item_t function = DLIST_TAIL(MIR_item_t, module->items);
  MIR_load_module(ctx, module);
  int64_t status;
  if (Bool_val(jit)) {
    MIR_gen_init(ctx);
    MIR_gen_set_optimize_level(ctx, 0);
    MIR_link(ctx, MIR_set_gen_interface, NULL);
    int64_t (*fn)(void *, int64_t, int64_t, void *) =
      (int64_t (*)(void *, int64_t, int64_t, void *)) MIR_gen(ctx, function);
    status = fn(bank, src, dst, publications);
    MIR_gen_finish(ctx);
  } else {
    MIR_val_t result, args[4];
    args[0].a = bank; args[1].i = src; args[2].i = dst; args[3].a = publications;
    MIR_link(ctx, MIR_set_interp_interface, NULL);
    MIR_interp_arr(ctx, function, &result, 4, args);
    status = result.i;
  }
  MIR_finish(ctx);
  if (status != 0) caml_failwith("Pass106: unexpected MIR return");
  output = caml_alloc_string(18);
  memcpy(Bytes_val(output), bank, 16);
  memcpy(Bytes_val(output) + 16, publications, 2);
  CAMLreturn(output);
}
