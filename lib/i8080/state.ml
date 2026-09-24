type t = {
  mutable a : int;
  mutable b : int;
  mutable c : int;
  mutable d : int;
  mutable e : int;
  mutable h : int;
  mutable l : int;
  mutable sp : int;
  mutable pc : int;
  flags : Flags.t;
}

let create () =
  {
    a = 0;
    b = 0;
    c = 0;
    d = 0;
    e = 0;
    h = 0;
    l = 0;
    sp = 0;
    pc = 0;
    flags = Flags.create ();
  }

let check_range name maximum value =
  if value < 0 || value > maximum then invalid_arg name

let byte name value = check_range name 0xff value
let word name value = check_range name 0xffff value

let a state = state.a
let b state = state.b
let c state = state.c
let d state = state.d
let e state = state.e
let h state = state.h
let l state = state.l
let sp state = state.sp
let pc state = state.pc

let set_a state value =
  byte "State.set_a" value;
  state.a <- value

let set_b state value =
  byte "State.set_b" value;
  state.b <- value

let set_c state value =
  byte "State.set_c" value;
  state.c <- value

let set_d state value =
  byte "State.set_d" value;
  state.d <- value

let set_e state value =
  byte "State.set_e" value;
  state.e <- value

let set_h state value =
  byte "State.set_h" value;
  state.h <- value

let set_l state value =
  byte "State.set_l" value;
  state.l <- value

let set_sp state value =
  word "State.set_sp" value;
  state.sp <- value

let set_pc state value =
  word "State.set_pc" value;
  state.pc <- value

let pair high low = (high lsl 8) lor low
let bc state = pair state.b state.c
let de state = pair state.d state.e
let hl state = pair state.h state.l

let set_pair name set_high set_low state value =
  word name value;
  set_high state ((value lsr 8) land 0xff);
  set_low state (value land 0xff)

let set_bc state value = set_pair "State.set_bc" set_b set_c state value
let set_de state value = set_pair "State.set_de" set_d set_e state value
let set_hl state value = set_pair "State.set_hl" set_h set_l state value

let flags state = state.flags
