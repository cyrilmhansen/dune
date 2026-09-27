(** Intel 8080 instruction T-state costs, derived from an executed step.

    This models guest CPU instruction timing only. It excludes wait states,
    interrupts between instructions, BDOS/BIOS service time, and peripherals. *)

val cost : Step.t -> int
(** T-states consumed by the instruction represented by [step]. Conditional
    CALL and RETURN costs use the observed outcome in the step. *)
