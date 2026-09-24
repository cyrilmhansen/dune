; Minimal CP/M .COM example for the userspace runner.
; This source documents the exact 19 bytes exercised by the integration test.
        ORG 0100H
        MVI C,09H
        LXI D,MESSAGE
        CALL 0005H
        MVI C,00H
        CALL 0005H
MESSAGE: DB 'HELLO$'
; MESSAGE is at 010DH. Encoded bytes:
; 0E 09 11 0D 01 CD 05 00 0E 00 CD 05 00 48 45 4C 4C 4F 24
