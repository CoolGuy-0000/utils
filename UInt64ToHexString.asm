;최소 버퍼 사이즈는 16 바이트 이상이여야함.

UInt64ToHexString:
    lea     r8, [rdx+15]
    mov     byte ptr [rdx+16], 0
    mov     r9, 16

	.loop:
    mov     rax, rcx
    and     eax, 0Fh
    cmp     al, 9
    ja      .letter
    add     al, '0'
    jmp     short .store

	.letter:
    add     al, 'A' - 10

	.store:
    mov     [r8], al
    dec     r8
    shr     rcx, 4
    dec     r9
    jnz     .loop

    ret

HexStringToUInt64:
    xor     rax, rax
    mov     r8, 16

	.loop:
    movzx   r9d, byte ptr [rcx]
    inc     rcx

    cmp     r9b, '9'
    jg      .check_hex

    sub     r9b, '0'
    jmp     short .accumulate

	.check_hex:
    cmp     r9b, 'F'
    jg      .done
    sub     r9b, 'A' - 10

	.accumulate:
    shl     rax, 4
    or      rax, r9

    dec     r8
    jnz     .loop

	.done:
    ret
