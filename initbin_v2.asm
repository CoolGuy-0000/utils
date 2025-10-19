FORMAT PE64 GUI 4.0 DLL

ENTRY code_start

section 'code' code readable writeable executable

code_start = $

	.FULL_STACK = .RegisterStack + .KERNEL32 + .BUF01
	
	.KERNEL32 = 8h
	.BUF01 = 28h
	.RegisterStack = 28h

call GetCurrentAddress
mov rbp, rax
sub rsp, .FULL_STACK

lea rdx, [rsp+.RegisterStack] ;BUF01
lea rcx, [rsp+.FULL_STACK]
call UInt64ToHexString

call GetKernelModuleHandle
mov [rsp + .RegisterStack + .BUF01], rax		;KERNEL32

lea rdx, [rbp+_str.SetEnvironmentVariableA]
mov rcx, rax
call GetProcAddress

lea rdx, [rsp+.RegisterStack]
lea rcx, [rbp+_str.CUR_RSP]
call rax

lea rdx, [rbp+_str.LoadLibraryA]
mov rcx, [rsp + .RegisterStack + .BUF01] ;KERNEL32
call GetProcAddress

lea rcx, [rbp+_str.BridgeDLL]
call rax

lea rdx, [rbp+_str.GoBack]
mov rcx, rax
call GetProcAddress

add rsp, .FULL_STACK
jmp rax

GetCurrentAddress:
mov rax, [rsp]
sub rax, 5
ret

GetKernelModuleHandle:
mov rax, [gs:60h]
mov rax, [rax+18h] ;LDR
mov rax, [rax+20h] ;InMemoryOrderModuleList
mov rax, [rax] 
mov rax, [rax]
mov rax, [rax+20h]
ret

GetProcAddress:
	arg_0 = 8
	arg_8 = 10h
	arg_10 = 18h

    mov     [rsp+arg_0], rbx
    mov     [rsp+arg_8], rbp
    mov     [rsp+arg_10], rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h
    movsxd  rax, dword ptr rcx+3Ch
    mov     rbp, rdx
    mov     rbx, rcx
    mov     edi, [rax+rcx+88h]
    mov     r14d, [rdi+rcx+1Ch]
    mov     r13d, [rdi+rcx+20h]
    add     r14, rcx
    mov     r12d, [rdi+rcx+24h]
    add     r13, rcx
    add     r12, rcx
    cmp     rdx, 0FFFFh
    ja      .CheckIfNameIsString
    sub     bp, [rdi+rcx+10h]
    movzx   eax, bp
    cmp     eax, [rdi+rcx+14h]
    jnb     .NotFound

	.ComputeFunctionAddress:
    mov     eax, [r14+rax*4]
    add     rax, rbx
    jmp     .return

	.CheckIfNameIsString:
    xor     esi, esi
    cmp     [rdi+rcx+18h], esi
    jbe     .NotFound

	.NameSearchLoop:
    mov     ecx, [r13+rsi*4+0]
    mov     rdx, rbp        ; Str2
    add     rcx, rbx        ; Str1
    call    ucrtbase_strcmp
    test    eax, eax
    jz      .NameMatched
    inc     esi
    cmp     esi, [rdi+rbx+18h]
    jb      .NameSearchLoop

	.NotFound:
    xor     eax, eax

	.return:
    mov     rbx, [rsp+48h+arg_0]
    mov     rbp, [rsp+48h+arg_8]
    mov     rsi, [rsp+48h+arg_10]
    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    retn

	.NameMatched:
    movzx   eax, word ptr r12+rsi*2
    jmp     .ComputeFunctionAddress


ucrtbase_strcmp:
	sub     rdx, rcx
	test    cl, 7
	jz      .AlignToQword

	.ByteCompareLoop:

	movzx   eax, byte ptr rcx
	cmp     al, [rdx+rcx]
	jnz     .ReturnDiff
	inc     rcx
	test    al, al
	jz      .ReturnEqual
	test    cl, 7
	jnz     .ByteCompareLoop

	.AlignToQword:                       
	mov     r11, 8080808080808080h
	mov     r10, 0FEFEFEFEFEFEFEFFh

	.QwordCompareLoop:
	lea     eax, [edx+ecx]
	and     eax, 0FFFh
	cmp     eax, 0FF8h
	ja      .ByteCompareLoop
	mov     rax, [rcx]
	cmp     rax, [rdx+rcx]
	jnz     .ByteCompareLoop
	lea     r9, [rax+r10]
	not     rax
	add     rcx, 8
	and     rax, r9
	test    r11, rax
	jz      .QwordCompareLoop

	.ReturnEqual:
	xor     eax, eax
	retn

	.ReturnDiff:
	sbb     rax, rax
	or      rax, 1
	retn

UInt64ToHexString:
    lea     r8, [rdx+15]
    mov     byte ptr rdx+16, 0
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

align 8

_str:
	.CUR_RSP = $-code_start
		DB "CUR_RSP",0,0

	.BridgeDLL = $-code_start
		DB ".\bridge.dll",0,0
	
	.GoBack = $-code_start 
		DB "GoBack",0,0

	.LoadLibraryA = $-code_start 
		DB "LoadLibraryA",0,0

	.SetEnvironmentVariableA = $-code_start
		DB "SetEnvironmentVariableA",0,0

code_size = $-code_start