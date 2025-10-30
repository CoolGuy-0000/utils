
SECTION .text

HOOK_HookRoutine       equ 0x00
HOOK_OriginalAddress   equ 0x08
HOOK_ReturnAddress     equ 0x10
HOOK_HookMain          equ 0x18
HOOK_CallerRetAddress  equ 0x20

HOOK_rsp               equ 0x28
HOOK_rbp               equ 0x30

HOOK_rcx               equ 0x38
HOOK_rdx               equ 0x40
HOOK_r8                equ 0x48
HOOK_r9                equ 0x50

HOOK_align0            equ 0x58     ; padding 8 bytes

HOOK_Xmm0              equ 0x60
HOOK_Xmm1              equ 0x70
HOOK_Xmm2              equ 0x80
HOOK_Xmm3              equ 0x90

HOOK_BackupCode        equ 0xA0     ; size 0x10
HOOK_ExitCode          equ 0xB0     ; size 0x10
HOOK_BackupSize        equ 0xC0
HOOK_bHandled          equ 0xC4
HOOK_RetValue          equ 0xC8
HOOK_StackUsage        equ 0xD0
HOOK_bSTDCALL          equ 0xD4

;return value must be CGHookObject itself !!
CGHookRoutineEnd:
	mov rsp, [rax + HOOK_rsp]
	mov rbp, [rax + HOOK_rbp]
	mov rcx, [rax + HOOK_rcx]
	mov rdx, [rax + HOOK_rdx]
	mov r8,  [rax + HOOK_r8]
	mov r9,  [rax + HOOK_r9]
	movdqu xmm0, [rax + HOOK_Xmm0]
	movdqu xmm1, [rax + HOOK_Xmm1]
	movdqu xmm2, [rax + HOOK_Xmm2]
	movdqu xmm3, [rax + HOOK_Xmm3]
	
	push rdi
	mov rdi, [rax + HOOK_CallerRetAddress]
	mov [rsp+8], rdi

	mov edi, [rax + HOOK_bHandled]
	test edi, edi
	jnz .handled

	pop rdi
	lea rax, [rax + HOOK_BackupCode]
	jmp rax

.handled:
	pop rdi

	mov ecx, [rax + HOOK_bSTDCALL]
	test ecx, ecx
	jnz .stdcall
	mov rax, [rax + HOOK_RetValue]
	ret

.stdcall:
	mov rcx, [rsp]
	xor rdx, rdx
	mov edx, [rax + HOOK_StackUsage]
	add rsp, rdx
	add rsp, 8
	mov rax, [rax + HOOK_RetValue]
	jmp rcx

global CGHookRoutine
CGHookRoutine:
	push rdi
	mov rdi, [rsp+8]
	mov [rax + HOOK_CallerRetAddress], rdi
	mov rdi, CGHookRoutineEnd
	mov qword [rsp+8], rdi
	pop rdi

	mov [rax + HOOK_rsp], rsp
	mov [rax + HOOK_rbp], rbp
	mov [rax + HOOK_rcx], rcx
	mov [rax + HOOK_rdx], rdx
	mov [rax + HOOK_r8], r8
	mov [rax + HOOK_r9], r9

	movdqu [rax + HOOK_Xmm0], xmm0
	movdqu [rax + HOOK_Xmm1], xmm1
	movdqu [rax + HOOK_Xmm2], xmm2
	movdqu [rax + HOOK_Xmm3], xmm3
	

	;whatever rcx is, it must be CGHookObject !!
	mov rcx, rax
	jmp qword [rax + HOOK_HookMain] ;HookMain
