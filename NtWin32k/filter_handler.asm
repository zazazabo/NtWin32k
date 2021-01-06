extern hook_handler : proc
.code
asm_hook_handler_2004 proc
	lea rdx, [rsp+58h]  ; rcx is the syscall number...
						; rdx is a pointer to arguments...
	call hook_handler
	cmp rax, 1
	je sysreturn

	xor rax, rax		; always return false...
	ret
sysreturn:
	add rsp, 80h
	mov rax, 00C0FFEEh	; return back to usermode with 0xC0FFEE as result...
	ret
asm_hook_handler_2004 endp

; stack distance to arguments is different on older versions of windows...
asm_hook_handler proc
	lea rdx, [rsp + 28h]
	call hook_handler
	cmp rax, 1
	je sysreturn

	xor rax, rax
	ret
sysreturn:
	add rsp, 50h
	mov rax, 00C0FFEEh
	ret
asm_hook_handler endp
end