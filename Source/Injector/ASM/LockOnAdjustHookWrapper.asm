extern HookAction:PROC

.code

HookWrapper proc
	; Backup all the general purpose registers
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push rbp

	; Create new stack frame
	mov rbp, rsp
	mov rdi, rsp
	sub rsp, 20h

	; Copy the arguments to be passed in required registers
	mov rcx, rax ;moving first argument into rcx , to be passed to function

	push rcx
	
	; Call our func
	call HookAction

	pop rcx

	mov [rax], rcx
	
	; Restore the old stack frame
	mov rsp, rdi
	pop rbp
	
	; Restore the registers
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	ret
HookWrapper endp
end