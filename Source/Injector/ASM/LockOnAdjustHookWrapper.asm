extern HookAction:PROC

.code

HookWrapper proc
	; Backup all the general purpose registers
    sub     rsp, 10h
    movdqu  [rsp], xmm0
    sub     rsp, 10h
    movdqu  [rsp], xmm1
    sub     rsp, 10h
    movdqu  [rsp], xmm2
    sub     rsp, 10h
    movdqu  [rsp], xmm3
    push    rax
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r10
    push    r11
    sub     rsp, 28h

	; Copy the arguments to be passed in required registers
	mov rcx, rax ;moving first argument into rcx , to be passed to function

	push rcx
	
	; Call our func
	call HookAction

	pop rcx

	mov [rax], rcx
	
	; Restore the registers
    add     rsp, 28h
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     rax
    movdqu  xmm3, [rsp]
    add     rsp, 10h
    movdqu  xmm2, [rsp]
    add     rsp, 10h
    movdqu  xmm1, [rsp]
    add     rsp, 10h
    movdqu  xmm0, [rsp]
    add     rsp, 10h

	ret
HookWrapper endp


end