BITS 64

push rax

; address of a global writable variable which is used to know if we have already ran the shellcode
mov rax, 0x1111111111111111
lock xchg rax, [rax]

; if the original content, we have already ran the shellcode, so skip it
cmp rax, 0
jne finished_running_shellcode

; run the shellcode
push rbx
push rcx
push rdx
push rbp
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

; address of the shellcode
mov rax, 0x2222222222222222
call rax

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
pop rbp
pop rdx
pop rcx
pop rbx

finished_running_shellcode:


; address of the trampoline
mov rax, 0x3333333333333333

; restore rax and write the trampoline address to the stack 
xchg rax, [rsp]

ret

