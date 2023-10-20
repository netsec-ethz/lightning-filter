[bits 64]
[CPU intelnop]
 
%macro linux_setup 0
%ifdef __linux__
    mov r9, rcx
    mov r8, rdx
    mov rcx, rdi
    mov rdx, rsi
%endif
%endmacro
 
%macro inversekey 1
    movdqu  xmm1,%1
    aesimc  xmm0,xmm1
    movdqu  %1,xmm0
%endmacro
 
%macro aesenc1_u 1
    movdqu  xmm4,%1
    aesenc  xmm0,xmm4
%endmacro
 
%macro aesenclast1_u 1
    movdqu  xmm4,%1
    aesenclast  xmm0,xmm4
%endmacro
 
%macro aesenc2_u 1
    movdqu  xmm4,%1
    aesenc  xmm0,xmm4
    aesenc  xmm1,xmm4
%endmacro
 
%macro aesenclast2_u 1
    movdqu  xmm4,%1
    aesenclast  xmm0,xmm4
    aesenclast  xmm1,xmm4
%endmacro
 
%macro aesenc4_u 1
    movdqa  xmm4,%1
   
    aesenc  xmm0,xmm4
    aesenc  xmm1,xmm4
    aesenc  xmm2,xmm4
    aesenc  xmm3,xmm4
%endmacro
 
%macro aesenclast4_u 1
    movdqa  xmm4,%1
 
    aesenclast  xmm0,xmm4
    aesenclast  xmm1,xmm4
    aesenclast  xmm2,xmm4
    aesenclast  xmm3,xmm4
%endmacro
 
%macro load_and_inc4 1
    movdqa  xmm4,%1
    movdqa  xmm0,xmm5
    pshufb  xmm0, xmm6 ; byte swap counter back
    movdqa  xmm1,xmm5
    paddd   xmm1,[counter_add_one wrt rip]
    pshufb  xmm1, xmm6 ; byte swap counter back
    movdqa  xmm2,xmm5
    paddd   xmm2,[counter_add_two wrt rip]
    pshufb  xmm2, xmm6 ; byte swap counter back
    movdqa  xmm3,xmm5
    paddd   xmm3,[counter_add_three wrt rip]
    pshufb  xmm3, xmm6 ; byte swap counter back
    pxor    xmm0,xmm4
    paddd   xmm5,[counter_add_four wrt rip]
    pxor    xmm1,xmm4
    pxor    xmm2,xmm4
    pxor    xmm3,xmm4
%endmacro
 
%macro xor_with_input4 1
    movdqu xmm4,[%1]
    pxor xmm0,xmm4
    movdqu xmm4,[%1+16]
    pxor xmm1,xmm4
    movdqu xmm4,[%1+32]
    pxor xmm2,xmm4
    movdqu xmm4,[%1+48]
    pxor xmm3,xmm4
%endmacro
 
%macro load_and_xor4 2
    movdqa  xmm4,%2
    movdqu  xmm0,[%1 + 0*16]
    pxor    xmm0,xmm4
    movdqu  xmm1,[%1 + 1*16]
    pxor    xmm1,xmm4
    movdqu  xmm2,[%1 + 2*16]
    pxor    xmm2,xmm4
    movdqu  xmm3,[%1 + 3*16]
    pxor    xmm3,xmm4
%endmacro
 
%macro store4 1
    movdqu [%1 + 0*16],xmm0
    movdqu [%1 + 1*16],xmm1
    movdqu [%1 + 2*16],xmm2
    movdqu [%1 + 3*16],xmm3
%endmacro
 
%macro copy_round_keys 3
    movdqu xmm4,[%2 + ((%3)*16)]
    movdqa [%1 + ((%3)*16)],xmm4
%endmacro
 
 
%macro key_expansion_1_192 1
    ;; Assumes the xmm3 includes all zeros at this point.
    pshufd xmm2, xmm2, 11111111b        
    shufps xmm3, xmm1, 00010000b        
    pxor xmm1, xmm3        
    shufps xmm3, xmm1, 10001100b
    pxor xmm1, xmm3        
    pxor xmm1, xmm2    
    movdqu [rdx+%1], xmm1          
%endmacro
 
; Calculate w10 and w11 using calculated w9 and known w4-w5
%macro key_expansion_2_192 1               
    movdqa xmm5, xmm4
    pslldq xmm5, 4
    shufps xmm6, xmm1, 11110000b
    pxor xmm6, xmm5
    pxor xmm4, xmm6
    pshufd xmm7, xmm4, 00001110b
    movdqu [rdx+%1], xmm7
%endmacro
 
 
section .data
align 16
shuffle_mask:
DD 0FFFFFFFFh
DD 03020100h
DD 07060504h
DD 0B0A0908h
 
byte_swap_16:
DDQ 0x000102030405060708090A0B0C0D0E0F
 
 
align 16
counter_add_one:
DD 1
DD 0
DD 0
DD 0
 
counter_add_two:
DD 2
DD 0
DD 0
DD 0
 
counter_add_three:
DD 3
DD 0
DD 0
DD 0
 
counter_add_four:
DD 4
DD 0
DD 0
DD 0
 
 
 
section .text
 
align 16
key_expansion128:
    pshufd xmm2, xmm2, 0xFF;
    movdqa xmm3, xmm1
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pxor xmm1, xmm2
 
    ; storing the result in the key schedule array
    movdqu [rdx], xmm1
    add rdx, 0x10                    
    ret
   
 
align 16
global ExpandKey128
ExpandKey128:
 
    linux_setup
 
   
 
    movdqu xmm1, [rcx]    ; loading the key
 
    movdqu [rdx], xmm1
 
    movdqa xmm5, [shuffle_mask wrt rip]
 
    add rdx,16
 
    aeskeygenassist xmm2, xmm1, 0x1     ; Generating round key 1
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
    call key_expansion128
 
    ret
 
 
 
align 16
global _do_rdtsc
_do_rdtsc:
 
    rdtsc
    ret
 
align 16
global sample_rate
sample_rate:
 
    ret
 
align 16
global PMAC
PMAC:
   
    linux_setup
   
testcount:
   
    cmp edx, 5                      ; if blk > 5
    jl endblk
   
para4blk:                       ; encrypt for four block
   
    movdqu xmm0, [r8+0*16]      ; loading the input
    movdqu xmm1, [r8+1*16]      ; loading the input
    movdqu xmm2, [r8+2*16]      ; loading the input
    movdqu xmm3, [r8+3*16]      ; loading the input
   
    movdqu xmm4, [rcx+0*16]     ; loading the round keys
   
    pxor xmm0, xmm4
    pxor xmm1, xmm4
    pxor xmm2, xmm4
    pxor xmm3, xmm4
    aesenc4_u [rcx+1*16]
    aesenc4_u [rcx+2*16]
    aesenc4_u [rcx+3*16]
    aesenc4_u [rcx+4*16]    
    aesenc4_u [rcx+5*16]
    aesenc4_u [rcx+6*16]
    aesenc4_u [rcx+7*16]
    aesenc4_u [rcx+8*16]
    aesenc4_u [rcx+9*16]
    aesenclast4_u [rcx+10*16]
   
    sub edx, 4                  ; blk = blk-4
    add r8, 64                  ; input address + 16
    pxor xmm0, xmm1
    pxor xmm2, xmm3
    pxor xmm0, xmm2
    movdqu xmm5, xmm0
    jmp testcount               ; goto loop test
   
endblk:
    movdqu xmm0, [r8]           ; loading the last block
    pxor xmm0, xmm5
   
    movdqu xmm4, [rcx+0*16]     ; loading the round keys
 
    pxor xmm0, xmm4
    aesenc1_u [rcx+1*16]
    aesenc1_u [rcx+2*16]
    aesenc1_u [rcx+3*16]
    aesenc1_u [rcx+4*16]    
    aesenc1_u [rcx+5*16]
    aesenc1_u [rcx+6*16]
    aesenc1_u [rcx+7*16]
    aesenc1_u [rcx+8*16]
    aesenc1_u [rcx+9*16]
    aesenclast1_u [rcx+10*16]
   
    movdqu  [r9], xmm0
    ret
 
 
align 16
global CBCMAC
CBCMAC:
   
    linux_setup
    pxor xmm1, xmm1             ; xmm1 = 0
    movdqu [r9], xmm1           ; use mac register for IV --> set to 0
 
testloop:
   
    test edx,edx                ; if blk = 0
    jz endloop
 
enc1block:                      ; encrypt for one block
   
    movdqu xmm0, [r8]           ; loading the input
    movdqu xmm1, [r9]           ; loading iv
    movdqu xmm4, [rcx+0*16]     ; loading the round keys
   
    pxor xmm0, xmm1             ; xor iv
    pxor xmm0, xmm4             ; xor with round key 0
    aesenc1_u [rcx+1*16]
    aesenc1_u [rcx+2*16]
    aesenc1_u [rcx+3*16]
    aesenc1_u [rcx+4*16]    
    aesenc1_u [rcx+5*16]
    aesenc1_u [rcx+6*16]
    aesenc1_u [rcx+7*16]
    aesenc1_u [rcx+8*16]
    aesenc1_u [rcx+9*16]
    aesenclast1_u [rcx+10*16]
   
    dec edx                 ; blk --
    add r8, 16              ; input address + 16
    movdqu [r9], xmm0       ; copy cipher as iv for next round encryption (use mac register)
    jmp testloop            ; goto loop test
   
endloop:
    ret
 
 
 
 
 
align 16
global CMAC
CMAC:

	linux_setup

	; generate subkey key1

	pxor xmm0, xmm0             ; set 0 input
	movdqu xmm4, [rcx+0*16]     ; loading the round keys

	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]    
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenclast1_u [rcx+10*16]

	mov r15, 0x87
	pxor xmm7, xmm7
	movq xmm7, r15				; xmm7 contains the constant 0x87
    pslldq xmm7, 15             ; swap

	movdqa xmm5, xmm0
	movq rax, xmm5				
	bt rax, 63					; check msb(L)
	jc key1case2				; jump if msb(L)=1
 
key1case1:
	; msb(L)=0
	movq rax, xmm5              ; high qword
	pextrq rbx, xmm5, 1         ; low qword

	bswap rax					; swap byte order since it is the wrong way around
	bswap rbx

	shl rax, 1					; left shift both registers
	shl rbx, 1
	jnc key1nocarry1			; carry flag would be set if the shift overflows
	or rax, 0x1 				; fix so that we have a correct shift of the 128bit register when we concatenate the 2

key1nocarry1:
	bswap rax					; swap back
	bswap rbx

	pxor xmm5, xmm5
	movq xmm5, rbx				; insert back
	pslldq xmm5, 8
	pinsrq xmm5, rax, 16
    pxor xmm5, xmm7
	jmp cmacsetup

key1case2:
	; msb(L)=1, see case 1, the difference is that no xor with 0x87 is required
	movq rax, xmm5              ; high qword
	pextrq rbx, xmm5, 1         ; low qword

	bswap rax
	bswap rbx

	shl rax, 1
	shl rbx, 1
	jnc key1nocarry2
	or rax, 0x1


key1nocarry2:
	bswap rax
	bswap rbx

	pxor xmm5, xmm5
	movq xmm5, rbx
	pslldq xmm5, 8
	pinsrq xmm5, rax, 16



; Subkey K2 is only required if the block is not full. As we only use it for ipv4 and ipv6 which are full blocks we do not have to compute it
;key2:
;	movdqa xmm6, xmm5
;
;	movq rax, xmm6				; REMOVE DUPL
;    bt rax, 63
;    jc key2case2				; jump if cf = 0
;
;key2case1:                       ; msb is 1
;    movq rax, xmm6              ; high qword
;    pextrq rbx, xmm6, 1            ; low qword
;    
;
;    bswap rax
;
;	bswap rbx
;
;	shl rax, 1
;
;
;	shl rbx, 1
;	jnc key2nocarry1
;	or rax, 0x1
;
;key2nocarry1:
;
;    pxor xmm6, xmm6
;    movq xmm6, rax
;    pslldq xmm6, 8
;    pinsrq xmm6, rbx, 16
;    pxor xmm6, xmm7
;
;    movq rbx, xmm6
;
;
;    pextrq rax, xmm6, 1 
;    bswap rax
;	 bswap rbx
;
;	 pxor xmm6, xmm6
;    movq xmm6, rbx
;    pslldq xmm6, 8
;    pinsrq xmm6, rax, 16
;
;    jmp cmacsetup
;
;key2case2:                      
;   movq rax, xmm6              
;   pextrq rbx, xmm6, 1
;    
;
;   bswap rax
;
;	bswap rbx
;
;	shl rax, 1
;
;
;	shl rbx, 1
;	jnc key2nocarry2
;	or rax, 0x1
;
;
;key2nocarry2:
;
;    bswap rax
;    bswap rbx
;
;    pxor xmm6, xmm6
;    movq xmm6, rbx
;    pslldq xmm6, 8
;    pinsrq xmm6, rax, 16



cmacsetup:
	pxor xmm1, xmm1				; xmm1 = 0
	movdqu [r9], xmm1			; use mac register for IV --> set to 0

cmactestloop:
	mov eax, edx
	dec eax
	test eax,eax
	jz cmacendloop

cmacenc1block:					; encrypt for one block

	movdqu xmm0, [r8]			; loading the input
	movdqu xmm1, [r9]			; loading iv
	movdqu xmm4, [rcx+0*16]		; loading the round keys

	pxor xmm0, xmm1				; xor iv
	pxor xmm0, xmm4				; xor with round key 0
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]    
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenclast1_u [rcx+10*16]

	dec edx 					; blk --
	add r8, 16					; input address + 16
	movdqu [r9], xmm0 			; copy cipher as iv for next round encryption
	jmp cmactestloop 			; goto loop test
   
cmacendloop:
	movdqu xmm0, [r8]			; loading the input
	pxor xmm0, xmm5
	movdqu xmm1, [r9]			; loading iv
	movdqu xmm4, [rcx+0*16]		; loading the round keys

	pxor xmm0, xmm1 			; xor iv
	pxor xmm0, xmm4 			; xor with round key 0
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]    
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenclast1_u [rcx+10*16]

	movdqu  [r9], xmm0
	ret

 
align 16
global PRF
PRF:
   
    linux_setup
   
    ; compute L = E_k(x)
    movdqu xmm0, [r8]           ; loading the seed (x)
    movdqu xmm2, xmm0           ; store original seed (x)
    movdqu xmm4, [rcx+0*16]     ; loading the round keys
    mov rax, 0
   
    pxor xmm0, xmm4
    aesenc1_u [rcx+1*16]
    aesenc1_u [rcx+2*16]
    aesenc1_u [rcx+3*16]
    aesenc1_u [rcx+4*16]    
    aesenc1_u [rcx+5*16]
    aesenc1_u [rcx+6*16]
    aesenc1_u [rcx+7*16]
    aesenc1_u [rcx+8*16]
    aesenc1_u [rcx+9*16]
    aesenclast1_u [rcx+10*16]
    movdqu xmm1, xmm0           ; stroe L
 
tloop:
   
    test edx,edx                ; if blk = 0
    jz eloop
 
prf1block:                      ; encrypt for one block
   
    ; inc(x)
    paddd xmm2,[counter_add_one wrt rip]
    movdqu xmm0, xmm2
   
    pxor xmm0, xmm4
    aesenc1_u [rcx+1*16]
    aesenc1_u [rcx+2*16]
    aesenc1_u [rcx+3*16]
    aesenc1_u [rcx+4*16]    
    aesenc1_u [rcx+5*16]
    aesenc1_u [rcx+6*16]
    aesenc1_u [rcx+7*16]
    aesenc1_u [rcx+8*16]
    aesenc1_u [rcx+9*16]
    aesenclast1_u [rcx+10*16]
   
    pxor xmm0, xmm1             ; store L xor E_k(inc(x))
    dec edx                     ; blk --
    movdqu [r9], xmm0           ; copy random to output
    add r9, 16                  ; shift to next block
    jmp tloop                   ; goto loop test
   
eloop:
    ret
