
ifndef UTILS_ASM_
UTILS_ASM_ MACRO
ENDM
msgMemcpy db "from MyMemCpy",0
msgCeilAli db "from ceil_align",0

; int   my_strcmp(char *, char *)
; (edi, esi) -> eax
; Compares 2 strings strcmp-style.
my_strcmp PROC NEAR

    push edi
    push esi
    push ebx                 ; Saving registers that we will use

loop_beg:
    cmp BYTE ptr [edi], 0
    jz  loop_end             ; if (str1[i] == '\0') then exit loop
    mov bl, BYTE ptr [edi]
    cmp BYTE ptr [esi], bl
    jnz loop_end             ; if (str1[i] != str2[i]) then exit loop
    inc edi
    inc esi
    jmp loop_beg

loop_end:
    movzx eax, BYTE ptr [edi]
    movzx ebx, BYTE ptr [esi]
    sub   eax, ebx

    pop ebx
    pop esi
    pop edi                  ; restore borrowed registers

    ret
my_strcmp ENDP

; void* memcpy(void *dest, void *src, size_t n)
; (edi, esi, edx) -> eax
my_memcpy PROC NEAR
    invoke MessageBoxA, NULL, addr msgMemcpy, addr msgMemcpy, MB_OK

 ; Procedimiento para copiar una cadena a la memoria
    push ebx
    push esi
    push edi

    mov esi, edx  ; Origen (puntero a la cadena)
    mov edi, ecx  ; Destino (puntero a la memoria reservada)

    xor ecx, ecx  ; Limpiar contador de repeticiones

copy_loop:
    mov al, [esi]  ; Leer byte de la cadena
    mov [edi], al  ; Escribir byte en la memoria reservada
    inc esi        ; Avanzar al siguiente byte de la cadena
    inc edi        ; Avanzar al siguiente byte de la memoria reservada
    inc ecx        ; Incrementar contador de repeticiones
    cmp byte ptr[esi], 0  ; Comprobar si hemos llegado al final de la cadena
    jne copy_loop     ; Si no, continuar copiando



lbl_result:
    mov eax, edi

    pop ebx
    pop esi
    pop edi                  ; restore borrowed registers

    ret
my_memcpy ENDP

; void *memset(void *s, int c, size_t n)
; (edi, esi, edx) -> eax
my_memset PROC NEAR

    push ebx
    push edx

    mov  eax, edi
    mov  ecx, edi
    lea  ebx, [edi + edx]
    test edi, edi            ; Test if s is NULL
    je   lbl_end

lbl_loop:
    mov edx, esi
    mov BYTE ptr [ecx], dl
    inc ecx
    cmp ecx, ebx
    jb  lbl_loop

lbl_end:
    pop edx
    pop ebx

    ret
my_memset ENDP

; int    ceil_align(int nbr, int alignment)
; args on stack (_stdcall) -> eax
; Ceils nbr to a multiple of alignment.
ceil_align PROC NEAR 
    ; Entrar a la función
    invoke MessageBoxA, NULL, addr msgCeilAli, addr msgCaption, MB_OK   
    
    mov edi, ecx;[esp + 4]    ; Primer parámetro: nbr
    mov esi, edx;[esp + 8]    ; Segundo parámetro: alignment
    xor eax, eax
    
ceil_align_loop:
    cmp eax, edi
    jae ceil_align_loop_end  ; Jump if above or equal
    add eax, esi
    jmp ceil_align_loop

ceil_align_loop_end:
    ret
ceil_align ENDP

endif                        ; UTILS_ASM_
