; Ejemplo completo de MASM32 que usa wsprintf y MessageBoxA sin .data
.386
.model flat, stdcall
option casemap:none

include \masm32\include\msvcrt.inc
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc 
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib
.data
msgFormat_2 db 'Number of bytes between begincopy and endcopy: %d', 0
buffer_2 db 256 dup(0)
.data?
mycode_len dd ?
.code

begin_copy:
jmp start


msgCaption db "Result", 0

start:
    ; Calcular el número de bytes entre begincopy y endcopy
   lea eax, end_copy
   lea ecx, begin_copy
   sub eax, ecx
   mov mycode_len, eax

    ; Formatear el mensaje con wsprintf
    invoke wsprintf, addr buffer_2, addr msgFormat_2, mycode_len
     invoke MessageBoxA, NULL, addr msgCaption, addr msgCaption, MB_OK
    ; Mostrar el resultado en un MessageBox
    invoke MessageBoxA, NULL, addr buffer_2, addr msgCaption, MB_OK
    
    ; Salir del programa
    invoke ExitProcess, 0

end_copy:

end start