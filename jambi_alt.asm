; Jambi
; MASM32 asm program for Intel i386 processors running Windows 32bits
; By Deb0ch.

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

.code

begin_copy:
jmp start
; Datos dentro de la sección .code
msgFormat_2 db 'Number of bytes between begincopy and endcopy: %d', 0
buffer_2 db 256 dup(0)
msgCaption db "Result", 0
mycode_len db 1

start:
   
    
    ; Calcular el número de bytes entre begincopy y endcopy
    lea eax, end_copy
    lea ecx, begin_copy
    sub eax, ecx
   ; mov dword ptr [mycode_len], eax
 ; Mensaje de depuración inicial
  
    ; Comprobar el valor de mycode_len
    invoke wsprintf, addr buffer_2, addr msgFormat_2, byte ptr [mycode_len] 
      invoke MessageBoxA, NULL, addr msgCaption, addr msgCaption, MB_OK
    invoke MessageBoxA, NULL, addr buffer_2, addr msgCaption, MB_OK
    
    ; Mostrar el resultado en un MessageBox
    invoke MessageBoxA, NULL, addr buffer_2, addr msgCaption, MB_OK
    
    ; Salir del programa
    invoke ExitProcess, 0

end_copy:

end start
