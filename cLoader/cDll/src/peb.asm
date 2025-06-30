.CODE
 
GetPeb PROC
        ;mov rax,60h       ;TEB
		mov rax, gs:[60h]  ;PEB
		RET
GetPeb ENDP
 
END