.586P
.model flat


.code

_RThread2 proc
startp2::
	push 0 ; //eip;
	pushfd
	pushad
	call geteip2
geteip2:
	pop ebx
	and ebx,0ffff0000h ;//ebx = membase;
	mov eax,[ebx]
	mov [esp+24h],eax;  //adjust eip;
	lea eax,[ebx+8]  ;  dll path;
	push eax;
	call dword ptr [ebx+4] ;loadlibrary;
	popad
	popfd
	ret	
_end2::
	nop;
_RThread2 endp

_GetStart2 proc
	mov eax,startp2
	ret
_GetStart2 endp

_GetSize2 Proc
	mov  eax, _end2-startp2
	ret
_GetSize2 endp

end
