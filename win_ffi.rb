module Win
  extend FFI::Library
  
  PROCESS_DUP_HANDLE        = 0x0040
  PROCESS_VM_OPERATION      = 0x0008
  PROCESS_VM_WRITE          = 0x0020
  PROCESS_CREATE_THREAD     = 0x0002
  PROCESS_QUERY_INFORMATION = 0x0400
  PROCESS_VM_READ           = 0x0010
  
  MEM_RESERVE               = 0x2000
  MEM_COMMIT                = 0x1000
  MEM_RESET                 = 0x80000
  PAGE_READWRITE            = 0x04
  PAGE_EXECUTE_READWRITE    = 0x40

  ERROR_SUCCESS             = 0
  CREATE_SUSPENDED          = 0x00000004
  
  class ProcessEntry32 < FFI::Struct
    layout :dwSize, :uint,
      :cntUsage, :uint,
      :th32ProcessID, :uint,
      :th32DefaultHeapID, :pointer,
      :td32ModuleID, :uint,
      :cntThreads, :uint,
      :th32ParentProcessID, :uint,
      :pcPriClassBase, :uint,
      :dwFlags, :uint,
      :szExeFile, [:char, 260]
  end
  
  class StartupInfo < FFI::Struct
    layout :cb, :uint,
      :lpReserved, :pointer,
      :lpDesktop, :pointer,
      :lpTitle, :pointer,
      :dwX, :uint,
      :dwY, :uint,
      :dwXSize, :uint,
      :dwYSize, :uint,
      :dwXCountChars, :uint,
      :dwYCountChars, :uint,
      :dwFillAttribute, :uint,
      :dwFlags, :uint,
      :wShowWindow, :ushort,
      :cbReserved2, :ushort,
      :lpReserved2, :pointer,
      :hStdInput, :uint,
      :hStdOutput, :uint,
      :hStdError, :uint,
  end
  
  class ProcessInfo < FFI::Struct
    layout :hProcess, :uint,
      :hThread, :uint,
      :dwProcessId, :uint,
      :dwThreadId, :uint,
  end
  
  class Wow64Context < FFI::Struct
    layout :hProcess, :uint, :dwPad1, :uint,
      :lpStartAddress, :pointer, :dwPad2, :uint,
      :lpParameter, :pointer, :dwPad3, :uint,
      :hThread, :uint, :dwPad4, :uint
  end

  ffi_lib 'kernel32'
  ffi_convention :stdcall
  
  attach_function :CreateToolhelp32Snapshot, [:uint, :uint], :uint
  attach_function :Process32First, [:uint, :pointer], :int
  attach_function :Process32Next, [:uint, :pointer], :int
  attach_function :CloseHandle, [:uint], :bool
  attach_function :CreateProcessA, [:pointer, :string, :pointer, :pointer, :bool, :uint,
                                   :pointer, :pointer, :pointer, :pointer], :bool
  attach_function :OpenProcess, [:uint, :bool, :uint], :uint
  attach_function :VirtualAllocEx, [:uint, :pointer, :uint, :uint, :uint], :pointer
  attach_function :VirtualAlloc, [:pointer, :uint, :uint, :uint], :pointer
  attach_function :WriteProcessMemory, [:uint, :pointer, :pointer, :uint, :pointer], :bool
  attach_function :CreateRemoteThread, [:uint, :pointer, :uint, :pointer, :pointer, :uint, :pointer], :uint
  attach_function :ResumeThread, [:uint], :uint
end