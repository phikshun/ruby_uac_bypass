def get_process_list
  process_list = []
  
  hsnapshot = Win.CreateToolhelp32Snapshot(3, 0)
  return process_list if !hsnapshot
  
  pe_pointer = FFI::MemoryPointer.new :char, Win::ProcessEntry32.size, true
  pe = Win::ProcessEntry32.new pe_pointer
  pe[:dwSize] = Win::ProcessEntry32.size
  
  Win.Process32First(hsnapshot, pe_pointer)
  proc_hash = {}
  proc_hash[:name] = pe[:szExeFile].to_s
  proc_hash[:pid]  = pe[:th32ProcessID].to_i
  process_list << proc_hash
  while(Win.Process32Next(hsnapshot, pe_pointer) != 0)
    proc_hash = {}
    proc_hash[:name] = pe[:szExeFile].to_s
    proc_hash[:pid]  = pe[:th32ProcessID].to_i
    process_list << proc_hash
  end
  
  process_list
end

def get_pid_by_name(process_name)
  process_name = process_name.downcase.gsub(/\.exe$/, '')
  process_list = get_process_list
  process_list.each do |process|
    name = process[:name].downcase.gsub(/\.exe$/, '')
    return process[:pid] if name == process_name
  end
  nil
end

def create_process(cmd_line)
  si_pointer = FFI::MemoryPointer.new :char, Win::StartupInfo.size, true
  si = Win::StartupInfo.new si_pointer
  si[:cb] = Win::StartupInfo.size
  si[:dwFlags] = 1
  si[:wShowWindow] = 0
  
  pi_pointer = FFI::MemoryPointer.new :char, Win::ProcessInfo.size, true
  pi = Win::ProcessInfo.new pi_pointer
  
  Win.CreateProcessA(nil, cmd_line, nil, nil, false, 8,
                      nil, nil, si_pointer, pi_pointer)
end
