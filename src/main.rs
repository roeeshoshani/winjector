use std::{
    ffi::CStr,
    os::raw::c_void,
    path::{Path, PathBuf},
    process::Command,
    ptr::null_mut,
};

use anyhow::{anyhow, ensure, Context};
use clap::Parser;
use hooker::{relocate_fn_start, JumperKind, TrampolineBytes};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{
            CloseHandle, FreeLibrary, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, HMODULE,
        },
        System::{
            Diagnostics::{
                Debug::{
                    GetThreadContext, InitializeContext, ReadProcessMemory, SetThreadContext,
                    WriteProcessMemory, CONTEXT, CONTEXT_FLAGS, CONTEXT_FULL_X86,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, Module32First, Module32Next, Thread32First,
                    Thread32Next, MODULEENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPTHREAD,
                    THREADENTRY32,
                },
            },
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{
                VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, PAGE_EXECUTE, PAGE_PROTECTION_FLAGS,
                PAGE_READWRITE,
            },
            ProcessStatus::{EnumProcessModulesEx, GetModuleInformation, MODULEINFO},
            Threading::{
                GetCurrentProcess, OpenProcess, OpenThread, ResumeThread, SuspendThread,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_ACCESS_RIGHTS,
                THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
            },
        },
    },
};

const TRAMPOLINE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug, Parser)]
struct Cli {
    pid: u32,
    hook_fn_module_name: String,
    hook_fn_name: String,
    dll_path: PathBuf,
    dll_to_shellcode_path: Option<PathBuf>,
}

const DEFAULT_DLL_TO_SHELLCODE_PATH: &str = "C:/users/sho/Documents/DllToShellCode.exe";

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let dll_to_shellcode_path = cli
        .dll_to_shellcode_path
        .unwrap_or_else(|| DEFAULT_DLL_TO_SHELLCODE_PATH.into());
    let hook_fn_info =
        find_fn_in_remote_process(cli.pid, &cli.hook_fn_module_name, &cli.hook_fn_name)?;
    let shellcode = dll_to_shellcode(&cli.dll_path, &dll_to_shellcode_path)
        .context("failed to convert dll to shellcode")?;
    run_remote_shellcode(cli.pid, &shellcode, hook_fn_info).context("failed to run shellcode")?;
    Ok(())
}

struct LibraryGuard(HMODULE);
impl Drop for LibraryGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}

fn str_to_cstr_bytes(s: &str) -> Vec<u8> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

struct FoundFnInfo {
    addr: usize,
    max_size: usize,
}

fn find_fn_in_remote_process(
    pid: u32,
    module_name: &str,
    fn_name: &str,
) -> anyhow::Result<FoundFnInfo> {
    let remote_mod_addr =
        find_addr_of_module_in_remote_process(pid, module_name).context(format!(
            "failed to find address of module {} in remote process",
            module_name,
        ))?;
    let module_name_cstr_bytes = str_to_cstr_bytes(module_name);
    let lib = LibraryGuard(unsafe {
        LoadLibraryA(PCSTR(module_name_cstr_bytes.as_ptr()))
            .context(format!("failed to load library {}", module_name))?
    });
    let fn_name_cstr_bytes = str_to_cstr_bytes(fn_name);
    let local_fn_addr = unsafe { GetProcAddress(lib.0, PCSTR(fn_name_cstr_bytes.as_ptr().cast())) }
        .context(format!(
            "function {} does not exist in module {}",
            fn_name, module_name
        ))?;
    let mut mod_info: MODULEINFO = unsafe { core::mem::zeroed() };
    unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            lib.0,
            &mut mod_info,
            core::mem::size_of_val(&mod_info) as u32,
        )
        .context("failed to get module information")?;
    };
    let local_mod_addr = mod_info.lpBaseOfDll;
    let local_mod_end_addr = local_mod_addr as usize + mod_info.SizeOfImage as usize;
    Ok(FoundFnInfo {
        addr: local_fn_addr as usize - local_mod_addr as usize + remote_mod_addr,
        max_size: local_mod_end_addr - local_fn_addr as usize,
    })
}

fn find_addr_of_module_in_remote_process(pid: u32, module_name: &str) -> anyhow::Result<usize> {
    let snapshot = HandleGuard(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
            .context("failed to create process modules snapshot")?
    });
    let mut mod_entry: MODULEENTRY32 = unsafe { core::mem::zeroed() };
    mod_entry.dwSize = core::mem::size_of::<MODULEENTRY32>() as u32;
    unsafe {
        Module32First(snapshot.0, &mut mod_entry)
            .context("failed to get first thread in threads snapshot")?
    };
    loop {
        let Ok(mod_entry_name) = unsafe { CStr::from_ptr(mod_entry.szModule.as_ptr()) }.to_str()
        else {
            continue;
        };
        if mod_entry_name.eq_ignore_ascii_case(module_name) {
            return Ok(mod_entry.modBaseAddr as usize);
        }
        if unsafe { Module32Next(snapshot.0, &mut mod_entry).is_err() } {
            break;
        }
    }
    Err(anyhow!(
        "module {} not found in module list of process with pid {}",
        module_name,
        pid
    ))
}

fn dll_to_shellcode(dll_path: &Path, dll_to_shellcode_path: &Path) -> anyhow::Result<Vec<u8>> {
    let shellcode_path = dll_path.with_extension("shellcode");
    let exit_status = Command::new(dll_to_shellcode_path)
        .args(["d", "0", "0", "0"])
        .arg(dll_path)
        .arg(&shellcode_path)
        .spawn()
        .context("failed to spawn dll to shellcode command")?
        .wait()
        .context("failed to wait for dll to shellcode command")?;
    ensure!(
        exit_status.success(),
        "dll to shellcode command failed with exit code {:?}",
        exit_status.code()
    );
    std::fs::read(&shellcode_path).context("failed to read dll to shellcode output file")
}

fn run_remote_shellcode(
    pid: u32,
    shellcode: &[u8],
    hook_fn_info: FoundFnInfo,
) -> anyhow::Result<()> {
    let threads = open_threads_of_process(pid, THREAD_SUSPEND_RESUME)
        .context("failed to find thread of process")?;
    let proc_handle = HandleGuard(unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        )
        .context("failed to open process")
    }?);

    let hook_fn_content = read_proc_memory(&proc_handle, hook_fn_info.addr, hook_fn_info.max_size)?;

    // relocate the start of the function and build a hook trampoline so that we can call the original function
    let relocated_fn_start = relocate_fn_start(
        &hook_fn_content,
        hook_fn_info.addr as u64,
        JumperKind::Long.size_in_bytes(),
    )
    .context("failed to relocate the start of the hooked function")?;
    let hook_tramp_addr = alloc_remote(&proc_handle, relocated_fn_start.trampoline_size())
        .context("failed to allocate hook trampoline")?;
    let hook_tramp_bytes = relocated_fn_start.build_trampoline(hook_tramp_addr as u64);
    write_proc_memory(&proc_handle, hook_tramp_addr, &hook_tramp_bytes)
        .context("failed to write hook trampoline")?;
    make_mem_prot_exec_remote(&proc_handle, hook_tramp_addr, hook_tramp_bytes.len())
        .context("failed to make hook tramp executable")?;

    // allocate the shellcode
    let shellcode_addr = alloc_shellcode_in_remote_process(&proc_handle, shellcode)?;

    // build the injection trampoline
    let injection_tramp_global_var_addr =
        alloc_remote(&proc_handle, 8).context("failed to allocate trampoline global var")?;
    let injection_tramp_bytes = build_injection_trampoline(
        injection_tramp_global_var_addr,
        shellcode_addr,
        hook_tramp_addr,
    );

    // allocate the injection trampoline
    let injection_tramp_addr =
        alloc_shellcode_in_remote_process(&proc_handle, &injection_tramp_bytes)
            .context("failed to allocate injection tramp")?;

    // finally, write the jumper to make it jump to the injection tramp

    println!("[*] suspending threads");
    for thread in &threads {
        suspend_thread(thread).context("failed to suspend thread")?;
    }

    println!("[*] writing jumper");
    let jumper = JumperKind::Long.build(hook_fn_info.addr as u64, injection_tramp_addr as u64);
    println!("jumper bytes: {:02x?}", jumper);
    write_proc_memory(&proc_handle, hook_fn_info.addr, &jumper)
        .context("failed to write jumper")?;

    println!("[*] resuming threads");
    for thread in &threads {
        resume_thread(thread).context("failed to suspend thread")?;
    }

    Ok(())
}

fn suspend_thread(thread_handle: &HandleGuard) -> windows::core::Result<()> {
    let res = unsafe { SuspendThread(thread_handle.0) };
    if res == u32::MAX {
        return Err(windows::core::Error::from_win32());
    }
    Ok(())
}

fn resume_thread(thread_handle: &HandleGuard) -> windows::core::Result<()> {
    let res = unsafe { ResumeThread(thread_handle.0) };
    if res == u32::MAX {
        return Err(windows::core::Error::from_win32());
    }
    Ok(())
}

fn build_injection_trampoline(
    global_var_addr: usize,
    shellcode_addr: usize,
    hook_trampoline_addr: usize,
) -> Vec<u8> {
    let mut trampoline = TRAMPOLINE_CODE.to_vec();
    assert!(bytes_find_and_replace_usize(
        &mut trampoline,
        0x1111111111111111,
        global_var_addr
    ));
    assert!(bytes_find_and_replace_usize(
        &mut trampoline,
        0x2222222222222222,
        shellcode_addr
    ));
    assert!(bytes_find_and_replace_usize(
        &mut trampoline,
        0x3333333333333333,
        hook_trampoline_addr
    ));
    trampoline
}

/// returns whether the pattern was found and replaced.
fn bytes_find_and_replace(bytes: &mut [u8], pattern: &[u8], replacement: &[u8]) -> bool {
    assert_eq!(pattern.len(), replacement.len());
    for i in 0..bytes.len() - pattern.len() {
        let window = &mut bytes[i..i + pattern.len()];
        if window == pattern {
            window.copy_from_slice(replacement);
            return true;
        }
    }
    false
}

/// returns whether the pattern was found and replaced.
fn bytes_find_and_replace_usize(bytes: &mut [u8], pattern: usize, replacement: usize) -> bool {
    bytes_find_and_replace(bytes, &pattern.to_ne_bytes(), &replacement.to_ne_bytes())
}
fn write_proc_memory(proc_handle: &HandleGuard, addr: usize, data: &[u8]) -> anyhow::Result<()> {
    let mut num_of_bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            proc_handle.0,
            addr as *const c_void,
            data.as_ptr().cast(),
            data.len(),
            Some(&mut num_of_bytes_written),
        )
        .context("failed to write shellcode to remote process")?
    };
    ensure!(
        num_of_bytes_written == data.len(),
        "not all bytes were written"
    );
    Ok(())
}

fn read_proc_memory(proc_handle: &HandleGuard, addr: usize, len: usize) -> anyhow::Result<Vec<u8>> {
    let mut num_of_bytes_read = 0;
    let mut buf = vec![0u8; len];
    unsafe {
        ReadProcessMemory(
            proc_handle.0,
            addr as *const c_void,
            buf.as_mut_ptr().cast(),
            buf.len(),
            Some(&mut num_of_bytes_read),
        )
        .context("failed to write shellcode to remote process")?
    };
    ensure!(num_of_bytes_read == buf.len(), "not all bytes were read");
    Ok(buf)
}

fn alloc_remote(proc_handle: &HandleGuard, len: usize) -> anyhow::Result<usize> {
    let allocated_addr =
        unsafe { VirtualAllocEx(proc_handle.0, None, len, MEM_COMMIT, PAGE_READWRITE) };
    ensure!(
        !allocated_addr.is_null(),
        "failed to allocate memory in the remote process"
    );
    Ok(allocated_addr as usize)
}

fn alloc_shellcode_in_remote_process(
    proc_handle: &HandleGuard,
    shellcode: &[u8],
) -> anyhow::Result<usize> {
    let allocated_addr = alloc_remote(proc_handle, shellcode.len())?;
    write_proc_memory(proc_handle, allocated_addr, shellcode)
        .context("failed to write shellcode to remote process")?;
    make_mem_prot_exec_remote(proc_handle, allocated_addr, shellcode.len())
        .context("failed to make shellcode executable")?;
    Ok(allocated_addr)
}

fn make_mem_prot_exec_remote(
    proc_handle: &HandleGuard,
    addr: usize,
    len: usize,
) -> anyhow::Result<()> {
    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            proc_handle.0,
            addr as *const c_void,
            len,
            PAGE_EXECUTE,
            &mut old_prot,
        )
        .context("failed to make memory executable in the remote process")?
    };
    Ok(())
}

fn open_threads_of_process(
    pid: u32,
    desired_access: THREAD_ACCESS_RIGHTS,
) -> anyhow::Result<Vec<HandleGuard>> {
    let snapshot = HandleGuard(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .context("failed to create threads snapshot")?
    });
    let mut thread: THREADENTRY32 = unsafe { core::mem::zeroed() };
    thread.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
    unsafe {
        Thread32First(snapshot.0, &mut thread)
            .context("failed to get first thread in threads snapshot")?
    };
    let mut result = Vec::new();
    loop {
        if thread.th32OwnerProcessID == pid {
            result.push(HandleGuard(unsafe {
                OpenThread(desired_access, false, thread.th32ThreadID)
                    .context("failed to open thread")?
            }));
        }
        if unsafe { Thread32Next(snapshot.0, &mut thread).is_err() } {
            break;
        }
    }
    Ok(result)
}
