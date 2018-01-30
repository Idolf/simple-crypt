use libc;
use nix;
use failure::Error;

pub fn lock_memory<T>(below_bytes: usize, above_bytes: usize, value: &T) -> Result<(), Error> {
    let ptr: usize = value as *const T as usize;
    let first_addr = (ptr - below_bytes) & !0xfff;
    let last_addr = ((ptr + above_bytes - 1) | 0xfff) + 1;
    let length = last_addr - first_addr;

    const MLOCK_ONFAULT: libc::c_int = 1;

    ensure!(
        unsafe { libc::syscall(libc::SYS_mlock2, first_addr, length, MLOCK_ONFAULT) } == 0,
        "could not lock memory: {}",
        nix::errno::Errno::last().desc()
    );

    Ok(())
}

pub fn set_no_dumpable() -> Result<(), Error> {
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == 0,
        "could not set the process as non-dumpable: {}",
        nix::errno::Errno::last().desc()
    );

    Ok(())
}
