pub struct UserInfo {
    pub is_root: bool,
}

pub fn current() -> UserInfo {
    // SAFETY: geteuid() takes no arguments, cannot fail, and only reads the
    // calling process's effective uid. No memory-safety implications.
    let euid = unsafe { libc::geteuid() };
    UserInfo { is_root: euid == 0 }
}
