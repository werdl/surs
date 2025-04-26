use std::{ffi::CString, fmt::Display};

use crate::result::Result;

/// represents a uid
#[derive(Debug)]
pub struct Uid(pub u32);

impl Display for Uid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

use libc::{getgrnam, getpwnam, setgid, setuid};

pub trait Escalate
where
    Self: Sized,
{
    fn new(id: u32) -> Self;
    fn from_str(name: &str) -> Result<Self>;
    fn escalate(&self) -> Result<()>;
}

impl Escalate for Uid {
    fn new(uid: u32) -> Self {
        Uid(uid)
    }

    fn from_str(user_name: &str) -> Result<Self> {
        let c_user =
            CString::new(user_name).map_err(|e| crate::result::SursError::ParseError(e))?;
        let pw_ptr = unsafe { getpwnam(c_user.as_ptr()) }; // unsafe as FFI

        if pw_ptr.is_null() {
            // check errno
            let err = std::io::Error::last_os_error();
            // according to the getpwnam manpage, EIO, EMFILE, ENFILE, ENOMEM, EINTR, ERANGE are the only errors that getpwnam can return
            match err.raw_os_error() {
                Some(libc::EIO) => Err(crate::result::SursError::InputOutputError),
                Some(libc::EMFILE) => Err(crate::result::SursError::ProcessFileCapError),
                Some(libc::ENFILE) => Err(crate::result::SursError::SystemFileCapError),
                Some(libc::ENOMEM) => Err(crate::result::SursError::InsufficientMemory),

                Some(libc::EINTR) => Err(crate::result::SursError::UnknownError(libc::EINTR)),
                Some(libc::ERANGE) => Err(crate::result::SursError::UnknownError(libc::ERANGE)),

                Some(0) => Err(crate::result::SursError::UserDoesNotExist), // getpwnam does not error, instead returning null as intended because no such user exists

                Some(e) => Err(crate::result::SursError::UnknownError(e)), // unknown error
                None => Err(crate::result::SursError::UnknownError(-1)),   // system probably borked
            }
        } else {
            let uid = unsafe {
                // safe, we have checked for null
                let pw = &*pw_ptr;
                pw.pw_uid
            };
            Ok(Uid(uid))
        }
    }

    fn escalate(&self) -> Result<()> {
        let res = unsafe { setuid(self.0) };

        if res != 0 {
            // check errno
            let err = std::io::Error::last_os_error();

            // according to the setuid manpage, EPERM and EINVAL are the only two errors that setuid can return
            match err.raw_os_error() {
                Some(libc::EPERM) => return Err(crate::result::SursError::PermissionDenied),
                Some(libc::EINVAL) => return Err(crate::result::SursError::InvalidUid),

                Some(e) => return Err(crate::result::SursError::UnknownError(e)),
                None => return Err(crate::result::SursError::UnknownError(-1)), // system probably borked
            }
        } else {
            Ok(())
        }
    }
}

/// represents a gid
#[derive(Debug, Clone)]
pub struct Gid(pub u32);

impl Display for Gid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Escalate for Gid {
    fn new(gid: u32) -> Self {
        Gid(gid)
    }

    fn from_str(group_name: &str) -> Result<Self> {
        let c_group =
            CString::new(group_name).map_err(|e| crate::result::SursError::ParseError(e))?;
        let grp_ptr = unsafe { getgrnam(c_group.as_ptr()) }; // unsafe as FFI

        if grp_ptr.is_null() {
            // check errno
            let err = std::io::Error::last_os_error();
            // according to the getgrnam manpage, EIO, EMFILE, ENFILE, ENOMEM, EINTR, ERANGE are the only errors that getpwnam can return
            match err.raw_os_error() {
                Some(libc::EIO) => Err(crate::result::SursError::InputOutputError),
                Some(libc::EMFILE) => Err(crate::result::SursError::ProcessFileCapError),
                Some(libc::ENFILE) => Err(crate::result::SursError::SystemFileCapError),
                Some(libc::ENOMEM) => Err(crate::result::SursError::InsufficientMemory),

                Some(libc::EINTR) => Err(crate::result::SursError::UnknownError(libc::EINTR)),
                Some(libc::ERANGE) => Err(crate::result::SursError::UnknownError(libc::ERANGE)),

                Some(0) => Err(crate::result::SursError::GroupDoesNotExist), // getpwnam does not error, instead returning null as intended because no such user exists

                Some(e) => Err(crate::result::SursError::UnknownError(e)), // unknown error
                None => Err(crate::result::SursError::UnknownError(-1)),   // system probably borked
            }
        } else {
            let gid = unsafe {
                // safe, we have checked for null
                let grp = &*grp_ptr;
                grp.gr_gid
            };
            Ok(Gid(gid))
        }
    }

    fn escalate(&self) -> Result<()> {
        let res = unsafe { setgid(self.0) };

        if res != 0 {
            // check errno
            let err = std::io::Error::last_os_error();

            // according to the setuid manpage, EPERM and EINVAL are the only two errors that setuid can return
            match err.raw_os_error() {
                Some(libc::EPERM) => return Err(crate::result::SursError::PermissionDenied),
                Some(libc::EINVAL) => return Err(crate::result::SursError::InvalidUid),

                Some(e) => return Err(crate::result::SursError::UnknownError(e)),
                None => return Err(crate::result::SursError::UnknownError(-1)), // system probably borked
            }
        } else {
            Ok(())
        }
    }
}
