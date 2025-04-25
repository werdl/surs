use std::{
    ffi::NulError,
    fmt::{Display, Formatter},
};

pub type Result<T> = std::result::Result<T, SursError>;

#[derive(Debug)]
pub enum SursError {
    InvalidUid,       // EINVAL
    PermissionDenied, // EPERM

    ParseError(NulError),

    InputOutputError,    // EIO
    ProcessFileCapError, // EMFILE
    SystemFileCapError,  // ENFILE
    InsufficientMemory,  // ENOMEM
    UserDoesNotExist,    // getpwnam returns null, but no errno set
    GroupDoesNotExist,   // getgrnam returns null, but no errno set

    CouldNotCopyFile(std::io::Error), // error copying file
    SpawnError(std::io::Error),       // error spawning process
    UnknownError(i32),                // EINTR, ERANGE
}

impl Display for SursError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SursError::InvalidUid => write!(f, "Invalid UID"),
            SursError::PermissionDenied => write!(f, "Permission Denied"),
            SursError::ParseError(e) => write!(f, "Parse Error: {}", e),
            SursError::InputOutputError => write!(f, "Input/Output Error"),
            SursError::ProcessFileCapError => write!(f, "Process File Cap Error"),
            SursError::SystemFileCapError => write!(f, "System File Cap Error"),
            SursError::InsufficientMemory => write!(f, "Insufficient Memory"),
            SursError::UserDoesNotExist => write!(f, "User Does Not Exist"),
            SursError::GroupDoesNotExist => write!(f, "Group Does Not Exist"),
            SursError::CouldNotCopyFile(e) => write!(f, "Could Not Copy File: {}", e),
            SursError::SpawnError(e) => write!(f, "Spawn Error: {}", e),
            SursError::UnknownError(e) => write!(f, "Unknown Error, errno: {}", e),
        }
    }
}
