use crate::result::{Result, SursError};

/// run a command as the current user
/// this function expects the user to be escalated, and it will return the process in that state
pub fn run(command: &str, args: &[&str]) -> Result<std::process::ExitStatus> {
    let mut command = std::process::Command::new(command);

    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    for arg in args {
        command.arg(arg);
    }

    let status = command
        .spawn()
        .map_err(|e| SursError::SpawnError(e))?
        .wait()
        .map_err(|e| SursError::SpawnError(e))?;
    Ok(status)
}

/// run a command as the current user in the background
/// this function expects the user to be escalated, and it will return the process in that state
pub fn run_background(command: &str, args: &[&str]) -> Result<std::process::Child> {
    let mut command = std::process::Command::new(command);

    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    for arg in args {
        command.arg(arg);
    }

    let child = command.spawn().map_err(|e| SursError::SpawnError(e))?;
    Ok(child)
}

/// edit a file by copying it to a temp file, opening it , and copying it back
/// this function expects the user to be escalated, and it will return the process in that state
pub fn edit(file: &str, editor: &str) -> Result<std::process::ExitStatus> {
    // ensure that file is not a symlink, and is not in the /dev hierarchy
    let actual_file = std::fs::canonicalize(file).map_err(|e| SursError::CouldNotCopyFile(e))?;
    if actual_file.is_symlink() {
        return Err(SursError::SpawnError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "File is a symlink",
        )));
    }
    if actual_file.starts_with("/dev") {
        return Err(SursError::SpawnError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "File is in /dev",
        )));
    }

    // first, generate a temp file
    let mut rand_string = String::new();

    let mut rng = rand::rng();

    while rand_string.len() < 8 {
        let c = rand::Rng::random_range(&mut rng, 97..=122) as u8; // ascii lowercase
        if c.is_ascii_alphanumeric() {
            rand_string.push(c as char);
        }
    }

    let temp_file = format!(
        "/tmp/{}-{}.tmp",
        actual_file
            .components()
            .last()
            .map(|component| component.as_os_str().to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        rand_string
    );

    // create file
    std::fs::File::create(&temp_file).map_err(|e| SursError::CouldNotCopyFile(e))?;
    std::fs::copy(file, &temp_file).map_err(|e| SursError::CouldNotCopyFile(e))?;

    let mut command = std::process::Command::new(editor);
    command.arg(&temp_file);
    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    let status = command
        .spawn()
        .map_err(|e| SursError::SpawnError(e))?
        .wait()
        .map_err(|e| SursError::SpawnError(e))?;

    std::fs::copy(&temp_file, file).map_err(|e| SursError::CouldNotCopyFile(e))?;
    std::fs::remove_file(&temp_file).map_err(|e| SursError::CouldNotCopyFile(e))?;
    Ok(status)
}
