use clap::Parser;
use escalate::{Escalate, Gid};
use result::Result;

mod escalate;
mod parse_opts;
mod result;
mod run;

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "haiku",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
)))]
compile_error!("surs only works on *nix, as it uses libc functionality");

#[derive(Parser, Debug)]
struct Opts {
    /// The command to run, with any arguments. If the --edit flag is set, this will be the file to edit.
    command: Option<String>,

    /// Specify that this command should be ran in the background.
    #[clap(short, long, default_value = "false")]
    background: bool,

    /// Specify the directory that should be used for the command (default is the current directory).
    #[clap(short, long)]
    directory: Option<String>,

    /// If set, this will be the editor used to edit the file. The default is $SURS_EDITOR, or $EDITOR, or $VISUAL, or /bin/vi, in that order.
    #[clap(short, long)]
    edit: Option<Option<String>>,

    /// Specify the group to run the command as. If a gid is specified, use #<gid>
    #[clap(short, long)]
    group: Option<String>,

    /// Specify that a login shell should be launched.
    #[clap(short = 'i', long, default_value = "false")]
    login: bool,

    /// List permissions for the current user and exit.
    #[clap(short, long, default_value = "false")]
    list: bool,

    /// Launch in non-interactive mode - if a password is required, surs will exit with an error.
    #[clap(short, long, default_value = "false")]
    non_interactive: bool,

    /// Use a custom prompt, with the following escape sequences:
    /// - %H: hostname
    /// - %h: hostname without domain
    /// - %u or %p: username
    /// - %U: target username
    /// - %%: literal %
    ///
    /// this overwrites $SURS_PROMPT, if set
    #[clap(short, long)]
    custom_prompt: Option<String>,

    /// Boot into a shell instead of running a command. Any value in COMMAND will be sent to the shell using -c. If this is specified without a shell name, the user's default shell will be used.
    #[clap(short, long)]
    shell: Option<Option<String>>,

    /// Specify the user to run the command as. This will be used to set the UID of the process. Defaults to root.
    #[clap(short, long, default_value = "root")]
    user: String,
}

fn escape_prompt(prompt: &str, target_user: &str) -> String {
    let mut output = String::new();

    let mut i = 0;
    while i < prompt.len() {
        let c = prompt.chars().nth(i).unwrap();
        match c {
            '%' => {
                match prompt.chars().collect::<Vec<char>>().get(i + 1) {
                    Some('H') | Some('h') => {
                        output.push_str(&get_hostname().unwrap_or_else(|_| "unknown".to_string()));
                    }
                    Some('u') | Some('p') => {
                        output.push_str(&get_username().unwrap_or_else(|_| "unknown".to_string()));
                    }
                    Some('U') => {
                        output.push_str(target_user);
                    }
                    Some('%') => {
                        output.push('%');
                    }
                    _ => {}
                };
                i += 1;
            }
            _ => {
                output.push(c);
            }
        }
        i += 1;
    }

    output
}

fn main() {
    let opts = Opts::parse();
    let privileges = parse_opts::parse();

    println!("Privileges: {:?}", privileges);

    if privileges.is_err() {
        println!("Error parsing privileges: {}", privileges.err().unwrap());

        println!("Here is an example config file: {}", parse_opts::example());

        std::process::exit(1);
    }

    let privileges = privileges.unwrap();

    let uname = get_username().unwrap_or_default();
    let groups = get_user_groups().unwrap_or_default();

    let target_group_id = if opts.group.is_some() {
        let group = opts.group.clone().unwrap();
        if group.starts_with('#') {
            let gid = group[1..].parse::<u32>();
            if gid.is_err() {
                eprintln!("Invalid GID: {}", gid.err().unwrap());
                std::process::exit(1);
            }
            Some(gid.unwrap())
        } else {
            // convert to gid
            let group_str = group.as_str();
            let group_cstr = CString::new(group_str).unwrap();
            let group_ptr = unsafe { getgrnam(group_cstr.as_ptr()) };
            if group_ptr.is_null() {
                eprintln!("Group not found: {}", group_str);
                std::process::exit(1);
            }
            let group = unsafe { &*group_ptr };
            let gid = group.gr_gid;
            if gid == 0 {
                eprintln!("Group not found: {}", group_str);
                std::process::exit(1);
            }
            Some(gid)
        }
    } else {
        None
    };

    // find a relevant privilege for the user OR any of the groups the user is in
    let user_privileges = privileges
        .privileges
        .iter()
        .filter(|privilege| {
            match &privilege.id {
                parse_opts::UserOrGroup::User(user) => user == &uname,
                parse_opts::UserOrGroup::Group(group) => {
                    groups.contains(group)
                }
            }
        })
        .collect::<Vec<_>>();

    if user_privileges.is_empty() {
        eprintln!("No privileges found for user/group");
        std::process::exit(1);
    }

    if opts.list {
        println!("Privileges for user/group:");
        for privilege in &user_privileges {
            println!("{:?}", privilege);
        }
        std::process::exit(0);
    }

    let prompt = if opts.custom_prompt.is_some() {
        opts.custom_prompt.clone().unwrap()
    } else if std::env::var("SURS_PROMPT").is_ok() {
        std::env::var("SURS_PROMPT").unwrap()
    } else {
        privileges.prompt.unwrap_or("[surs]: password for %u: ".to_string())
    };

    // check if the privilege matches the user
    let relevant_privilege = user_privileges
        .iter()
        .find(|privilege| {
            privilege.exec_as == opts.user
        });

    if relevant_privilege.is_none() {
        eprintln!("No privileges found for user/group");
        std::process::exit(1);
    }

    println!(
        "Relevant privilege found: {:?}",
        relevant_privilege.unwrap()
    );

    let privilege = relevant_privilege.unwrap();

    // prompt for password if required
    if privilege.password_required {
        let mut attempts = 0;
        let max_attempts = privileges.max_attempts.unwrap_or(3);

        while attempts < max_attempts {
            let password =
                rpassword::prompt_password(escape_prompt(&prompt, &privilege.exec_as)).unwrap();
            if password.is_empty() {
                eprintln!("No password provided");
                attempts += 1;
                if attempts == max_attempts {
                    eprintln!("Maximum attempts reached");
                    std::process::exit(1);
                }
                continue;
            }

            let uname = get_username().unwrap_or("unknown".to_string());

            let hash = shadow::Shadow::from_name(&uname).unwrap_or_else(|| {
                eprintln!("Error getting password hash");
                std::process::exit(1);
            }).password;

            if check_password(&password, &hash) {
                break;
            } else {
                eprintln!("Incorrect password");
                attempts += 1;
                if attempts == max_attempts {
                    eprintln!("{} incorrect attempts", max_attempts);
                    std::process::exit(1);
                }
            }
        }
    }

    println!("Escalating to {}", privilege.exec_as);

    let uid = escalate::Uid::from_str(&privilege.exec_as);

    if uid.is_err() {
        eprintln!("Error getting UID: {}", uid.err().unwrap());
        std::process::exit(1);
    }

    let uid = uid.unwrap();

    if target_group_id.is_some() {
        let gid = Gid::new(target_group_id.unwrap());

        let res = gid.escalate();

        if res.is_err() {
            eprintln!("Error setting GID: {}", res.err().unwrap());
            std::process::exit(1);
        }
    }

    let res = uid.escalate();
    if res.is_err() {
        eprintln!("Error setting UID: {}", res.err().unwrap());
        std::process::exit(1);
    }

    // set the directory
    if opts.directory.is_some() {
        let dir = opts.directory.clone().unwrap();
        let res = std::env::set_current_dir(&dir);
        if res.is_err() {
            eprintln!("Error setting directory: {}", res.err().unwrap());
            std::process::exit(1);
        }
    }

    if opts.shell.is_some() {
        let shell = unsafe {
            getpwuid(uid.0)
        };

        if shell.is_null() {
            eprintln!("Error getting shell: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }

        let shell = unsafe { CStr::from_ptr((*shell).pw_shell) }
            .to_string_lossy()
            .into_owned();

        let shell = if opts.shell.clone().unwrap().is_some() {
            if opts.shell.clone().unwrap().is_some() {
                opts.shell.clone().unwrap().unwrap()
            } else {
                shell
            }
        } else {
            shell
        };

        let args = if opts.login {
            vec!["-l"]
        } else {
            vec![]
        };

        let res = run::run(&shell, args.as_slice());
        if res.is_err() {
            eprintln!("Error running shell: {}", res.err().unwrap());
            std::process::exit(1);
        }

        std::process::exit(res.unwrap().code().unwrap_or(1));
    } else if opts.edit.is_some() {
        let editor = if opts.edit.clone().unwrap().is_some() {
            opts.edit.clone().unwrap().unwrap()
        } else if std::env::var("SURS_EDITOR").is_ok() {
            std::env::var("SURS_EDITOR").unwrap()
        } else if std::env::var("EDITOR").is_ok() {
            std::env::var("EDITOR").unwrap()
        } else if std::env::var("VISUAL").is_ok() {
            std::env::var("VISUAL").unwrap()
        } else {
            "/bin/vi".to_string()
        };

        let file = opts.command.clone().unwrap();
        let res = run::edit(&file, &editor);
        if res.is_err() {
            eprintln!("Error editing file: {}", res.err().unwrap());
            std::process::exit(1);
        }

        std::process::exit(0);
    } else if opts.background {
        let command = opts.command.clone().unwrap();
        let args = command.split_whitespace().collect::<Vec<_>>();

        let res = run::run_background(&args[0], &args[1..]);
        if res.is_err() {
            eprintln!("Error running command: {}", res.err().unwrap());
            std::process::exit(1);
        }

        std::process::exit(res.unwrap().wait().unwrap().code().unwrap_or(1));
    } else if opts.command.is_some() {
        let command = opts.command.clone().unwrap();
        let args = command.split_whitespace().collect::<Vec<_>>();

        let res = run::run(&args[0], &args[1..]);
        if res.is_err() {
            eprintln!("Error running command: {}", res.err().unwrap());
            std::process::exit(1);
        }

        std::process::exit(res.unwrap().code().unwrap_or(1));
    } else {
        let command = opts.command.clone().unwrap();
        let args = command.split_whitespace().collect::<Vec<_>>();
        let res = run::run(&args[0], &args[1..]);
        if res.is_err() {
            eprintln!("Error running command: {}", res.err().unwrap());
            std::process::exit(1);
        }
        std::process::exit(res.unwrap().code().unwrap_or(1));
    }
}

use libc::{c_char, getgrgid, getgrnam, getpwuid, gid_t};
use std::ffi::{CStr, CString};

use std::vec::Vec;

fn get_user_groups() -> Result<Vec<String>> {
    let groups = unsafe {
        let num_groups = libc::getgroups(0, ::std::ptr::null_mut());
        let mut groups = vec![0; num_groups as usize];
        let res = libc::getgroups(num_groups, groups.as_mut_ptr());

        // check for error
        if res != num_groups {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(e) => return Err(result::SursError::UnknownError(e)),
                None => return Err(result::SursError::UnknownError(-1)),
            }
        }

        groups
    };

    let mut group_names = Vec::new();
    for group in groups.iter() {
        let group_ptr = unsafe { getgrgid(*group as gid_t) };
        if group_ptr.is_null() {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EIO) => return Err(result::SursError::InputOutputError),
                Some(libc::EMFILE) => return Err(result::SursError::ProcessFileCapError),
                Some(libc::ENFILE) => return Err(result::SursError::SystemFileCapError),
                Some(libc::ENOMEM) => return Err(result::SursError::InsufficientMemory),
                Some(libc::EINTR) => return Err(result::SursError::UnknownError(libc::EINTR)),
                Some(libc::ERANGE) => return Err(result::SursError::UnknownError(libc::ERANGE)),
                Some(0) => return Err(result::SursError::GroupDoesNotExist),
                Some(e) => return Err(result::SursError::UnknownError(e)),
                None => return Err(result::SursError::UnknownError(-1)),
            }
        }

        let group_name = unsafe { CStr::from_ptr((*group_ptr).gr_name) }
            .to_string_lossy()
            .into_owned();
        if group_name.is_empty() {
            eprintln!("Warning: Group name is empty for GID {}", group);
            continue;
        }
        group_names.push(group_name);
    }

    Ok(group_names)
}

fn get_hostname() -> Result<String> {
    let mut buf: [libc::c_char; 256] = [0; 256];
    let res = unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len() as libc::size_t) };

    if res != 0 {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(e) => return Err(result::SursError::UnknownError(e)),
            None => return Err(result::SursError::UnknownError(-1)),
        }
    }
    if res != 0 {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(e) => return Err(result::SursError::UnknownError(e)),
            None => return Err(result::SursError::UnknownError(-1)),
        }
    }
    unsafe { Ok(CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()) }
}

fn get_username() -> Result<String> {
    let uid = unsafe { libc::getuid() };
    let user_ptr = unsafe { getpwuid(uid) };
    if user_ptr.is_null() {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(e) => return Err(result::SursError::UnknownError(e)),
            None => return Err(result::SursError::UnknownError(-1)),
        }
    }
    unsafe {
        Ok(CStr::from_ptr((*user_ptr).pw_name)
            .to_string_lossy()
            .into_owned())
    }
}

unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

fn check_password(password: &str, hash: &str) -> bool {
    let pass_c = CString::new(password).expect("CString::new failed");
    let hash_c = CString::new(hash).expect("CString::new failed");

    unsafe {
        let result = crypt(pass_c.as_ptr(), hash_c.as_ptr());
        if result.is_null() {
            return false;
        }

        let result_str = std::ffi::CStr::from_ptr(result).to_str().expect("CStr::to_str failed");
        result_str == hash
    }
}
