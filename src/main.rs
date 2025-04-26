use clap::Parser;
use escalate::{Escalate, Gid, Uid};
use log::{debug, info};
use parse_opts::{timed_out, update_timeout, Privilege, UserOrGroup};
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
compile_surs_error!("surs only works on *nix, as it uses libc functionality");

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

    /// Should we edit a file (in command). The used editor is the editor specified in the config file, $SURS_EDITOR, $EDITOR, or $VISUAL, in that order. If none of these are set, vi will be used.
    #[clap(short, long)]
    edit: bool,

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

fn escape_prompt(prompt: &str, target: String) -> String {
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
                        output.push_str(&target);
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

macro_rules! surs_error {
    ($msg:expr) => {
        eprintln!("{}: {}", std::env::args().next().unwrap_or_else(|| "unknown".to_string()), $msg);
        std::process::exit(1);
    };
    ($fmt:expr, $($arg:tt)+) => {
        eprintln!("{}: {}", std::env::args().next().unwrap_or_else(|| "unknown".to_string()), format!($fmt, $($arg)+));
        std::process::exit(1);
    };
}

fn main() {
    env_logger::init();
    let opts = Opts::parse();
    let privileges = parse_opts::parse();

    if opts.shell.is_none() && opts.command.is_none() {
        surs_error!("No command specified");
    }

    debug!("Privileges: {:#?}", privileges);

    if privileges.is_err() {
        info!(
            "Here is an example config file (save it to {}): \n{}",
            if cfg!(debug_assertions) {
                "surs.conf.json"
            } else {
                "/etc/surs.conf.json"
            },
            parse_opts::example()
        );

        surs_error!("Error parsing privileges: {}", privileges.err().unwrap());
    }

    let privileges = privileges.unwrap();

    let uname = get_username().unwrap_or_default();
    let groups = get_user_groups().unwrap_or_default();

    let target_group_id = if opts.group.is_some() {
        let group = opts.group.clone().unwrap();
        if group.starts_with('#') {
            let gid = group[1..].parse::<u32>();
            if gid.is_err() {
                surs_error!("Invalid GID: {}", gid.err().unwrap());
            }
            Some(gid.unwrap())
        } else {
            // convert to gid
            let group_str = group.as_str();
            let group_cstr = CString::new(group_str).unwrap();
            let group_ptr = unsafe { getgrnam(group_cstr.as_ptr()) };
            if group_ptr.is_null() {
                surs_error!("Group not found: {}", group_str);
            }
            let group = unsafe { &*group_ptr };
            let gid = group.gr_gid;
            if gid == 0 {
                surs_error!("Group not found: {}", group_str);
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
        .filter(|privilege| match &privilege.perm_owner {
            parse_opts::UserOrGroup::User(user) => user == &uname,
            parse_opts::UserOrGroup::Group(group) => groups.contains(group),
        })
        .collect::<Vec<_>>();

    if user_privileges.is_empty() {
        surs_error!("No privileges found for user/group");
    }

    if opts.list {
        debug!("Privileges for user/group:");
        for privilege in &user_privileges {
            debug!("{:#?}", privilege);
        }
        std::process::exit(0);
    }

    let prompt = if opts.custom_prompt.is_some() {
        opts.custom_prompt.clone().unwrap()
    } else if std::env::var("SURS_PROMPT").is_ok() {
        std::env::var("SURS_PROMPT").unwrap()
    } else {
        privileges
            .prompt
            .unwrap_or("[surs]: password for %u: ".to_string())
    };

    // check if the privilege matches the user or group
    let relevant_privileges: Vec<&&Privilege> = user_privileges
        .iter()
        .filter(|privilege| {
            match &privilege.exec_as {
                // privilege.exec_as == chosen user
                parse_opts::UserOrGroup::User(user) => user == &opts.user,

                // privilege.exec_as == chosen group
                parse_opts::UserOrGroup::Group(group) => {
                    // get gid from group name
                    let group_cstr = CString::new(group.as_str()).unwrap();
                    let group_ptr = unsafe { getgrnam(group_cstr.as_ptr()) };
                    if group_ptr.is_null() {
                        surs_error!("Group not found: {}", group);
                    }

                    let group_struct = unsafe { &*group_ptr };
                    let gid = group_struct.gr_gid;
                    if gid == 0 {
                        surs_error!("Group not found: {:#?}", group);
                    }
                    gid == target_group_id.unwrap_or(0)
                }
            }
        })
        .collect();

    if relevant_privileges.is_empty() {
        surs_error!("No relevant privileges found for user/group");
    }

    // now check we have a privilege for a. user and (if specified) b. group
    if relevant_privileges
        .iter()
        .filter(|privilege| matches!(privilege.exec_as, UserOrGroup::User(_)))
        .count()
        == 0
    {
        surs_error!("No privileges found for user {}", opts.user);
    }

    if relevant_privileges
        .iter()
        .filter(|privilege| matches!(privilege.exec_as, UserOrGroup::Group(_)))
        .count()
        == 0
        && target_group_id.is_some()
    {
        surs_error!(
            "No privileges found for group {}",
            opts.group.unwrap()
        );
    }

    debug!("Relevant privilege found: {:#?}", relevant_privileges);

    let uid = Uid::from_str(&opts.user);
    if uid.is_err() {
        surs_error!("Error getting UID: {}", uid.err().unwrap());
    }
    let uid = uid.unwrap();

    let gid = target_group_id.map(Gid::new);

    // prompt for password if required
    if relevant_privileges.iter().any(|p| p.password_required)
        && (timed_out(
            parse_opts::UidOrGid::Uid(uid.0),
            privileges.timeout.unwrap_or(300),
        )
        .unwrap_or(false)
            || {
                if let Some(gid) = gid.clone() {
                    timed_out(
                        parse_opts::UidOrGid::Gid(gid.0),
                        privileges.timeout.unwrap_or(300),
                    )
                    .is_ok()
                } else {
                    false
                }
            })
    {
        let mut attempts = 0;
        let max_attempts = privileges.max_attempts.unwrap_or(3);

        while attempts < max_attempts {
            let password =
                rpassword::prompt_password(escape_prompt(&prompt, opts.user.clone())).unwrap();
            if password.is_empty() {
                eprintln!("Sorry, try again.");

                attempts += 1;
                if attempts == max_attempts {
                    surs_error!("{} incorrect attempts", max_attempts);
                }
                continue;
            }

            let uname = get_username().unwrap_or("unknown".to_string());

            let hash = shadow::Shadow::from_name(&uname)
                .unwrap_or_else(|| {
                    surs_error!("Error getting password hash");
                })
                .password;

            if check_password(&password, &hash) {
                break;
            } else {
                eprintln!("Sorry, try again.");
                attempts += 1;
                if attempts == max_attempts {
                    surs_error!("{} incorrect password attempts", max_attempts);
                }
            }
        }
    }

    debug!("Escalating to user {}", opts.user);
    let res = uid.escalate();
    if res.is_err() {
        surs_error!("Error escalating to user: {}", res.err().unwrap());
    }

    if opts.group.is_some() {
        debug!("Escalating to group {}", opts.group.unwrap());
        let res = gid.unwrap().escalate();
        if res.is_err() {
            surs_error!("Error escalating to group: {}", res.err().unwrap());
        }
    }

    // set the directory
    if opts.directory.is_some() {
        let dir = opts.directory.clone().unwrap();
        let res = std::env::set_current_dir(&dir);
        if res.is_err() {
            surs_error!("Error setting directory: {}", res.err().unwrap());
        }
    }

    if opts.shell.is_some() {
        let shell = unsafe { getpwuid(uid.0) };

        if shell.is_null() {
            surs_error!("Error getting shell: {}", std::io::Error::last_os_error());
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

        let args = if opts.login { vec!["-l"] } else { vec![] };

        let res = run::run(&shell, args.as_slice());
        if res.is_err() {
            surs_error!("Error running shell: {}", res.err().unwrap());
        }

        let timeout_res = update_timeout(
            parse_opts::UidOrGid::Uid(uid.0)
        );
        if timeout_res.is_err() {
            surs_error!("Error updating timeout: {}", timeout_res.err().unwrap());
        }

        std::process::exit(res.unwrap().code().unwrap_or(1));
    } else if opts.edit {
        let editor = if privileges.editor.is_some() {
            privileges.editor.clone().unwrap()
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
            surs_error!("Error editing file: {}", res.err().unwrap());
        }

        let res = update_timeout(
            parse_opts::UidOrGid::Uid(uid.0)
        );
        if res.is_err() {
            surs_error!("Error updating timeout: {}", res.err().unwrap());
        }

        std::process::exit(0);
    } else if opts.background {
        let command = opts.command.clone().unwrap();
        let args = command.split_whitespace().collect::<Vec<_>>();

        let cmd_res = run::run_background(&args[0], &args[1..]);
        if cmd_res.is_err() {
            surs_error!("Error running command: {}", cmd_res.err().unwrap());
        }

        let res = update_timeout(
            parse_opts::UidOrGid::Uid(uid.0)
        );
        if res.is_err() {
            surs_error!("Error updating timeout: {}", res.err().unwrap());
        }

        std::process::exit(cmd_res.unwrap().wait().unwrap().code().unwrap_or(1));
    } else if opts.command.is_some() {
        let command = opts.command.clone().unwrap();
        let args = command.split_whitespace().collect::<Vec<_>>();

        let cmd_res = run::run(&args[0], &args[1..]);
        if cmd_res.is_err() {
            surs_error!("Error running command: {}", cmd_res.err().unwrap());
        }

        let res = update_timeout(
            parse_opts::UidOrGid::Uid(uid.0)
        );
        if res.is_err() {
            surs_error!("Error updating timeout: {}", res.err().unwrap());
        }

        std::process::exit(cmd_res.unwrap().code().unwrap_or(1));
    } else {
        let command = opts.command.clone().unwrap();
        let args = command.split_whitespace().collect::<Vec<_>>();

        let cmd_res = run::run(&args[0], &args[1..]);
        if cmd_res.is_err() {
            surs_error!("Error running command: {}", cmd_res.err().unwrap());
        }

        let res = update_timeout(
            parse_opts::UidOrGid::Uid(uid.0)
        );
        if res.is_err() {
            surs_error!("Error updating timeout: {}", res.err().unwrap());
        }

        std::process::exit(cmd_res.unwrap().code().unwrap_or(1));
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
            surs_error!("Group name is empty for GID {}", group);
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

        let result_str = std::ffi::CStr::from_ptr(result)
            .to_str()
            .expect("CStr::to_str failed");
        result_str == hash
    }
}
