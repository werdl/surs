use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// Represents either a user or a group
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserOrGroup {
    #[serde(rename = "user")]
    User(String),

    #[serde(rename = "group")]
    Group(String),
}

impl Display for UserOrGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserOrGroup::User(user) => write!(f, "user={}", user),
            UserOrGroup::Group(group) => write!(f, "group={}", group),
        }
    }
}

/// Represents a privilege and who it is afforded to
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Privilege {
    /// the user who owns the privilege (ie. can execute it)
    pub perm_owner: UserOrGroup,
    /// whether the privilege requires a password
    pub password_required: bool,
    /// the user or group that will be escalated to (ie. the target user)
    pub exec_as: UserOrGroup,
}

/// Represents the config file (when compiled for release, /etc/surs.conf.json, or for dev ./surs.conf.json)
#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigFile {
    pub privileges: Vec<Privilege>,
    pub interactive: bool,
    pub editor: Option<String>,
    pub prompt: Option<String>,
    pub max_attempts: Option<u32>,
    pub timeout: Option<u32>,
}

pub fn parse() -> Result<ConfigFile, &'static str> {
    let config_file = if cfg!(debug_assertions) {
        "surs.conf.json"
    } else {
        "/etc/surs.conf.json"
    };

    let contents =
        std::fs::read_to_string(config_file).map_err(|_| "Could not read config file")?;

    let config: ConfigFile =
        serde_json::from_str(&contents).map_err(|_| "Could not parse config file")?;

    Ok(config)
}

pub fn example() -> String {
    let ex = ConfigFile {
        privileges: vec![Privilege {
            perm_owner: UserOrGroup::User(crate::get_username().unwrap_or("root".into())),
            password_required: true,
            exec_as: UserOrGroup::User("root".into()),
        }],
        interactive: true,
        editor: Some("nano".into()),
        prompt: Some("[surs] password for %u: ".into()),
        max_attempts: Some(3),
        timeout: Some(300),
    };

    serde_json::to_string_pretty(&ex).unwrap()
}

#[derive(Copy, Clone)]
pub enum UidOrGid {
    Uid(u32),
    Gid(u32),
}

impl std::fmt::Display for UidOrGid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UidOrGid::Uid(uid) => write!(f, "uid={}", uid),
            UidOrGid::Gid(gid) => write!(f, "gid={}", gid),
        }
    }
}

/// write to /etc/surs.timeout
pub fn update_timeout(target: UidOrGid) -> Result<(), &'static str> {
    let timeout_file = format!("/tmp/{}.surs.timeout", target.to_string());

    // overwrite the file with the current timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    std::fs::write(timeout_file, now.to_string()).map_err(|_| "Could not write to timeout file")?;

    Ok(())
}

/// check if we are timed out
pub fn timed_out(target: UidOrGid, timeout: u32) -> Result<bool, &'static str> {
    let timeout_file = format!("/tmp/{}.surs.timeout", target.to_string());

    // check if the file exists
    if !std::path::Path::new(&timeout_file).exists() {
        return Ok(false);
    }

    // read the file
    let contents =
        std::fs::read_to_string(timeout_file).map_err(|_| "Could not read timeout file")?;

    // parse the contents as a u64
    let timestamp = contents
        .trim()
        .parse::<u64>()
        .map_err(|_| "Could not parse timeout file")?;


    // get the current time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(now > ((timeout as u64) + timestamp))
}
