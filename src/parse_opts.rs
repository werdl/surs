use serde::{Deserialize, Serialize};

/// Represents either a user or a group
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserOrGroup {
    #[serde(rename = "user")]
    User(String),

    #[serde(rename = "group")]
    Group(String),
}

/// Represents a privilege and who it is afforded to
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Privilege {
    pub id: UserOrGroup,
    pub password_required: bool,
    pub exec_as: String,
}

/// Represents the config file (when compiled for release, /etc/surs.conf.json, or for dev ./surs.conf.json)
#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigFile {
    pub privileges: Vec<Privilege>,
    pub interactive: bool,
    pub editor: Option<String>,
    pub prompt: Option<String>,
    pub max_attempts: Option<u32>,
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
            id: UserOrGroup::User(crate::get_username().unwrap_or("root".into())),
            password_required: true,
            exec_as: "root".into(),
        }],
        interactive: true,
        editor: Some("nano".into()),
        prompt: Some("surs> ".into()),
        max_attempts: Some(3),
    };

    serde_json::to_string_pretty(&ex).unwrap()
}
