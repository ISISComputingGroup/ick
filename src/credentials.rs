use anyhow::{Context, anyhow};
use log::trace;
use std::fs::File;

#[cfg(test)]
use serial_test::serial;

use keepass::{
    Database, DatabaseKey,
    db::NodeRef::{Entry, Group},
};

/// A windows credential, consisting of:
/// - Host, the machine on which this credential is valid
/// - Username, authentication username
/// - Password, authentication password
#[derive(PartialEq, Eq)]
pub struct Credential {
    pub host: String,
    pub username: String,
    pub password: String,
}

/// Get an environment variable, providing context on which environment
/// variable was missing as part of the error message.
fn get_env_var(var: &str) -> anyhow::Result<String> {
    std::env::var(var).with_context(|| format!("Missing {var} environment variable"))
}

/// Backends from which a credential can be acquired.
#[derive(PartialEq, Eq, Debug)]
pub enum CredentialSource {
    Keepass { path: String, key: String },
    Keeper { token: String },
}

impl CredentialSource {
    /// Look for appropriate environment variables containing details about the
    /// credential-storage backend, and create a credential source from those env
    /// variables.
    fn from_env() -> anyhow::Result<CredentialSource> {
        let typ = get_env_var("ICK_CRED_STORE")?;

        match typ.to_lowercase().as_str() {
            "keepass" => {
                let path = get_env_var("ICK_KEEPASS_FILE")?;
                let key = get_env_var("ICK_KEEPASS_KEY")?;
                Ok(CredentialSource::Keepass { path, key })
            }
            "keeper" => {
                let token = get_env_var("ICK_KEEPER_TOKEN")?;
                Ok(CredentialSource::Keeper { token })
            }
            _ => Err(anyhow!(
                "Invalid ICK_CRED_STORE environment variable, must be either 'keepass' or 'keeper'"
            )),
        }
    }
}

fn get_keepass_group_name(admin: bool) -> &'static str {
    if admin { "Admin" } else { "User" }
}

/// Get credentials for the specified machines from keepass.
fn get_credentials_keepass(
    source: &str,
    key: &str,
    machines: &[String],
    admin: bool,
) -> anyhow::Result<Vec<Credential>> {
    trace!("Getting credentials from keepass DB at {source}");

    let mut file = File::open(source)?;
    let key = DatabaseKey::new().with_password(key);
    let db = Database::open(&mut file, key)?;

    trace!("Keepass database at {source} successfully opened");

    let group_name = get_keepass_group_name(admin);

    trace!("Looking for credentials in group {group_name} for machines {machines:?}");

    machines
        .iter()
        .map(|machine| {
            let node = db.root.get(&[group_name, machine]).ok_or(anyhow!(
                "unable to find credential {}/{}",
                group_name,
                machine
            ))?;
            match node {
                Group { .. } => Err(anyhow!(
                    "Expected entry, not group, in {group_name}/{machine}"
                )),
                Entry(fields, ..) => Ok(Credential {
                    host: machine.clone(),
                    username: fields
                        .get("UserName")
                        .ok_or(anyhow!("Username field not found"))?
                        .to_owned(),
                    password: fields
                        .get("Password")
                        .ok_or(anyhow!("Password field not found"))?
                        .to_owned(),
                }),
            }
        })
        .collect()
}

/// Get either user or administrative credentials for the specified machines.
///
/// If a credential_source is not provided, it will default to creating a credential source
/// from the environment (and returning Err if the relevant variables are not set correctly).
pub fn get_credentials(
    machines: &[String],
    admin: bool,
    credential_source: Option<&CredentialSource>,
) -> anyhow::Result<Vec<Credential>> {
    let credential_source = match credential_source {
        Some(source) => source,
        None => &CredentialSource::from_env()?,
    };

    match credential_source {
        CredentialSource::Keepass { path, key } => {
            get_credentials_keepass(path, key, machines, admin)
        }
        CredentialSource::Keeper { .. } => Err(anyhow!("Keeper API not yet supported")),
    }
}

#[cfg(test)]
#[serial]
mod tests {
    use super::*;

    #[test]
    fn test_get_credentials_from_keeper_causes_error() {
        let result = get_credentials(
            &["x".to_owned(), "y".to_owned()],
            false,
            Some(&CredentialSource::Keeper {
                token: "some_token".to_owned(),
            }),
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_appropriate_keepass_env_variables_can_be_used() {
        // SAFETY: std::env::set_var is safe on Windows.
        // This test is guarded by cfg(target_os = "windows")
        unsafe {
            std::env::set_var("ICK_CRED_STORE", "keepass");
            std::env::set_var("ICK_KEEPASS_FILE", "foo");
            std::env::set_var("ICK_KEEPASS_KEY", "bar");
        }
        let source = CredentialSource::from_env().expect("should have parsed successfully");
        assert_eq!(
            source,
            CredentialSource::Keepass {
                path: "foo".to_owned(),
                key: "bar".to_owned(),
            }
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_appropriate_keeper_env_variables_can_be_used() {
        // SAFETY: std::env::set_var is safe on Windows.
        // This test is guarded by cfg(target_os = "windows")
        unsafe {
            std::env::set_var("ICK_CRED_STORE", "keeper");
            std::env::set_var("ICK_KEEPER_TOKEN", "baz");
        }
        let source = CredentialSource::from_env().expect("should have parsed successfully");
        assert_eq!(
            source,
            CredentialSource::Keeper {
                token: "baz".to_owned(),
            }
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_invalid_ick_cred_store_env_var_causes_error() {
        // SAFETY: std::env::set_var is safe on Windows.
        // This test is guarded by cfg(target_os = "windows")
        unsafe {
            std::env::set_var("ICK_CRED_STORE", "blah");
            std::env::set_var("ICK_KEEPASS_FILE", "foo");
            std::env::set_var("ICK_KEEPASS_KEY", "bar");
        }
        let source = CredentialSource::from_env();
        assert!(source.is_err_and(|e| e.to_string().contains(
            "Invalid ICK_CRED_STORE environment variable, must be either 'keepass' or 'keeper'"
        )));
    }

    #[test]
    fn test_get_keepass_group_name() {
        assert_eq!(get_keepass_group_name(false), "User");
        assert_eq!(get_keepass_group_name(true), "Admin");
    }
}
