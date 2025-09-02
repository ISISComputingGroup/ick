use anyhow::{Context, anyhow, bail};
use log::trace;
use serde::Serialize;
use std::fs::File;

#[cfg(test)]
use serial_test::serial;

use keepass::{
    Database, DatabaseKey,
    db::NodeRef::{self, Entry, Group},
};

const USERNAME_KEY: &str = "UserName";
const PASSWORD_KEY: &str = "Password";

/// A windows credential, consisting of:
/// - Host, the machine on which this credential is valid
/// - Username, authentication username
/// - Password, authentication password
#[derive(PartialEq, Eq, Serialize)]
pub struct Credential {
    /// hostname on which this credential is valid.
    host: String,
    /// Username to authenticate to this host. May contain a domain
    /// component, like SERVER\user, or may just be a "bare"
    /// username.
    username: String,
    /// Password corresponding to the provided username.
    password: String,
}

impl Credential {
    /// Create a new credential from hostname, username, password.
    ///
    /// host must be a hostname on which this credential applies
    ///
    /// username may be either qualified (SERVER\user), or a bare username
    ///
    /// password must be the password corresponding to the above username
    pub fn new(host: &str, username: &str, password: &str) -> Credential {
        Credential {
            host: host.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    /// Get the target machine on which this credential is valid.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get only the username component of the username, stripping any domain component.
    #[allow(unused)]
    pub fn username_without_domain(&self) -> &str {
        if let Some((_, username)) = self.username.split_once('\\') {
            username
        } else {
            &self.username
        }
    }

    /// Get only the domain component of the username. If the username was unqualified,
    /// return None.
    #[allow(unused)]
    pub fn domain(&self) -> Option<&str> {
        self.username.split_once('\\').map(|(domain, _)| domain)
    }

    /// Get the username, which may be either qualified (SERVER\user) or bare.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password for this credential.
    pub fn password(&self) -> &str {
        &self.password
    }
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

/// Get the name of the keepass group containing the relevant set of credentials.
fn get_keepass_group_name(admin: bool) -> &'static str {
    if admin { "Admin" } else { "User" }
}

fn node_to_credential<T: AsRef<str>>(node: NodeRef, machine: T) -> anyhow::Result<Credential> {
    match node {
        Group { .. } => bail!("Expected entry, not group"),
        Entry(fields, ..) => Ok(Credential::new(
            machine.as_ref(),
            fields
                .get(USERNAME_KEY)
                .ok_or(anyhow!("Username field not found"))?,
            fields
                .get(PASSWORD_KEY)
                .ok_or(anyhow!("Password field not found"))?,
        )),
    }
}

/// Get credentials for the specified machines from keepass.
fn get_credentials_keepass<T: AsRef<str>>(
    source: &str,
    key: &str,
    machines: &[T],
    admin: bool,
) -> anyhow::Result<Vec<Credential>> {
    trace!("Getting credentials from keepass DB at {source}");

    let mut file = File::open(source)?;
    let key = DatabaseKey::new().with_password(key);
    let db = Database::open(&mut file, key)
        .map_err(|e| anyhow!("Failed to open database at {source}: {e}"))?;

    trace!("Keepass database at {source} successfully opened");

    let group_name = get_keepass_group_name(admin);

    trace!("Looking for credentials in group {group_name}");

    machines
        .iter()
        .map(AsRef::as_ref)
        .map(|machine| {
            let node = db.root.get(&[group_name, machine]).ok_or(anyhow!(
                "unable to find credential {group_name}/{machine} in {source}",
            ))?;
            node_to_credential(node, machine)
                .map_err(|e| anyhow!("Failed to read credential at {group_name}/{machine}: {e}"))
        })
        .collect()
}

/// Get either user or administrative credentials for the specified machines.
///
/// If a credential_source is not provided, it will default to creating a credential source
/// from the environment (and returning Err if the relevant variables are not set correctly).
pub fn get_credentials<T: AsRef<str>>(
    machines: &[T],
    admin: bool,
    credential_source: Option<&CredentialSource>,
) -> anyhow::Result<Vec<Credential>> {
    let source = match credential_source {
        Some(source) => source,
        None => &CredentialSource::from_env()?,
    };

    match source {
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
    use keepass::db::{Entry, Group, Value};

    #[test]
    fn test_get_credentials_from_keeper_causes_error() {
        let result = get_credentials(
            &["x", "y"],
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

    #[test]
    fn test_username_without_domain() {
        assert_eq!(
            Credential::new("foo", "bar\\baz", "pass").username_without_domain(),
            "baz"
        );
        assert_eq!(
            Credential::new("foo", "bar", "pass").username_without_domain(),
            "bar"
        );
    }

    #[test]
    fn test_get_domain() {
        assert_eq!(
            Credential::new("foo", "bar\\baz", "pass").domain(),
            Some("bar")
        );
        assert_eq!(Credential::new("foo", "bar", "pass").domain(), None);
    }

    #[test]
    fn test_node_to_credential_with_group() {
        let node_ref = NodeRef::Group(&Group::default());
        let result = node_to_credential(node_ref, "");
        assert!(result.is_err_and(|e| e.to_string().contains("Expected entry, not group")))
    }

    #[test]
    fn test_node_to_credential_with_entry_with_missing_username() {
        let entry = Entry::default();
        let node_ref = NodeRef::Entry(&entry);
        let result = node_to_credential(node_ref, "");
        assert!(result.is_err_and(|e| e.to_string().contains("Username field not found")))
    }

    #[test]
    fn test_node_to_credential_with_entry_with_missing_password() {
        let mut entry = Entry::default();
        entry.fields.insert(
            USERNAME_KEY.to_owned(),
            Value::Unprotected("some_username".to_owned()),
        );
        let node_ref = NodeRef::Entry(&entry);
        let result = node_to_credential(node_ref, "");
        assert!(result.is_err_and(|e| e.to_string().contains("Password field not found")))
    }

    #[test]
    fn test_node_to_credential_with_correct_entry() {
        let mut entry = Entry::default();
        entry.fields.insert(
            USERNAME_KEY.to_owned(),
            Value::Unprotected("some_username".to_owned()),
        );
        entry.fields.insert(
            PASSWORD_KEY.to_owned(),
            Value::Unprotected("some_password".to_owned()),
        );
        let node_ref = NodeRef::Entry(&entry);
        let result = node_to_credential(node_ref, "some_machine");
        assert!(
            result.is_ok_and(
                |v| v == Credential::new("some_machine", "some_username", "some_password")
            )
        )
    }
}
