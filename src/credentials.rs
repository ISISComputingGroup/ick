use anyhow::anyhow;
use std::fs::File;

use keepass::{
    Database, DatabaseKey,
    db::NodeRef::{Entry, Group},
};

/// A windows credential, consisting of:
/// - Domain, the domain or machine on which this credential is valid
/// - Username, authentication username
/// - Password, authentication password
pub struct Credential {
    pub host: String,
    pub domain: String,
    pub username: String,
    pub password: String,
}

/// Implementations of acquiring a credential
pub enum CredentialSource {
    Keepass { path: String, key: String },
    Keeper { token: String },
}

fn get_credentials_keepass(
    source: &str,
    key: &str,
    machines: &[String],
    admin: bool,
) -> anyhow::Result<Vec<Credential>> {
    let mut file = File::open(source)?;
    let key = DatabaseKey::new().with_password(key);
    let db = Database::open(&mut file, key)?;

    let group_name = if admin { "Admin" } else { "User" };

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
                    domain: machine.clone(),
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

pub fn get_credentials(
    machines: &[String],
    admin: bool,
    credential_source: &CredentialSource,
) -> anyhow::Result<Vec<Credential>> {
    match credential_source {
        CredentialSource::Keepass { path, key } => {
            get_credentials_keepass(path, key, machines, admin)
        }
        CredentialSource::Keeper { .. } => Err(anyhow!("Keeper API not yet supported")),
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_foo() {}
}
