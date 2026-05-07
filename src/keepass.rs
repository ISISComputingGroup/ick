use crate::credentials::Credential;
use anyhow::anyhow;
use keepass::{Database, DatabaseKey, db::Entry};
use log::trace;
use std::fs::File;

const USERNAME_KEY: &str = "UserName";
const PASSWORD_KEY: &str = "Password";

/// Get the name of the keepass group containing the relevant set of credentials.
fn get_keepass_group_name(admin: bool) -> &'static str {
    if admin { "Admin" } else { "User" }
}

fn node_to_credential(node: &Entry, machine: String) -> anyhow::Result<Credential> {
    Ok(Credential::new(
        machine,
        node.get(USERNAME_KEY)
            .ok_or(anyhow!("Username field not found"))?
            .to_owned(),
        node.get(PASSWORD_KEY)
            .ok_or(anyhow!("Password field not found"))?
            .to_owned(),
    ))
}

/// Get credentials for the specified machines from keepass.
pub fn get_credentials_keepass<T: AsRef<str>>(
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
            let root = db.root();
            let group = root
                .group_by_name(group_name)
                .ok_or(anyhow!("unable to find group {group_name} in {source}",))?;
            let entry = group.entry_by_name(machine).ok_or(anyhow!(
                "unable to find credential {group_name}/{machine} in {source}",
            ))?;
            node_to_credential(&entry, machine.to_owned())
                .map_err(|e| anyhow!("Failed to read credential at {group_name}/{machine}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_keepass_group_name() {
        assert_eq!(get_keepass_group_name(false), "User");
        assert_eq!(get_keepass_group_name(true), "Admin");
    }
}
