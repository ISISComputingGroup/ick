use crate::credentials::Credential;
use anyhow::{anyhow, bail};
use keepass::{
    Database, DatabaseKey,
    db::NodeRef::{self, Entry, Group},
};
use log::trace;
use std::fs::File;

const USERNAME_KEY: &str = "UserName";
const PASSWORD_KEY: &str = "Password";

/// Get the name of the keepass group containing the relevant set of credentials.
fn get_keepass_group_name(admin: bool) -> &'static str {
    if admin { "Admin" } else { "User" }
}

fn node_to_credential(node: NodeRef, machine: String) -> anyhow::Result<Credential> {
    match node {
        Group { .. } => bail!("Expected entry, not group"),
        Entry(fields, ..) => Ok(Credential::new(
            machine,
            fields
                .get(USERNAME_KEY)
                .ok_or(anyhow!("Username field not found"))?
                .to_owned(),
            fields
                .get(PASSWORD_KEY)
                .ok_or(anyhow!("Password field not found"))?
                .to_owned(),
        )),
    }
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
            let node = db.root.get(&[group_name, machine]).ok_or(anyhow!(
                "unable to find credential {group_name}/{machine} in {source}",
            ))?;
            node_to_credential(node, machine.to_owned())
                .map_err(|e| anyhow!("Failed to read credential at {group_name}/{machine}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{Entry, Group, Value};

    #[test]
    fn test_get_keepass_group_name() {
        assert_eq!(get_keepass_group_name(false), "User");
        assert_eq!(get_keepass_group_name(true), "Admin");
    }

    #[test]
    fn test_node_to_credential_with_group() {
        let node_ref = NodeRef::Group(&Group::default());
        let result = node_to_credential(node_ref, "".to_owned());
        assert!(result.is_err_and(|e| e.to_string().contains("Expected entry, not group")))
    }

    #[test]
    fn test_node_to_credential_with_entry_with_missing_username() {
        let entry = Entry::default();
        let node_ref = NodeRef::Entry(&entry);
        let result = node_to_credential(node_ref, "".to_owned());
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
        let result = node_to_credential(node_ref, "".to_owned());
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
        let result = node_to_credential(node_ref, "some_machine".to_owned());
        assert!(result.is_ok_and(|v| v
            == Credential::new(
                "some_machine".to_owned(),
                "some_username".to_owned(),
                "some_password".to_owned()
            )))
    }
}
