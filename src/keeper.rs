use crate::credentials::Credential;
use anyhow::anyhow;
use base64::prelude::*;
use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    dto::Record,
    dto::dtos::KeeperFolder,
    enums::StandardFieldTypeEnum,
    storage::InMemoryKeyValueStorage,
};
use std::collections::{HashMap, HashSet};

fn record_to_credential(record: &Record) -> anyhow::Result<Credential> {
    let host = record.title.clone();
    let username = record
        .get_standard_field_value(StandardFieldTypeEnum::LOGIN.get_type(), true)?
        .as_str()
        .ok_or(anyhow!("failed to read username for {host}"))?
        .to_owned();
    let password = record
        .get_standard_field_value(StandardFieldTypeEnum::PASSWORD.get_type(), true)?
        .as_str()
        .ok_or(anyhow!("failed to read password for {host}"))?
        .to_owned();

    Ok(Credential::new(host, username, password))
}

const ADMIN_FOLDER_IDENTIFIER: &str = "Admin";

fn is_admin_folder(folder: &KeeperFolder) -> bool {
    folder.name.contains(ADMIN_FOLDER_IDENTIFIER)
}

fn get_secrets_manager(keeper_key: &str) -> anyhow::Result<SecretsManager> {
    let decoded_key = BASE64_STANDARD.decode(keeper_key)?;
    let config_contents = String::from_utf8(decoded_key)?;
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_contents))?;
    let client_options = ClientOptions::new_client_options(config);
    SecretsManager::new(client_options).map_err(|e| anyhow!("{e}"))
}

fn get_allowed_folder_uids(folders: &[KeeperFolder], admin: bool) -> HashSet<String> {
    folders
        .iter()
        .filter(|f| (!admin) ^ is_admin_folder(f))
        .map(|f| f.folder_uid.clone())
        .collect()
}

pub fn get_credentials_keeper<T: AsRef<str>>(
    keeper_key: &str, // Really a base64'd version of a config file.
    machines: &[T],
    admin: bool,
) -> anyhow::Result<Vec<Credential>> {
    let mut secrets_manager = get_secrets_manager(keeper_key)?;

    let all_secrets = secrets_manager.get_secrets(vec![])?;

    let allowed_folder_uids = get_allowed_folder_uids(&secrets_manager.get_folders()?, admin);

    let all_creds = all_secrets
        .iter()
        .filter(|r| allowed_folder_uids.contains(&r.folder_uid))
        .map(record_to_credential)
        .map(|cred| cred.map(|c| (c.host().to_owned(), c)))
        .collect::<anyhow::Result<HashMap<_, _>>>()?;

    machines
        .iter()
        .map(AsRef::as_ref)
        .map(|machine| {
            all_creds
                .get(machine)
                .cloned()
                .ok_or(anyhow!("Failed to get credential for {machine}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_folder() -> KeeperFolder {
        KeeperFolder {
            folder_key: vec![],
            folder_uid: "admin_uid".to_owned(),
            parent_uid: "".to_owned(),
            name: "This is an Admin folder".to_owned(),
        }
    }

    fn user_folder() -> KeeperFolder {
        KeeperFolder {
            folder_key: vec![],
            folder_uid: "user_uid".to_owned(),
            parent_uid: "".to_owned(),
            name: "This is a User folder".to_owned(),
        }
    }

    #[test]
    fn test_keeper_admin_folder() {
        assert!(is_admin_folder(&admin_folder()))
    }

    #[test]
    fn test_keeper_non_admin_folder() {
        assert!(!is_admin_folder(&user_folder()))
    }

    #[test]
    fn test_get_allowed_folder_uids_admin() {
        let allowed_uids = get_allowed_folder_uids(&[admin_folder(), user_folder()], true);
        assert_eq!(allowed_uids.len(), 1);
        assert!(allowed_uids.contains("admin_uid"));
    }

    #[test]
    fn test_get_allowed_folder_uids_user() {
        let allowed_uids = get_allowed_folder_uids(&[admin_folder(), user_folder()], false);
        assert_eq!(allowed_uids.len(), 1);
        assert!(allowed_uids.contains("user_uid"));
    }
}
