use crate::credentials::Credential;
use anyhow::anyhow;
use base64::prelude::*;
use keeper_secrets_manager_core::{
    core::{ClientOptions, SecretsManager},
    dto::Record,
    enums::StandardFieldTypeEnum,
    storage::InMemoryKeyValueStorage,
};

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

pub fn get_credentials_keeper<T: AsRef<str>>(
    keeper_key: &str, // Really a base64'd version of a config file.
    machines: &[T],
    admin: bool,
) -> anyhow::Result<Vec<Credential>> {
    let config_contents = String::from_utf8(BASE64_STANDARD.decode(keeper_key)?)?;
    let config = InMemoryKeyValueStorage::new_config_storage(Some(config_contents))?;
    let client_options = ClientOptions::new_client_options(config);
    let mut secrets_manager = SecretsManager::new(client_options)?;
    let secrets = secrets_manager.get_secrets(vec![])?;

    let mut folders = secrets_manager.get_folders()?;

    if admin {
        folders.retain(|f| f.name.contains("Admin"));
    } else {
        folders.retain(|f| !f.name.contains("Admin"));
    }

    let allowed_folder_uids: Vec<_> = folders.iter().map(|f| f.folder_uid.clone()).collect();

    let all_creds = secrets
        .iter()
        .filter(|r| allowed_folder_uids.contains(&r.folder_uid))
        .map(record_to_credential)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut result = vec![];

    for machine in machines {
        let machine = machine.as_ref();
        let cred = all_creds
            .iter()
            .find(|x| x.host() == machine)
            .ok_or(anyhow!("Failed to get credential for {machine}"))?;
        result.push(cred.clone());
    }

    Ok(result)
}
