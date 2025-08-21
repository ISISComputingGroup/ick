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

pub fn get_credentials(machines: &[String], admin: bool) -> Vec<Credential> {
    machines
        .iter()
        .map(|m| Credential {
            host: m.clone(),
            domain: m.clone(),
            username: "spudulike".to_owned(),
            password: "".to_owned(),
        })
        .collect()
}

mod tests {
    use super::*;

    #[test]
    fn test_foo() {}
}
