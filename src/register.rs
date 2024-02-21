use crate::State;
use lazy_regex::*;

pub static ALPHANUMERIC_REGEX: Lazy<Regex> = lazy_regex!("^[a-zA-Z0-9]+$");

pub fn is_valid_name(name: &str) -> bool {
    if name.len() > 30 {
        return false;
    }

    ALPHANUMERIC_REGEX.is_match(name)
}

pub async fn check_available(state: &State, name: String) -> anyhow::Result<bool> {
    if !is_valid_name(&name) {
        return Ok(false);
    }

    state.db.check_name_available(name)
}

#[cfg(all(test, not(feature = "integration-tests")))]
mod tests {
    use crate::register::is_valid_name;

    #[tokio::test]
    async fn check_name() {
        // bad names
        assert!(!is_valid_name("thisisoverthe30characternamelimit"));
        assert!(!is_valid_name("thisisoverthe30characternamelimit"));
        assert!(!is_valid_name("no!"));
        assert!(!is_valid_name("bad&name"));
        assert!(!is_valid_name("bad space name"));
        assert!(!is_valid_name("bad_name"));

        // good
        assert!(is_valid_name("goodname"));
        assert!(is_valid_name("goodname1"));
        assert!(is_valid_name("yesnameisverygoodandunderlimit"));
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests_integration {
    use secp256k1::Secp256k1;

    use crate::{db::setup_db, models::app_user::NewAppUser, register::check_available, State};

    #[tokio::test]
    async fn test_username_checker() {
        dotenv::dotenv().ok();
        let pg_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = setup_db(pg_url);
        let state = State {
            db: db.clone(),
            secp: Secp256k1::new(),
        };

        let name = "veryuniquename123".to_string();
        let available = check_available(&state, name).await.expect("should get");
        assert!(available);

        let commonname = "commonname".to_string();
        let common_app_user = NewAppUser {
            pubkey: "".to_string(),
            name: commonname.clone(),
            federation_id: "".to_string(),
            federation_invite_code: "".to_string(),
        };

        // don't care about error if already exists
        let _ = state.db.insert_new_user(common_app_user);

        let available = check_available(&state, commonname)
            .await
            .expect("should get");
        assert!(!available);
    }
}
