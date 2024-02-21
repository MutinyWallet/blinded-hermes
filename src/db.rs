use diesel::{pg::PgConnection, r2d2::ConnectionManager, r2d2::Pool};
use std::sync::Arc;

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::models::app_user::{AppUser, NewAppUser};

#[cfg_attr(test, automock)]
pub(crate) trait DBConnection {
    fn check_name_available(&self, name: String) -> anyhow::Result<bool>;
    fn insert_new_user(&self, name: NewAppUser) -> anyhow::Result<AppUser>;
}

pub(crate) struct PostgresConnection {
    db: Pool<ConnectionManager<PgConnection>>,
}

impl DBConnection for PostgresConnection {
    fn check_name_available(&self, name: String) -> anyhow::Result<bool> {
        let conn = &mut self.db.get()?;
        AppUser::check_available_name(conn, name)
    }

    fn insert_new_user(&self, new_user: NewAppUser) -> anyhow::Result<AppUser> {
        let conn = &mut self.db.get()?;
        new_user.insert(conn)
    }
}

pub(crate) fn setup_db(url: String) -> Arc<dyn DBConnection + Send + Sync> {
    let manager = ConnectionManager::<PgConnection>::new(url);
    let pool = Pool::builder()
        .max_size(10) // should be a multiple of 100, our database connection limit
        .test_on_check_out(true)
        .build(manager)
        .expect("Unable to build DB connection pool");
    Arc::new(PostgresConnection { db: pool })
}
