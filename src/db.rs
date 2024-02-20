use diesel::{pg::PgConnection, r2d2::ConnectionManager, r2d2::Pool, Connection};
use std::sync::Arc;

#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
pub(crate) trait DBConnection {
    // fn get_services(&self) -> anyhow::Result<Vec<Service>>;
}

pub(crate) struct PostgresConnection {
    db: Pool<ConnectionManager<PgConnection>>,
}

impl DBConnection for PostgresConnection {
    /*
    fn get_services(&self) -> anyhow::Result<Vec<Service>> {
        let conn = &mut self.db.get()?;
        Service::get_services(conn)
    }
    */
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
