use diesel::{pg::PgConnection, r2d2::ConnectionManager, r2d2::Pool};
use std::sync::Arc;

#[cfg(test)]
use mockall::{automock, predicate::*};

use crate::models::{
    app_user::{AppUser, NewAppUser},
    invoice::Invoice,
    zaps::Zap,
};

#[cfg_attr(test, automock)]
pub(crate) trait DBConnection {
    fn check_name_available(&self, name: String) -> anyhow::Result<bool>;
    fn insert_new_user(&self, name: NewAppUser) -> anyhow::Result<AppUser>;
    fn get_pending_invoices(&self) -> anyhow::Result<Vec<Invoice>>;
    fn set_invoice_state(&self, invoice: Invoice, s: i32) -> anyhow::Result<()>;
    fn get_user_by_name(&self, name: String) -> anyhow::Result<Option<AppUser>>;
    fn get_user_by_id(&self, id: i32) -> anyhow::Result<Option<AppUser>>;
    fn get_zap_by_id(&self, id: i32) -> anyhow::Result<Option<Zap>>;
    fn set_zap_event_id(&self, zap: Zap, event_id: String) -> anyhow::Result<()>;
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

    fn get_pending_invoices(&self) -> anyhow::Result<Vec<Invoice>> {
        let conn = &mut self.db.get()?;
        Invoice::get_by_state(conn, 0)
    }

    fn get_user_by_name(&self, name: String) -> anyhow::Result<Option<AppUser>> {
        let conn = &mut self.db.get()?;
        AppUser::get_by_name(conn, name)
    }

    fn get_user_by_id(&self, id: i32) -> anyhow::Result<Option<AppUser>> {
        let conn = &mut self.db.get()?;
        AppUser::get_by_id(conn, id)
    }

    fn set_invoice_state(&self, invoice: Invoice, s: i32) -> anyhow::Result<()> {
        let conn = &mut self.db.get()?;
        invoice.set_state(conn, s)
    }
    fn get_zap_by_id(&self, id: i32) -> anyhow::Result<Option<Zap>> {
        let conn = &mut self.db.get()?;
        Zap::get_by_id(conn, id)
    }
    fn set_zap_event_id(&self, zap: Zap, event_id: String) -> anyhow::Result<()> {
        let conn = &mut self.db.get()?;
        zap.set_event_id(conn, event_id)
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
