use crate::models::schema::zaps;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    QueryableByName,
    Queryable,
    Insertable,
    AsChangeset,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = zaps)]
pub struct Zap {
    pub id: i32,
    pub request: String,
    pub event_id: Option<String>,
}

impl Zap {
    pub fn insert(&self, conn: &mut PgConnection) -> anyhow::Result<()> {
        diesel::insert_into(zaps::table)
            .values(self)
            .execute(conn)?;

        Ok(())
    }

    pub fn get_zaps(conn: &mut PgConnection) -> anyhow::Result<Vec<Zap>> {
        Ok(zaps::table.load::<Self>(conn)?)
    }

    pub fn get_by_id(conn: &mut PgConnection, zap_id: i32) -> anyhow::Result<Option<Zap>> {
        Ok(zaps::table
            .filter(zaps::id.eq(zap_id))
            .first::<Zap>(conn)
            .optional()?)
    }

    pub fn set_event_id(&self, conn: &mut PgConnection, event_id: String) -> anyhow::Result<()> {
        diesel::update(zaps::table)
            .filter(zaps::id.eq(self.id))
            .set(zaps::event_id.eq(event_id))
            .execute(conn)?;

        Ok(())
    }
}
