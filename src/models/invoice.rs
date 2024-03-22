use crate::models::schema::invoice;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    QueryableByName, Queryable, AsChangeset, Serialize, Deserialize, Debug, Clone, PartialEq,
)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = invoice)]
pub struct Invoice {
    pub id: i32,
    pub federation_id: String,
    pub op_id: String,
    pub preimage: String,
    pub app_user_id: i32,
    pub bolt11: String,
    pub amount: i64,
    pub state: i32,
}

impl Invoice {
    pub fn get_invoices(conn: &mut PgConnection) -> anyhow::Result<Vec<Invoice>> {
        Ok(invoice::table.load::<Self>(conn)?)
    }

    pub fn get_by_id(conn: &mut PgConnection, user_id: i32) -> anyhow::Result<Option<Invoice>> {
        Ok(invoice::table
            .filter(invoice::id.eq(user_id))
            .first::<Invoice>(conn)
            .optional()?)
    }

    pub fn get_by_operation(
        conn: &mut PgConnection,
        op_id: String,
    ) -> anyhow::Result<Option<Invoice>> {
        Ok(invoice::table
            .filter(invoice::op_id.eq(op_id))
            .first::<Invoice>(conn)
            .optional()?)
    }

    pub fn get_by_state(conn: &mut PgConnection, state: i32) -> anyhow::Result<Vec<Invoice>> {
        Ok(invoice::table
            .filter(invoice::state.eq(state))
            .load::<Invoice>(conn)?)
    }

    pub fn set_state(&self, conn: &mut PgConnection, s: i32) -> anyhow::Result<()> {
        diesel::update(invoice::table)
            .filter(invoice::id.eq(self.id))
            .set(invoice::state.eq(s))
            .execute(conn)?;

        Ok(())
    }
}

#[derive(Insertable)]
#[diesel(table_name = invoice)]
pub struct NewInvoice {
    pub federation_id: String,
    pub op_id: String,
    pub preimage: String,
    pub app_user_id: i32,
    pub bolt11: String,
    pub amount: i64,
    pub state: i32,
}

impl NewInvoice {
    pub fn insert(&self, conn: &mut PgConnection) -> anyhow::Result<Invoice> {
        diesel::insert_into(invoice::table)
            .values(self)
            .get_result::<Invoice>(conn)
            .map_err(|e| e.into())
    }
}
