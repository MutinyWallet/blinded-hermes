use crate::models::schema::app_user;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    QueryableByName, Queryable, AsChangeset, Serialize, Deserialize, Debug, Clone, PartialEq,
)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(table_name = app_user)]
pub struct AppUser {
    pub id: i32,
    pub pubkey: String,
    pub name: String,
    pub unblinded_msg: String,
    pub federation_id: String,
    pub federation_invite_code: String,
}

impl AppUser {
    pub fn get_app_users(conn: &mut PgConnection) -> anyhow::Result<Vec<AppUser>> {
        Ok(app_user::table.load::<Self>(conn)?)
    }

    pub fn get_by_id(conn: &mut PgConnection, user_id: i32) -> anyhow::Result<Option<AppUser>> {
        Ok(app_user::table
            .filter(app_user::id.eq(user_id))
            .first::<AppUser>(conn)
            .optional()?)
    }

    pub fn get_by_name(conn: &mut PgConnection, name: String) -> anyhow::Result<Option<AppUser>> {
        Ok(app_user::table
            .filter(app_user::name.eq(name))
            .first::<AppUser>(conn)
            .optional()?)
    }

    pub fn check_available_name(conn: &mut PgConnection, name: String) -> anyhow::Result<bool> {
        Ok(app_user::table
            .filter(app_user::name.eq(name))
            .count()
            .get_result::<i64>(conn)?
            == 0)
    }

    pub fn get_by_token(conn: &mut PgConnection, msg: String) -> anyhow::Result<Option<AppUser>> {
        Ok(app_user::table
            .filter(app_user::unblinded_msg.eq(msg))
            .first::<AppUser>(conn)
            .optional()?)
    }

    pub fn get_by_pubkey(
        conn: &mut PgConnection,
        pubkey: String,
    ) -> anyhow::Result<Option<AppUser>> {
        Ok(app_user::table
            .filter(app_user::pubkey.eq(pubkey))
            .first::<AppUser>(conn)
            .optional()?)
    }
}

#[derive(Insertable)]
#[diesel(table_name = app_user)]
pub struct NewAppUser {
    pub pubkey: String,
    pub name: String,
    pub federation_id: String,
    pub unblinded_msg: String,
    pub federation_invite_code: String,
}

impl NewAppUser {
    pub fn insert(&self, conn: &mut PgConnection) -> anyhow::Result<AppUser> {
        diesel::insert_into(app_user::table)
            .values(self)
            .get_result::<AppUser>(conn)
            .map_err(|e| e.into())
    }
}
