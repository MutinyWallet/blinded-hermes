use crate::models::schema::app_user;
use diesel::prelude::*;
use fedimint_ln_common::bitcoin::secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
    pub invoice_index: i32,
    pub disabled_zaps: bool,
}

impl AppUser {
    pub fn pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(&self.pubkey).expect("invalid pubkey")
    }

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

    pub fn get_by_name_and_increment_counter(
        conn: &mut PgConnection,
        name: &str,
    ) -> anyhow::Result<Option<AppUser>> {
        conn.transaction(|conn| {
            let user = app_user::table
                .filter(app_user::name.eq(name))
                .first::<AppUser>(conn)
                .optional()?;

            // if the user exists, increment their invoice index
            if let Some(user) = &user {
                diesel::update(app_user::table.filter(app_user::id.eq(user.id)))
                    .set(app_user::invoice_index.eq(app_user::invoice_index + 1))
                    .execute(conn)?;
            }

            Ok(user)
        })
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

    pub fn update_federation(
        &self,
        conn: &mut PgConnection,
        new_federation_id: String,
        new_federation_invite_code: String,
    ) -> anyhow::Result<()> {
        diesel::update(app_user::table)
            .filter(app_user::name.eq(&self.name))
            .set((
                app_user::federation_id.eq(new_federation_id),
                app_user::federation_invite_code.eq(new_federation_invite_code),
                app_user::disabled_zaps.eq(false),
            ))
            .execute(conn)?;

        Ok(())
    }

    pub fn disable_zaps(&self, conn: &mut PgConnection) -> anyhow::Result<()> {
        diesel::update(app_user::table)
            .filter(app_user::name.eq(&self.name))
            .set((app_user::disabled_zaps.eq(true),))
            .execute(conn)?;

        Ok(())
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
