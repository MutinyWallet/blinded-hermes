// @generated automatically by Diesel CLI.

diesel::table! {
    app_user (id) {
        id -> Int4,
        #[max_length = 64]
        pubkey -> Varchar,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 255]
        unblinded_msg -> Varchar,
        #[max_length = 64]
        federation_id -> Varchar,
        #[max_length = 255]
        federation_invite_code -> Varchar,
        invoice_index -> Int4,
        disabled_zaps -> Bool,
    }
}

diesel::table! {
    invoice (id) {
        id -> Int4,
        #[max_length = 64]
        federation_id -> Varchar,
        #[max_length = 64]
        op_id -> Varchar,
        #[max_length = 64]
        preimage -> Varchar,
        app_user_id -> Int4,
        user_invoice_index -> Int4,
        #[max_length = 2048]
        bolt11 -> Varchar,
        amount -> Int8,
        state -> Int4,
        #[max_length = 100]
        lnurlp_comment -> Nullable<Varchar>,
    }
}

diesel::table! {
    zaps (id) {
        id -> Int4,
        request -> Text,
        #[max_length = 64]
        event_id -> Nullable<Varchar>,
    }
}

diesel::joinable!(invoice -> app_user (app_user_id));
diesel::joinable!(zaps -> invoice (id));

diesel::allow_tables_to_appear_in_same_query!(
    app_user,
    invoice,
    zaps,
);
