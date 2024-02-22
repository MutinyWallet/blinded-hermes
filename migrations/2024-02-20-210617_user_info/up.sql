CREATE TABLE app_user (
    id SERIAL PRIMARY KEY,
    pubkey VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL UNIQUE,
    federation_id VARCHAR(64) NOT NULL,
    federation_invite_code VARCHAR(255) NOT NULL
);

CREATE TABLE invoice (
    id SERIAL PRIMARY KEY,
    federation_id VARCHAR(64) NOT NULL,
    op_id VARCHAR(64) NOT NULL,
    app_user_id INTEGER NOT NULL references app_user(id),
    bolt11 VARCHAR(2048) NOT NULL,
    amount BIGINT NOT NULL,
    state INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE zaps
(
    id       INTEGER NOT NULL PRIMARY KEY references invoice (id),
    request  TEXT    NOT NULL,
    event_id VARCHAR(64)
);
