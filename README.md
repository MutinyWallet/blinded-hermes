# Blind Hermes Service

## Usage

You need a postgres database and an authentication key. These can be set in the environment variables `DATABASE_URL`
These can be set in a `.env` file in the root of the project.

To run the server, run `cargo run --release` in the root of the project.

## Configuration

This service is configured via environment variables, which may be set in an `.env` file in the working directory, or injected dynamically (command-line prefix, container orchestration, etc.) See `.env.sample`.

 - `DATABASE_URL`: a postgres connection string of the format `postgres://u:p@host[:port]/dbname`
 - `HERMES_PORT`: (optional; default 8080) host port to bind

## Development

### Testing

Easiest way to run the unit and integrations test against a fresh postgres db: 

```
nix develop --command bash -c "just reset-db && just test && just test-integration"
```

### Database

Required just for the first time setup: 

```
diesel setup
```

#### Generating new migrations

To generate a new migration script. This will dump a few sql up/down files that you need to fill in:
```
diesel migration generate {migration_name}
```

Any time you change a migration, you should run this locally, this will set up the autogen code correctly:
```
diesel migration run
```

Migrations are NOT embedded into the code. You must shut down the server, run the below command locally, and then spin the server back up with the new version.

```
diesel migration run --database-url {PROD_DB_CONNECTION}
```

Replace PROD_DB_CONNECTION with the database config for production.
