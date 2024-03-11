test:
    cargo test

test-integration:
    cargo test --features integration-tests

run:
    RUST_LOG=debug cargo run

release:
    cargo run --release

clippy:
    cargo clippy --all-features --tests -- -D warnings

reset-db:
    diesel migration revert --all && diesel migration run
