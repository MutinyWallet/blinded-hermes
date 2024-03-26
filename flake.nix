{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        craneLib = crane.lib.${system};
        my-crate = craneLib.buildPackage {
          src = craneLib.cleanCargoSource (craneLib.path ./.);

          buildInputs = [
            pkgs.just
            pkgs.openssl
            pkgs.openssl.dev
            pkgs.zlib
            pkgs.postgresql
            pkgs.gcc
            pkgs.gcc.cc.lib
            pkgs.pkg-config
            pkgs.libclang.lib
            pkgs.clang
            pkgs.flyctl
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];
        };

        setupPostgresScript = pkgs.writeShellScript "setup-postgres" ''
          export PGDATA=$(mktemp -d)
          export PGSOCKETS=$(mktemp -d)
          ${pkgs.postgresql}/bin/initdb -D $PGDATA
          ${pkgs.postgresql}/bin/pg_ctl start -D $PGDATA -o "-h localhost -p 5432 -k $PGSOCKETS"
          until ${pkgs.postgresql}/bin/pg_isready -h localhost -p 5432; do sleep 1; done
          ${pkgs.postgresql}/bin/createuser -h localhost -p 5432 -s postgres
          ${pkgs.postgresql}/bin/psql -h localhost -p 5432 -c "CREATE USER \"hermes_user\" WITH PASSWORD 'password';" -U postgres
          ${pkgs.postgresql}/bin/psql -h localhost -p 5432 -c "CREATE DATABASE \"hermes\" OWNER \"hermes_user\";" -U postgres
	  exit
        '';

        setupEnvScript = pkgs.writeShellScript "setup-env" ''
          if [ ! -f .env ]; then
            cp .env.sample .env
            sed -i 's|DATABASE_URL=postgres://localhost/hermes|DATABASE_URL=postgres://hermes_user:password@localhost:5432/hermes|g' .env
	    # random nsec for CI only
            sed -i 's|NSEC=|NSEC=nsec1lmtupx60q0pg6lk3kcl0c56mp7xukulmcc2rxu3gd6sage8xzxhs3slpac|g' .env
	    # localhost domain
            sed -i 's|DOMAIN_URL=|DOMAIN_URL=http://127.0.0.1:8080|g' .env
          fi
        '';

	setupFedimintTestDirScript = pkgs.writeShellScript "setup-fedimint-test-dir" ''
          if [ -d .fedimint-test-dir ]; then
            rm -rf .fedimint-test-dir
          fi
          mkdir -m 700 .fedimint-test-dir
        '';

      in
      {
        packages.default = my-crate;

        devShells.default = craneLib.devShell {
          inputsFrom = [ my-crate ];
          packages = [
            pkgs.just
            pkgs.openssl
            pkgs.openssl.dev
            pkgs.zlib
            pkgs.postgresql
            pkgs.gcc
            pkgs.rust-analyzer
            pkgs.diesel-cli
            pkgs.gcc.cc.lib
            pkgs.pkg-config
            pkgs.libclang.lib
            pkgs.clang
            pkgs.flyctl
          ];
          shellHook = ''
            export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
            export LD_LIBRARY_PATH=${pkgs.openssl}/bin:${pkgs.gcc.cc.lib}/lib:$LD_LIBRARY_PATH
            export PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig
            
            ${setupPostgresScript}
            ${setupEnvScript}
            ${setupFedimintTestDirScript}
          '';
        };
      });
}
