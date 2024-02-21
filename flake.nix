{
  description = "Nix package for Pacrat";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    utils.url = "github:numtide/flake-utils";
    flake-compat.url = "github:edolstra/flake-compat";
  };

  outputs =
    {
      nixpkgs,
      utils,
      ...
    }:
    utils.lib.eachDefaultSystem(system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        pacratServerPkg = pkgs.buildGoModule {
          pname = "pacrat-server";
          version = "0.1.0";

          src = ./.;

          vendorHash = null;

          modRoot = "./server";

          preInstall =
            ''
              mv $GOPATH/bin/{server,pacrat-server}
            '';

          meta = with nixpkgs.lib; {
            description = "A simple Arch Linux custom repository manager";
            homepage = "https://git.facekapow.dev/facekapow/pacrat";
            license = licenses.agpl3;
            maintainers = [];
          };
        };
      in
      {
        packages.default = pacratServerPkg;
        legacyPackages.pacrat-server = pacratServerPkg;
        nixosModules.default = { ... }: {
          imports = [ ./module.nix ];
          nixpkgs.overlays = [
            (self: super: {
              pacrat = pacratServerPkg;
            })
          ];
        };
      }
    );
}
