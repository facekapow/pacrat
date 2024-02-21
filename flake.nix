{
  description = "Nix package for Pacrat";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    utils.url = "github:numtide/flake-utils";
    flake-compat.url = "github:edolstra/flake-compat";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
      ...
    }: {
      overlays.default = final: prev: {
        pacrat-server = final.callPackage ./pacrat-server.nix {};
      };
    } // utils.lib.eachDefaultSystem(system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            self.overlays.default
          ];
        };
      in
      {
        packages = {
          inherit (pkgs) pacrat-server;
          default = pkgs.pacrat-server;
        };
        nixosModules.default = { ... }: {
          imports = [ ./module.nix ];
          nixpkgs.overlays = [
            self.overlays.default
          ];
        };
      }
    );
}
