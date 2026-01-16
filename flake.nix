{
  description = "Picoforge - Pico FIDO security keys commissioning tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        packages.default = pkgs.callPackage ./package.nix { };

        devShells.default = import ./shell.nix { inherit pkgs; };
      }
    );
}
