{ pkgs ? (import ./nixpkgs-pinned.nix) {} }:

let
  python = pkgs.python3.withPackages (ps: [
    ps.mypy # Mypy goes here so it has access to the types of dependencies.
    ps.tomli
  ]);
in
  pkgs.buildEnv {
    name = "github-access-manager-devenv";
    paths = [
      python
      pkgs.black
    ];
  }
