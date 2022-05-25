{ pkgs ? (import ./nixpkgs-pinned.nix) {} }:

let
  python = pkgs.python3.withPackages (ps: [
    ps.mypy # Mypy goes here so it has access to the types of dependencies.
  ]);
in
  pkgs.buildEnv {
    name = "github-access-manager-devenv";
    paths = [
      python
      pkgs.black
    ];
  }
