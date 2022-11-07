# GitHub Access Manager

GitHub Access Manager compares the current state of a GitHub organization
against a declarative target state specified in a TOML file. It then points out
any discrepancies so that you may reconcile them, either by changing settings on
GitHub or by editing your config file.

We might add limited support for reconciling some discrepancies automatically in
the future.

## Running

GitHub access manager needs Python 3.11 or later (for TOML support) and has no
dependencies outside of the standard library.

    ./main.py --help
    ./main.py config.toml

Optionally, a Nix flake is provided to run with a pinned Python version. You
need [Nix 2.10 or later](https://nixos.org/download.html). Then run `nix`
with either `--extra-experimental-features nix-command` and
`--extra-experimental-features flakes`, or add them to your
`~/.config/nix/nix.conf`:

    experimental-features = nix-command flakes

Then run with Nix:

    nix run . -- --help
    nix run . -- config.toml

You can also enter a shell with the right Python version in the environment:

    nix develop
    ./main.py --help
