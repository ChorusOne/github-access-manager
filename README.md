# GitHub Access Manager

GitHub Access Manager compares the current state of a GitHub organization
against a declarative target state specified in a TOML file. It then points out
any discrepancies so that you may reconcile them, either by changing settings on
GitHub or by editing your config file.

We might add limited support for reconciling some discrepancies automatically in
the future.

## Running

Run in an environment with all dependencies available with [Nix][nix] [2.3][nix-2.3]:

    nix run --command ./main.py

Alternatively, use Python 3.11 which has toml support in the standard library,
or set up a virtualenv and `pip install tomli`.

See the docstring in `main.py` for more information, or run with `--help`.

[nix]:     https://nixos.org/
[nix-2.3]: https://releases.nixos.org/?prefix=nix/nix-2.3/
