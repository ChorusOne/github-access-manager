{
  description = "GitHub Access Manager";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      name = "github-access-manager";
      version = builtins.substring 0 8 self.lastModifiedDate;
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
      {
        packages = forAllSystems (system:
          let
            pkgs = import nixpkgs { inherit system; };
          in
            {
              default = pkgs.stdenv.mkDerivation {
                inherit name version;
                src = ./.;
                buildInputs = [ pkgs.python311 ];
                installPhase = ''
                  mkdir --parents $out/bin
                  echo "#!${pkgs.python311}/bin/python3" > preamble
                  cat preamble main.py > $out/bin/github-access-manager
                  chmod +x $out/bin/github-access-manager
                '';
              };
            }
        );
      };
}
