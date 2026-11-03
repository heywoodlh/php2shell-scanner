{
  description = "php2shell-scanner";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      forAllSystems = with nixpkgs; (lib.genAttrs lib.systems.flakeExposed);
      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python3Packages = pkgs.python3Packages;
        in
        {
          default = python3Packages.buildPythonApplication {
            pname = "php2shell-scanner";
            version = "0.1.0";
            pyproject = true;
            src = ./.;

            build-system = [ python3Packages.setuptools ];

            # run.py locates paths.txt next to itself via __file__, so install
            # it alongside the modules in site-packages. Detection and
            # enumeration are pure Python (scan.py / subdomains.py); no
            # external tools are needed at runtime.
            postInstall = ''
              cp paths.txt "$out/${python3Packages.python.sitePackages}/"
            '';

            doCheck = false;
          };
        }
      );

      inherit formatter;
    };
}
