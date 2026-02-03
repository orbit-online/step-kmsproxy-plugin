let
  nixpkgs = builtins.fetchTarball "https://github.com/nixos/nixpkgs/tarball/25.11";
  pkgs = import nixpkgs { };
in
pkgs.mkShell {
  packages = [
    pkgs.go
    pkgs.pkg-config
    pkgs.pcsclite
  ];
}
