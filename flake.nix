{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    naersk.url = "github:nix-community/naersk/master";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, utils, naersk, ... }:
  utils.lib.eachDefaultSystem (
    system:
      let
        pkgs = import nixpkgs { inherit system; }; 
        naersk' = pkgs.callPackage naersk { };
        deps = with pkgs; [
          cargo
          rustc
          libpcap
        ];
      in
      {
        defaultPackage = naersk'.buildPackage {
          src = ./.;
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];
          buildInputs = [ deps ];
          shellHook = ''
            export PKG_CONFIG_PATH=${pkgs.udev.dev}/lib/pkgconfig:${pkgs.alsa-lib.dev}/lib/pkgconfig:${pkgs.pkg-config}/lib/pkgconfig
            export LD_LIBRARY_PATH=${with pkgs; lib.makeLibraryPath deps}
          '';
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];
        buildInputs = [ deps ];
          shellHook = ''
            export PKG_CONFIG_PATH=${pkgs.udev.dev}/lib/pkgconfig:${pkgs.alsa-lib.dev}/lib/pkgconfig:${pkgs.pkg-config}/lib/pkgconfig
            export LD_LIBRARY_PATH=${with pkgs; lib.makeLibraryPath deps}
          '';
        };
      }
  );

}


