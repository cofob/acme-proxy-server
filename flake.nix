{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    # Using flake-utils for perSystem boilerplate
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        # Import nixpkgs with the rust-overlay applied
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Formatter for nix files
        formatter = pkgs.nixfmt-rfc-style;

        # Development shell environment
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            nixfmt-rfc-style
            just
            uv
            acme-sh
            certbot
          ];

          shellHook = ''
            uv sync --all-groups --all-packages

            os_type=$(uname)
            if [[ "$os_type" == "Linux" ]] || [[ "$os_type" == "Darwin" ]]; then
              if [ -f ".venv/bin/activate" ]; then
                source .venv/bin/activate
              else
                echo "Error: .venv/bin/activate not found. Please ensure the virtual environment exists."
              fi
            else
              echo "Operating system is not Linux or macOS ($os_type). Skipping virtual environment activation."
            fi

            echo "Dev Shell Ready!"
          '';
        };
      }
    );
}
