# nix/checks/nix-fmt.nix
#
# `nixfmt --check` over every *.nix in the repo. Fix with `nix fmt`.
#
{
  pkgs,
  src,
}:

pkgs.runCommand "bird-nix-fmt"
  {
    nativeBuildInputs = [
      pkgs.nixfmt
      pkgs.findutils
    ];
    inherit src;
  }
  ''
    cd $src
    bad=0
    while IFS= read -r f; do
      if ! nixfmt --check "$f" 2>/dev/null; then
        echo "nixfmt: not formatted: $f"
        bad=$((bad+1))
      fi
    done < <(find . -type f -name '*.nix' -not -path './.git/*')
    if [ "$bad" -gt 0 ]; then
      echo "nixfmt: $bad file(s) need formatting — run 'nix fmt'" >&2
      exit 1
    fi
    echo "nixfmt: all *.nix files formatted" > $out
  ''
