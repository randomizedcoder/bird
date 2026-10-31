# nix/checks/deadnix.nix
#
# `deadnix` over every *.nix in the repo — unused lambda arguments, unused
# `let` bindings, dead `with` scopes.
#
# Not auto-fixed: `deadnix --edit` rewrites the lambda pattern but not the
# call sites, so dropping an argument breaks every `import ./foo.nix { … }`.
# Fix by hand, or prefix a required-but-unused argument with `_`.
#
{
  pkgs,
  src,
}:

pkgs.runCommand "bird-deadnix"
  {
    nativeBuildInputs = [
      pkgs.deadnix
      pkgs.findutils
    ];
    inherit src;
  }
  ''
    cd $src
    mapfile -t files < <(find . -type f -name '*.nix' -not -path './.git/*' | sort)
    # --fail turns findings into a non-zero exit.
    if ! deadnix --fail "''${files[@]}"; then
      echo "deadnix: dead Nix code found — remove the binding or prefix it with _" >&2
      exit 1
    fi
    echo "deadnix: no dead code in ''${#files[@]} *.nix file(s)" > $out
  ''
