# nix/checks/statix.nix
#
# `statix check` over every *.nix in the repo — Nix antipatterns (manual
# inherit, useless parens, redundant `rec`, …). Companion to deadnix.nix.
#
{
  pkgs,
  src,
}:

pkgs.runCommand "bird-statix"
  {
    nativeBuildInputs = [ pkgs.statix ];
    inherit src;
  }
  ''
    cd $src
    if ! statix check -i .git -o errfmt .; then
      echo "statix: Nix antipatterns found — 'statix fix <file>' applies the" >&2
      echo "        mechanical ones; re-run 'nix fmt' afterwards." >&2
      exit 1
    fi
    echo "statix: no antipatterns" > $out
  ''
