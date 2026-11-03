# nix/checks/default.nix
#
# Cheap `nix flake check` targets for the Nix tree itself. The bird build and
# the fuzz-harness replay are added to `checks` in flake.nix.

{ pkgs, src }:

{
  nix-fmt = import ./nix-fmt.nix { inherit pkgs src; };
  deadnix = import ./deadnix.nix { inherit pkgs src; };
  statix = import ./statix.nix { inherit pkgs src; };
}
