# nix/analysis/roots.nix
#
# Which BIRD directories the analysers look at: the daemon (nest, conf,
# filter, lib, proto, sysdep) and the client. test/, misc/, doc/, tools/
# and the generated sources under obj/ are excluded. Shared by the runners
# (as find/flawfinder arguments) and triage (as path filters).
{
  dirs = [
    "client"
    "conf"
    "filter"
    "lib"
    "nest"
    "proto"
    "sysdep"
  ];

  # Unit tests live next to the code (lib/ip_test.c); generated sources
  # (bison/flex/m4) live under obj/, which no root matches. Regex for
  # grep -E -v.
  generatedRegex = "(_test\\.c)$";
}
