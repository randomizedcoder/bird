# nix/analysis/valgrind.nix
#
# Unit-test suite under valgrind memcheck. Build normally, then run every
# test program (the executable next to each */*_test.o) under valgrind with
# -f (no fork: birdtest otherwise forks a child per suite, and the child's
# report would be all that differs from the parent's). The tests read their
# config fixtures (filter/test.conf, ...) relative to the source root, so
# they run from there.
{ ctx, src }:

let
  inherit (ctx)
    pkgs
    mkAnalysisDrv
    configureBird
    scrubStore
    ;
in
mkAnalysisDrv {
  name = "valgrind";
  inherit src;
  extraNativeBuildInputs = ctx.packages.checkInputs ++ [ pkgs.valgrind ];

  buildPhase = ''
    runHook preBuild
    ${configureBird [ ]}
    make -j"$NIX_BUILD_CORES" all tests
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p $out "$TMPDIR/vg"
    : > $out/check.log
    for t in $(find obj -name '*_test.o' | sed 's/\.o$//' | sort); do
      [ -x "$t" ] || continue
      name=$(echo "''${t#obj/}" | tr / _)
      echo "=== $t" >> $out/check.log
      timeout 900 ${pkgs.valgrind}/bin/valgrind \
        --leak-check=full --errors-for-leak-kinds=definite \
        --log-file="$TMPDIR/vg/$name.%p.log" \
        "$t" -f >> $out/check.log 2>&1 \
        && echo "  exit 0" >> $out/check.log \
        || echo "  exit $?" >> $out/check.log
    done

    cat "$TMPDIR"/vg/*.log 2>/dev/null | ${scrubStore} | sed "s|$PWD/||g" > $out/report.txt || true
    errors=$(grep -oP 'ERROR SUMMARY: \K[0-9]+' $out/report.txt | awk '{s+=$1} END {print s+0}')
    lost=$(grep -oP 'definitely lost: \K[0-9,]+(?= bytes)' $out/report.txt | tr -d , | awk '{s+=$1} END {print s+0}')
    echo "$errors" > $out/count.txt
    {
      echo "=== valgrind memcheck (unit tests) ==="
      echo "logs: $(ls "$TMPDIR"/vg | wc -l)"
      echo "test exits: $(grep -c '  exit 0' $out/check.log) zero, $(grep -c '  exit [1-9]' $out/check.log) non-zero"
      echo "errors (sum of ERROR SUMMARY): $errors"
      echo "definitely lost bytes: $lost"
    } > $out/summary.txt
    cat $out/summary.txt
  '';
}
