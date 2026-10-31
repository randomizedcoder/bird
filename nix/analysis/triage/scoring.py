"""Priority scoring, cross-tool correlation, and high-confidence filtering.

Ported from rocm-ernic (originally xdp2) via FRR for BIRD. Check IDs and noise
patterns are specific to C static analysis tools.
"""

from collections import defaultdict

from finding import Finding
from filters import is_security_sensitive, is_test_code


# flawfinder check_ids that are intentional patterns in system software
FLAWFINDER_NOISE = {
    'race.chmod', 'race.chown', 'race.access', 'race.vfork',
    'shell.system', 'shell.execl', 'shell.execlp', 'shell.execv', 'shell.execvp',
    'buffer.read', 'buffer.char', 'buffer.equal', 'buffer.memcpy',
    'buffer.strlen', 'buffer.getenv', 'buffer.wchar_t',
    'misc.open', 'random.random', 'tmpfile.mkstemp', 'access.umask',
    'format.snprintf', 'format.vsnprintf', 'misc.chroot',
}

# Bug-class check IDs that represent real correctness issues (not style)
BUG_CLASS_CHECKS = {
    # Correctness bugs
    'uninitMemberVar', 'unsignedLessThanZero',
    'core.UndefinedBinaryOperatorResult', 'core.NullDereference',
    'core.DivideZero', 'core.uninitialized',
    'core.uninitialized.Assign',
    # Bugprone clang-tidy checks
    'bugprone-use-after-move',
    'bugprone-sizeof-expression',
    'bugprone-integer-division',
    # Memory safety
    'unix.Malloc', 'unix.MismatchedDeallocator',
    'alpha.security.ArrayBoundV2', 'security.ArrayBound',
    'optin.taint.TaintedAlloc',
    # gcc -fanalyzer
    '-Wanalyzer-use-after-free', '-Wanalyzer-double-free',
    '-Wanalyzer-out-of-bounds', '-Wanalyzer-null-dereference',
    '-Wanalyzer-possible-null-dereference',
    '-Wanalyzer-use-of-uninitialized-value',
    '-Wanalyzer-tainted-array-index', '-Wanalyzer-tainted-size',
    '-Wanalyzer-tainted-allocation-size',
    # gcc warnings
    '-Wuse-after-free', '-Wstringop-overflow=', '-Warray-bounds=',
    # BIRD semgrep rules targeting wire parsing
    'wire-len-to-memcpy-unchecked', 'wire-len-advance-unchecked',
    'format-result-advance', 'format-result-accumulate',
}

# Style checks that shouldn't appear in high-confidence even in security code
STYLE_ONLY_CHECKS = {
    'constParameterPointer', 'constVariablePointer',
    'constParameter', 'constParameterCallback',
    'shadowVariable', 'shadowArgument', 'shadowFunction',
    'knownConditionTrueFalse', 'unusedStructMember',
    'variableScope',                    # Moving declarations is style, not bugs
    'bugprone-narrowing-conversions',   # size_t→ssize_t, uint→int: intentional in C networking code
    'bugprone-signed-char-misuse',      # Sign extension is intentional for error codes
}

# API-usage lints: they flag a construct (alloca, strcpy, bzero, sprintf,
# signedness), not a defect, and several tools flag the same construct. They
# stay in the full report but never count as high confidence and never make a
# location cross-tool: 3 tools all saying "alloca here" is not 3 votes.
HAZARD_PATTERN_TOOLS = {'flawfinder'}   # purely lexical

HAZARD_PATTERN_CHECKS = {
    # gcc-warnings
    '-Wpointer-sign', '-Walloca', '-Wvla', '-Wparentheses', '-Wcast-align',
    '-Wshadow=local', '-Wshadow=compatible-local',
    # cppcheck
    'allocaCalled', 'bzeroCalled', 'funcArgNamesDifferentUnnamed',
    'unreadVariable',
    # clang-tidy
    'bugprone-unsafe-functions',
    'bugprone-multi-level-implicit-pointer-conversion',
    'bugprone-switch-missing-default-case',
    # BIRD semgrep rules that flag a construct, not a missing check
    'bsprintf-unbounded', 'unsafe-sprintf', 'unsafe-strcpy-strcat',
    'strncpy-usage', 'alloca-usage', 'atoi-usage',
}

HAZARD_PATTERN_PREFIXES = (
    'clang-analyzer-security.insecureAPI.',
    'security.insecureAPI.',
)


def is_hazard_pattern(f) -> bool:
    """True for API-usage lints (see HAZARD_PATTERN_CHECKS).

    clang-tidy joins aliased checks with commas
    ("bugprone-unsafe-functions,cert-msc24-c"), so each part is tested.
    """
    if f.tool in HAZARD_PATTERN_TOOLS:
        return True
    for part in f.check_id.split(','):
        if part in HAZARD_PATTERN_CHECKS or part.startswith(HAZARD_PATTERN_PREFIXES):
            return True
    return False


# Prefixes excluded from high-confidence output
_HIGH_CONF_EXCLUDED_PREFIXES = (
    'readability-',
    'misc-include-cleaner', 'misc-use-internal-linkage',
    'misc-use-anonymous-namespace', 'misc-unused-parameters',
    'misc-const-correctness', 'misc-header-include-cycle',
    'misc-no-recursion',
    'cert-',
    # High-volume bugprone checks that are style/convention, not bugs
    'bugprone-reserved-identifier',         # _ / __ prefixed helpers are project convention
    'bugprone-easily-swappable-parameters', # Style — can't change existing API
    'bugprone-assignment-in-if-condition',  # Intentional C pattern: if ((x = func()))
    'bugprone-macro-parentheses',           # Style — many macros are correct without extra parens
    'bugprone-implicit-widening-of-multiplication-result',  # False positives in packet offset math
)


def priority_score(f, category_counts: dict) -> int:
    """Higher score = higher priority. Range roughly 0-100."""
    score = 0

    # Severity
    if f.severity == 'error':
        score += 40
    elif f.severity == 'warning':
        score += 20

    # Security-sensitive location
    if is_security_sensitive(f.file):
        score += 20

    # Test code is lower priority
    if is_test_code(f.file):
        score -= 15

    # Small-count categories are anomalies (more likely real bugs)
    count = category_counts.get(f.check_id, 999)
    if count <= 3:
        score += 30
    elif count <= 10:
        score += 20
    elif count <= 30:
        score += 10

    return score


def find_cross_tool_hits(findings: list, tolerance: int = 3) -> list:
    """Find file:line pairs flagged by 2+ independent tools.

    Uses a tolerance of +/-N lines to account for minor line number differences.
    """
    # Group findings by file
    by_file = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)

    clusters = []
    for filepath, file_findings in by_file.items():
        # Sort by line
        file_findings.sort(key=lambda f: f.line)

        # For each pair of findings from different tools, check proximity
        for i, f1 in enumerate(file_findings):
            cluster = [f1]
            for f2 in file_findings[i + 1:]:
                if f2.line > f1.line + tolerance:
                    break
                if f2.tool != f1.tool:
                    cluster.append(f2)
            if len(set(f.tool for f in cluster)) >= 2:
                clusters.append(cluster)

    # Deduplicate overlapping clusters
    seen_keys = set()
    unique_clusters = []
    for cluster in clusters:
        key = frozenset((f.tool, f.file, f.line) for f in cluster)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_clusters.append(cluster)

    return unique_clusters


def get_high_confidence(findings: list) -> list:
    """Return high-confidence findings as (Finding, score, is_cross) tuples, sorted by score."""
    # Compute category counts
    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.check_id] += 1

    # Find cross-tool correlations among findings that point at a defect
    semantic = [f for f in findings
                if f.check_id not in FLAWFINDER_NOISE and not is_hazard_pattern(f)]
    cross_hits = find_cross_tool_hits(semantic)
    cross_locations = set()
    for cluster in cross_hits:
        for f in cluster:
            cross_locations.add((f.file, f.line))

    high_conf = []
    for f in findings:
        # Skip noise categories entirely from high-confidence
        if f.check_id in FLAWFINDER_NOISE or f.check_id in STYLE_ONLY_CHECKS:
            continue
        if is_hazard_pattern(f):
            continue
        # Skip excluded prefixes (style, not bugs)
        if any(f.check_id.startswith(p) for p in _HIGH_CONF_EXCLUDED_PREFIXES):
            continue

        score = priority_score(f, cat_counts)
        is_cross = (f.file, f.line) in cross_locations
        is_bug_class = f.check_id in BUG_CLASS_CHECKS
        is_small_cat = cat_counts[f.check_id] <= 3
        # Only cppcheck/clang-analyzer error-severity in security code
        is_security_bug = (is_security_sensitive(f.file) and f.severity == 'error'
                           and f.tool in ('cppcheck', 'clang-analyzer', 'gcc-analyzer'))

        if is_cross or is_bug_class or (is_small_cat and score >= 60) or is_security_bug:
            high_conf.append((f, score, is_cross))

    # Sort by score descending
    high_conf.sort(key=lambda x: -x[1])
    return high_conf
