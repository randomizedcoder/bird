"""Table-driven unit tests for the triage package.

Run: python3 -m unittest discover -s nix/analysis/triage -p 'test_*.py'
(also run by the `triage-tests` flake check).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from finding import Finding, normalize_path, normalize_severity  # noqa: E402
from filters import (  # noqa: E402
    deduplicate, filter_findings, is_generated, is_security_sensitive,
    is_test_code, is_third_party,
)
from parsers import clang, flawfinder, semgrep  # noqa: E402
from scoring import find_cross_tool_hits, get_high_confidence  # noqa: E402

STORE = '/nix/store/' + 'a' * 32 + '-bird-analysis-compile-db/'


def mk(tool='cppcheck', check='nullPointer', sev='error',
       file='proto/bgp/attrs.c', line=10, msg='m'):
    return Finding(tool, check, sev, file, line, msg)


class TestNormalize(unittest.TestCase):
    def test_normalize_path(self):
        rows = [
            {'description': 'store prefix stripped',
             'input': STORE + 'proto/bgp/attrs.c', 'expected': 'proto/bgp/attrs.c'},
            {'description': 'already relative unchanged',
             'input': 'lib/flowspec.c', 'expected': 'lib/flowspec.c'},
            {'description': 'double slash collapsed',
             'input': STORE + 'lib//flowspec.c', 'expected': 'lib/flowspec.c'},
            {'description': 'empty string',
             'input': '', 'expected': ''},
            {'description': 'short hash is not a store prefix',
             'input': '/nix/store/abc-x/lib/a.c', 'expected': '/nix/store/abc-x/lib/a.c'},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(normalize_path(r['input']), r['expected'])

    def test_normalize_severity(self):
        rows = [
            {'description': 'error', 'input': 'error', 'expected': 'error'},
            {'description': 'flawfinder level 5', 'input': '5', 'expected': 'error'},
            {'description': 'flawfinder level 3', 'input': '3', 'expected': 'warning'},
            {'description': 'cppcheck style', 'input': 'style', 'expected': 'style'},
            {'description': 'case + whitespace', 'input': ' WARNING ', 'expected': 'warning'},
            {'description': 'unknown defaults to warning', 'input': 'weird', 'expected': 'warning'},
            {'description': 'level 0 boundary', 'input': '0', 'expected': 'style'},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(normalize_severity(r['input']), r['expected'])


class TestClassifiers(unittest.TestCase):
    def test_paths(self):
        rows = [
            {'description': 'bgp attr parser is in scope and sensitive',
             'path': 'proto/bgp/attrs.c',
             'expected': (False, False, False, True)},
            {'description': 'bison output under obj/ is generated and out of scope',
             'path': 'obj/conf/cf-parse.tab.c',
             'expected': (True, True, False, False)},
            {'description': 'm4 filter interpreter is generated',
             'path': 'obj/filter/inst-interpret.c',
             'expected': (True, True, False, False)},
            {'description': 'unit test beside the code is test code',
             'path': 'lib/flowspec_test.c',
             'expected': (False, False, True, False)},
            {'description': 'test framework dir out of scope and test code',
             'path': 'test/birdtest.c',
             'expected': (True, False, True, False)},
            {'description': 'system header out of scope',
             'path': 'usr/include/string.h',
             'expected': (True, False, False, False)},
            {'description': 'client in scope, not sensitive',
             'path': 'client/client.c',
             'expected': (False, False, False, False)},
            {'description': 'prefix match must be anchored',
             'path': 'xproto/bgp/attrs.c',
             'expected': (True, False, False, False)},
            {'description': 'netlink is sensitive',
             'path': 'sysdep/linux/netlink.c',
             'expected': (False, False, False, True)},
        ]
        for r in rows:
            with self.subTest(r['description']):
                p = r['path']
                got = (is_third_party(p), is_generated(p),
                       is_test_code(p), is_security_sensitive(p))
                self.assertEqual(got, r['expected'])

    def test_filter_findings(self):
        rows = [
            {'description': 'normal finding kept',
             'finding': mk(), 'expected': 1},
            {'description': 'excluded check id dropped',
             'finding': mk(check='missingIncludeSystem'), 'expected': 0},
            {'description': 'line 0 dropped (boundary)',
             'finding': mk(line=0), 'expected': 0},
            {'description': 'line 1 kept (boundary)',
             'finding': mk(line=1), 'expected': 1},
            {'description': 'fortify message dropped',
             'finding': mk(msg='_FORTIFY_SOURCE requires'), 'expected': 0},
            {'description': 'out-of-root dropped',
             'finding': mk(file='tools/x.c'), 'expected': 0},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(len(filter_findings([r['finding']])), r['expected'])

    def test_deduplicate(self):
        rows = [
            {'description': 'empty', 'input': [], 'expected': 0},
            {'description': 'same key twice collapses',
             'input': [mk(), mk(msg='other')], 'expected': 1},
            {'description': 'different line kept',
             'input': [mk(), mk(line=11)], 'expected': 2},
            {'description': 'different check kept',
             'input': [mk(), mk(check='uninitvar')], 'expected': 2},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(len(deduplicate(r['input'])), r['expected'])


class TestScoring(unittest.TestCase):
    def test_cross_tool(self):
        rows = [
            {'description': 'two tools same line -> one cluster',
             'input': [mk(), mk(tool='clang-tidy', check='x')], 'expected': 1},
            {'description': 'two tools within tolerance (3 lines)',
             'input': [mk(), mk(tool='clang-tidy', check='x', line=13)], 'expected': 1},
            {'description': 'two tools beyond tolerance',
             'input': [mk(), mk(tool='clang-tidy', check='x', line=14)], 'expected': 0},
            {'description': 'same tool twice is not cross',
             'input': [mk(), mk(check='x')], 'expected': 0},
            {'description': 'different files never cluster',
             'input': [mk(), mk(tool='clang-tidy', file='lib/ip.c')], 'expected': 0},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(len(find_cross_tool_hits(r['input'])), r['expected'])

    def test_high_confidence(self):
        rows = [
            {'description': 'bug-class check is high confidence',
             'input': [mk(tool='clang-analyzer', check='core.NullDereference', sev='warning')],
             'expected': 1},
            {'description': 'readability prefix excluded',
             'input': [mk(tool='clang-tidy', check='readability-foo')], 'expected': 0},
            {'description': 'flawfinder noise excluded',
             'input': [mk(tool='flawfinder', check='buffer.memcpy')], 'expected': 0},
            {'description': 'semgrep wire rule is bug class',
             'input': [mk(tool='semgrep', check='wire-len-to-memcpy-unchecked', sev='warning')],
             'expected': 1},
            {'description': 'cppcheck error in security path',
             'input': [mk(check='someRareThing')], 'expected': 1},
            {'description': 'style-only check excluded',
             'input': [mk(check='variableScope', sev='style')], 'expected': 0},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(len(get_high_confidence(r['input'])), r['expected'])


class TestParsers(unittest.TestCase):
    def _parse(self, mod, text, *args):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as t:
            t.write(text)
        try:
            return mod.parse(t.name, *args)
        finally:
            os.unlink(t.name)

    def test_clang_lines(self):
        rows = [
            {'description': 'clang-tidy warning',
             'line': STORE + 'proto/bgp/attrs.c:12:3: warning: x y [bugprone-foo]',
             'expected': ('proto/bgp/attrs.c', 12, 'bugprone-foo', 'warning')},
            {'description': 'gcc analyzer with CWE tag keeps last bracket',
             'line': 'lib/ip.c:5:1: warning: deref of NULL [CWE-476] [-Wanalyzer-null-dereference]',
             'expected': ('lib/ip.c', 5, '-Wanalyzer-null-dereference', 'warning')},
            {'description': 'note lines ignored',
             'line': 'lib/ip.c:5:1: note: here [x]', 'expected': None},
            {'description': 'no check id ignored',
             'line': 'lib/ip.c:5:1: warning: plain', 'expected': None},
        ]
        for r in rows:
            with self.subTest(r['description']):
                got = self._parse(clang, r['line'] + '\n', 'clang-tidy')
                if r['expected'] is None:
                    self.assertEqual(got, [])
                else:
                    f = got[0]
                    self.assertEqual((f.file, f.line, f.check_id, f.severity), r['expected'])

    def test_flawfinder_lines(self):
        rows = [
            {'description': 'level 4 strcpy',
             'line': 'proto/bgp/a.c:7:2:  [4] (buffer) strcpy:Does not check',
             'expected': ('buffer.strcpy', 'error', 7)},
            {'description': 'level 1 boundary',
             'line': 'proto/bgp/a.c:8:2:  [1] (buffer) strlen:Does not handle',
             'expected': ('buffer.strlen', 'style', 8)},
            {'description': 'garbage ignored',
             'line': 'Hits = 12', 'expected': None},
        ]
        for r in rows:
            with self.subTest(r['description']):
                got = self._parse(flawfinder, r['line'] + '\n')
                if r['expected'] is None:
                    self.assertEqual(got, [])
                else:
                    f = got[0]
                    self.assertEqual((f.check_id, f.severity, f.line), r['expected'])


class TestSemgrep(unittest.TestCase):
    def test_rule_id(self):
        rows = [
            {'description': 'nix store config prefix stripped',
             'input': 'nix.store.wire-len-to-memcpy-unchecked',
             'expected': 'wire-len-to-memcpy-unchecked'},
            {'description': 'deeper path prefix stripped',
             'input': 'home.das.bird.nix.analysis.format-result-advance',
             'expected': 'format-result-advance'},
            {'description': 'bare id unchanged',
             'input': 'unsafe-sprintf', 'expected': 'unsafe-sprintf'},
            {'description': 'empty string',
             'input': '', 'expected': ''},
            {'description': 'trailing dot yields empty id (boundary)',
             'input': 'nix.store.', 'expected': ''},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(semgrep.rule_id(r['input']), r['expected'])

    def test_parse_report(self):
        report = ('{"results": [{"check_id": "nix.store.wire-len-advance-unchecked",'
                  ' "path": "/nix/store/' + 'a' * 32 + '-src/proto/bgp/attrs.c",'
                  ' "start": {"line": 291}, "extra": {"severity": "WARNING",'
                  ' "message": "m"}}], "errors": []}')
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as t:
            t.write(report)
        try:
            got = semgrep.parse(t.name)
        finally:
            os.unlink(t.name)
        rows = [
            {'description': 'one finding', 'actual': len(got), 'expected': 1},
            {'description': 'prefix stripped', 'actual': got[0].check_id,
             'expected': 'wire-len-advance-unchecked'},
            {'description': 'path repo-relative', 'actual': got[0].file,
             'expected': 'proto/bgp/attrs.c'},
            {'description': 'severity normalized', 'actual': got[0].severity,
             'expected': 'warning'},
        ]
        for r in rows:
            with self.subTest(r['description']):
                self.assertEqual(r['actual'], r['expected'])

    def test_missing_report(self):
        self.assertEqual(semgrep.parse('/nonexistent/report.json'), [])


if __name__ == '__main__':
    unittest.main()
