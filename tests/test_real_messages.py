#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""The sample messages in emails/: their recorded results, and what must always hold.

Two layers. `TestExpectedResults` compares each sample against the result
recorded for it in expected/, which catches a changed answer. `TestRealMessages`
asserts only what must hold for any message at all, which catches a malformed
one — and keeps holding when the samples are replaced.

See README.md in this directory for how to run these.
"""

import difflib
import json
import unittest

from support import (EMAIL_DIR, EXPECTED_DIR, REGENERATE, evaluate_sample, expected_path,
                     format_expected, load_expected, msi, sample_messages)


def result_diff(expected: dict, actual: dict, name: str) -> str:
    """A readable unified diff between a recorded result and a fresh one."""
    lines = difflib.unified_diff(format_expected(expected).splitlines(),
                                 format_expected(actual).splitlines(),
                                 fromfile='expected/' + name, tofile='actual', lineterm='',
                                 n=2)

    return '\n'.join(lines)


@unittest.skipUnless(EMAIL_DIR.is_dir(), 'no emails/ sample messages')
class TestExpectedResults(unittest.TestCase):
    """Every sample message still evaluates to the result recorded for it.

    The invariant tests below cannot tell a right answer from a wrong one, only
    a well-formed one from a malformed one. These can: expected/<name>.json
    holds the complete result for emails/<name>.eml under default settings, so
    any change in what the program says about a real message — a verdict, a
    domain, a rendered note, a raw header — fails here with a diff.

    A failure is not automatically a bug. It means the reported answer moved:
    read the diff, decide whether the new answer is the better one, and if it
    is, re-record it with `python tests/update_expected.py` and commit the diff
    along with the change that caused it.
    """

    @classmethod
    def setUpClass(cls):
        cls.paths = sample_messages()

    def test_every_sample_has_a_recorded_result(self):
        missing = [path.name for path in self.paths if not expected_path(path).is_file()]
        self.assertEqual(missing, [], 'no result recorded yet — run ' + REGENERATE)

    def test_no_recorded_result_outlives_its_message(self):
        stale = sorted(path.name for path in EXPECTED_DIR.glob('*.json')
                       if not (EMAIL_DIR / (path.stem + '.eml')).is_file())
        self.assertEqual(stale, [], 'sample message gone — run ' + REGENERATE + ' --prune')

    def test_each_sample_matches_its_recorded_result(self):
        for path in self.paths:
            if not expected_path(path).is_file():
                continue  # Already reported, once, by the test above.

            with self.subTest(message=path.name):
                expected = load_expected(path)
                actual = evaluate_sample(path)
                if actual != expected:
                    self.fail('{} no longer evaluates as recorded. If the new answer is '
                              'the correct one, re-record it with `{}`.\n\n{}'.format(
                                  path.name, REGENERATE, result_diff(expected, actual, path.name)))

    def test_the_recorded_results_are_current_format(self):
        # A file hand-edited into a shape the program would never produce would
        # otherwise sit there asserting nothing until its sample changed.
        for path in self.paths:
            if not expected_path(path).is_file():
                continue

            with self.subTest(message=path.name):
                self.assertEqual(expected_path(path).read_text('utf-8'),
                                 format_expected(load_expected(path)),
                                 'not in recorded form — run ' + REGENERATE)


@unittest.skipUnless(EMAIL_DIR.is_dir(), 'no emails/ sample messages')
class TestRealMessages(unittest.TestCase):
    """Smoke test over the sample messages in tests/emails/.

    Real headers are far messier than hand-written ones (many Received hops,
    several DKIM signatures, encoded words, odd whitespace), so these assert
    only what must hold for any message — never anything about their content,
    which lets the samples be replaced or obfuscated freely.
    """

    #: The fixed shape every security finding must have.
    ENTRY_KEYS = {'present', 'verified', 'status', 'domain', 'aligned', 'verdict',
                  'description'}

    @classmethod
    def setUpClass(cls):
        cls.paths = sample_messages()

    def test_every_sample_evaluates(self):
        for path in self.paths:
            with self.subTest(message=path.name):
                result = msi.evaluate_message_security_info(
                    str(path), msi.SecurityInfoConfig(extra_headers=['Message-ID', 'Return-Path']))

                self.assertIn(result['status'], ('pass', 'warn', 'fail', 'unknown'))
                self.assertIn(result['dkim_from'], ('pass', 'warn', 'fail', 'unknown', 'none'))
                self.assertEqual(result['dkim_from'], result['security']['dkim']['verdict'])
                self.assertEqual(result['summary'], msi.i18n_gettext('summary' + result['status']))
                # The sender and the transport, both with something to show.
                self.assertEqual(set(result['info']), {'header-from', 'transport'})
                self.assertTrue(all(result['info'].values()))
                # Every mechanism reported, each in the documented fixed shape.
                self.assertEqual(list(result['security']), ['spf', 'dkim', 'dmarc'])
                for method, entry in result['security'].items():
                    self.assertEqual(set(entry), self.ENTRY_KEYS, method)
                    self.assertIn(entry['verdict'], ('pass', 'warn', 'fail', 'unknown', 'none'))
                    self.assertIsInstance(entry['present'], bool)
                    self.assertIsInstance(entry['verified'], bool)
                    # A status is a bare protocol token, never a rendered line.
                    if entry['status'] is not None:
                        self.assertRegex(entry['status'], r'^[A-Z]+$')

                self.assertEqual(json.loads(json.dumps(result)), result)

    def test_the_status_is_the_worst_of_the_findings_shown(self):
        # Nothing may decide the verdict off to one side: whatever the report
        # says about a real message, the headline is exactly the worst of the
        # per-mechanism verdicts printed beneath it. A reader who disagrees with
        # the headline can always point at the line that produced it.
        engine = msi.MessageSecurityInfo(msi.SecurityInfoConfig())
        for path in self.paths:
            with self.subTest(message=path.name):
                result = msi.evaluate_message_security_info(str(path))
                verdicts = [entry['verdict'] for entry in result['security'].values()]
                self.assertEqual(result['status'], engine.combine_statuses(verdicts))

    def test_no_raw_header_value_is_folded(self):
        for path in self.paths:
            with self.subTest(message=path.name):
                result = msi.evaluate_message_security_info(str(path))
                for header in result['headers']:
                    self.assertNotIn('\n', header['value'])

    def test_every_sample_renders_a_report(self):
        for path in self.paths:
            with self.subTest(message=path.name):
                result = msi.evaluate_message_security_info(str(path))
                report = msi.format_report(result, color=True)

                self.assertIn(msi.i18n_gettext('linktitle'), report)
                self.assertIn(msi.i18n_gettext('frommarker' + result['dkim_from']), report)
                # Printable on any stdout encoding, i.e. no stray surrogates.
                report.encode('utf-8')

    def test_evaluation_is_deterministic(self):
        for path in self.paths:
            with self.subTest(message=path.name):
                self.assertEqual(msi.evaluate_message_security_info(str(path)),
                                 msi.evaluate_message_security_info(str(path)))

    def test_a_trust_list_drops_all_untrusted_evidence(self):
        # Distrusting every authserv-id must leave no DKIM or DMARC verdict.
        for path in self.paths:
            with self.subTest(message=path.name):
                filtered = msi.evaluate_message_security_info(
                    str(path), msi.SecurityInfoConfig(trusted_authserv=['nobody.invalid']))
                security = filtered['security']

                # Signed, but with every stamped result distrusted nothing
                # confirms it: 'unknown', never a pass, warn or fail.
                self.assertEqual(filtered['dkim_from'], 'unknown')
                self.assertFalse(filtered['security']['dkim']['verified'])
                self.assertFalse(security['dkim']['verified'])
                self.assertIsNone(security['dkim']['status'])
                self.assertEqual(security['dmarc']['status'], None)
                self.assertFalse(security['dmarc']['present'])

                # A Received-SPF header carries no authserv-id, so it cannot be
                # trust-filtered and may still produce a pass on its own; without
                # one there is nothing left to pass on.
                if not msi.load_headers(str(path)).get('Received-SPF'):
                    self.assertIn(filtered['status'], ('warn', 'unknown'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
