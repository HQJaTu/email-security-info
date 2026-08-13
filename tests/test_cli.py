#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""The command line end to end: file and stdin input, output modes, exit codes.

See README.md in this directory for how to run these.
"""

import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from support import FAIL_EML, PASS_EML, UNALIGNED_EML, UNVERIFIED_EML, msi


class TestCommandLine(unittest.TestCase):
    """Argument handling, file/stdin input and exit codes."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = pathlib.Path(directory.name)

    def write(self, name: str, content: bytes) -> str:
        path = self.dir / name
        path.write_bytes(content)

        return str(path)

    def run_main(self, *argv) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = msi.main(list(argv))

        return code, out.getvalue()

    def test_text_report_of_a_file(self):
        code, out = self.run_main('--color', 'never', self.write('pass.eml', PASS_EML))
        self.assertEqual(code, 0)
        self.assertIn('PASS', out)

    def test_json_output(self):
        code, out = self.run_main('--json', self.write('fail.eml', FAIL_EML))
        result = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['dkim_from'], 'fail')

    def test_stdin_input(self):
        stdin = mock.Mock(buffer=io.BytesIO(PASS_EML))
        with mock.patch.object(sys, 'stdin', stdin):
            code, out = self.run_main('--json', '-')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['status'], 'pass')

    def test_exit_status_is_off_by_default(self):
        code, _ = self.run_main('--color', 'never', self.write('fail.eml', FAIL_EML))
        self.assertEqual(code, 0)

    def test_exit_status_maps_the_verdict(self):
        cases = {'pass.eml': (PASS_EML, 0), 'warn.eml': (UNALIGNED_EML, 3),
                 'fail.eml': (FAIL_EML, 4), 'unknown.eml': (UNVERIFIED_EML, 5)}
        for name, (message, expected) in cases.items():
            with self.subTest(name=name):
                code, _ = self.run_main('--exit-status', '--color', 'never',
                                        self.write(name, message))
                self.assertEqual(code, expected)

    def test_unreadable_file_is_reported(self):
        with self.assertLogs(msi.log, level='ERROR'):
            code, out = self.run_main(str(self.dir / 'missing.eml'))
        self.assertEqual(code, 1)
        self.assertEqual(out, '')

    def test_all_checks_disabled_produces_no_report(self):
        with self.assertLogs(msi.log, level='WARNING'):
            code, out = self.run_main('--no-check-spf', '--no-check-dkim', '--no-check-dmarc',
                                      self.write('pass.eml', PASS_EML))
        self.assertEqual(code, 1)
        self.assertEqual(out, '')

    def test_untrusted_authserv_changes_the_verdict_end_to_end(self):
        forged = (b'Authentication-Results: upstream.attacker.test; dkim=pass '
                  b'header.d=paypal.com; dmarc=pass header.from=paypal.com\n'
                  b'From: PayPal <service@paypal.com>\n\nbody\n')
        path = self.write('forged.eml', forged)

        _, out = self.run_main('--json', path)
        self.assertEqual(json.loads(out)['status'], 'pass')

        _, out = self.run_main('--json', '--trusted-authserv', 'mx.example.org', path)
        self.assertEqual(json.loads(out)['status'], 'warn')


class TestEvaluateMessageSecurityInfo(unittest.TestCase):
    """The public one-call API."""

    def test_evaluates_a_file_path(self):
        with tempfile.NamedTemporaryFile(suffix='.eml', delete=False) as handle:
            handle.write(PASS_EML)
        self.addCleanup(os.unlink, handle.name)

        result = msi.evaluate_message_security_info(handle.name)
        self.assertEqual(result['status'], 'pass')

    def test_honours_the_config(self):
        with tempfile.NamedTemporaryFile(suffix='.eml', delete=False) as handle:
            handle.write(PASS_EML)
        self.addCleanup(os.unlink, handle.name)

        result = msi.evaluate_message_security_info(
            handle.name, msi.SecurityInfoConfig(check_spf=False, check_dmarc=False, check_tls=False))
        self.assertEqual([r['label'] for r in result['rows']], ['From', 'DKIM'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
