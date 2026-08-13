#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Configuration: validating settings, and reading them from the command line
and the config file.

See README.md in this directory for how to run these.
"""

import contextlib
import io
import pathlib
import tempfile
import unittest

from support import msi


class TestConfig(unittest.TestCase):
    """SecurityInfoConfig validation."""

    def test_method_enabled_defaults_to_true(self):
        config = msi.SecurityInfoConfig()
        for method in ('spf', 'dkim', 'dmarc', 'tls'):
            self.assertTrue(config.method_enabled(method))
        self.assertFalse(msi.SecurityInfoConfig(check_tls=False).method_enabled('tls'))

    def test_invalid_header_names_are_rejected(self):
        config = msi.SecurityInfoConfig(extra_headers=['X-Ok', 'bad header!', 'also:bad', '', '   '])
        with self.assertLogs(msi.log, level='WARNING'):
            self.assertEqual(config.valid_extra_headers(), ['X-Ok'])

    def test_duplicates_are_removed_case_insensitively(self):
        config = msi.SecurityInfoConfig(extra_headers=['X-Spam', ' x-spam ', 'Message-ID'])
        self.assertEqual(config.valid_extra_headers(), ['X-Spam', 'Message-ID'])


class TestArguments(unittest.TestCase):
    """Where settings come from: the command line and the config file."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = pathlib.Path(directory.name)

    def test_repeatable_options_accumulate(self):
        args = msi._parse_args(['--trusted-authserv', 'a', '--trusted-authserv', 'b',
                                '--extra-headers', 'X-One', '--extra-headers', 'X-Two', 'x.eml'])
        self.assertEqual(args.trusted_authserv, ['a', 'b'])
        self.assertEqual(args.extra_headers, ['X-One', 'X-Two'])

    def test_check_flags_default_on_and_can_be_negated(self):
        args = msi._parse_args(['x.eml'])
        self.assertTrue(args.check_spf and args.check_dkim and args.check_dmarc and args.check_tls)
        args = msi._parse_args(['--no-check-tls', '--no-check-spf', 'x.eml'])
        self.assertFalse(args.check_tls)
        self.assertFalse(args.check_spf)
        self.assertTrue(args.check_dkim)

    def test_config_file_settings_are_applied(self):
        config = self.dir / 'cfg.toml'
        config.write_text('[message-security-info]\n'
                          'trusted-authserv = ["mx.example.org"]\n'
                          'check-tls = false\n'
                          'extra-headers = ["X-Spam-Status", "Message-ID"]\n')
        args = msi._parse_args(['-c', str(config), 'x.eml'])
        self.assertEqual(args.trusted_authserv, ['mx.example.org'])
        self.assertFalse(args.check_tls)
        self.assertEqual(args.extra_headers, ['X-Spam-Status', 'Message-ID'])

    def test_the_command_line_overrides_the_config_file(self):
        config = self.dir / 'cfg.toml'
        config.write_text('[message-security-info]\ncheck-tls = false\n')
        args = msi._parse_args(['-c', str(config), '--check-tls', 'x.eml'])
        self.assertTrue(args.check_tls)

    def test_a_missing_message_argument_is_a_usage_error(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            msi._parse_args([])


if __name__ == '__main__':
    unittest.main(verbosity=2)
