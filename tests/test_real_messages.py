#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Smoke test over the sample messages in emails/.

See README.md in this directory for how to run these.
"""

import json
import unittest

from support import EMAIL_DIR, msi


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
                  'marker', 'description'}

    @classmethod
    def setUpClass(cls):
        cls.paths = sorted(EMAIL_DIR.glob('*.eml'))

    def test_every_sample_evaluates(self):
        for path in self.paths:
            with self.subTest(message=path.name):
                result = msi.evaluate_message_security_info(
                    str(path), msi.SecurityInfoConfig(extra_headers=['Message-ID', 'Return-Path']))

                self.assertIn(result['status'], ('pass', 'warn', 'fail', 'unknown'))
                self.assertIn(result['dkim_from'], ('pass', 'fail', 'none'))
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

                self.assertEqual(filtered['dkim_from'], 'none')
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
