#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Parsing the Authentication-Results (RFC 8601) and Received-SPF (RFC 7208) headers,
including which authserv-ids may be trusted.

See README.md in this directory for how to run these.
"""

import unittest

from support import PASS_EML, headers, info


class TestParseAuthresults(unittest.TestCase):
    """Parsing the Authentication-Results header (RFC 8601)."""

    def test_parses_all_three_methods_from_a_folded_header(self):
        auth = info().parse_authresults(headers(PASS_EML))
        self.assertEqual(auth['dkim'], [{'result': 'pass', 'domain': 'example.com'}])
        self.assertEqual(auth['spf'], [{'result': 'pass', 'domain': 'example.com'}])
        self.assertEqual(auth['dmarc'], [{'result': 'pass', 'domain': 'example.com'}])

    def test_no_header_yields_empty_lists(self):
        auth = info().parse_authresults(headers('From: a@b.test\n\nbody\n'))
        self.assertEqual(auth, {'dkim': [], 'spf': [], 'dmarc': []})

    def test_merges_several_authentication_results_headers(self):
        auth = info().parse_authresults(headers(
            'Authentication-Results: mx1.example.org; spf=pass smtp.mailfrom=a.test\n'
            'Authentication-Results: mx2.example.org; dkim=pass header.d=a.test\n'
            '\nbody\n'))
        self.assertEqual(len(auth['spf']), 1)
        self.assertEqual(len(auth['dkim']), 1)

    def test_keeps_every_entry_of_one_method_in_order(self):
        auth = info().parse_authresults(headers(
            'Authentication-Results: mx; dkim=pass header.d=a.test; dkim=fail header.d=b.test\n'
            '\nbody\n'))
        self.assertEqual([e['result'] for e in auth['dkim']], ['pass', 'fail'])

    def test_ignores_unknown_methods_and_junk_segments(self):
        auth = info().parse_authresults(headers(
            'Authentication-Results: mx; iprev=pass; x=y; ; dkim=pass header.d=a.test\n'
            '\nbody\n'))
        self.assertEqual(len(auth['dkim']), 1)
        self.assertEqual(auth['spf'], [])

    def test_result_and_method_case_is_normalized(self):
        auth = info().parse_authresults(headers(
            'Authentication-Results: mx; DKIM=Pass header.d=Example.COM\n\nbody\n'))
        self.assertEqual(auth['dkim'], [{'result': 'pass', 'domain': 'example.com'}])

    def test_the_authserv_id_is_not_read_as_a_result(self):
        # A segment before the first ';' never contributes a method result.
        auth = info().parse_authresults(headers(
            'Authentication-Results: dkim=pass.example.org; spf=pass smtp.mailfrom=a.test\n'
            '\nbody\n'))
        self.assertEqual(auth['dkim'], [])
        self.assertEqual(len(auth['spf']), 1)


class TestTrustedAuthserv(unittest.TestCase):
    """Only the configured authserv-ids may be believed."""

    HEADER = ('Authentication-Results: upstream.attacker.test; dkim=pass header.d=paypal.com\n'
              'Authentication-Results: mx.example.org; dkim=fail header.d=paypal.com\n'
              '\nbody\n')

    def test_untrusted_results_are_dropped(self):
        auth = info(trusted_authserv=['mx.example.org']).parse_authresults(headers(self.HEADER))
        self.assertEqual([e['result'] for e in auth['dkim']], ['fail'])

    def test_empty_trust_list_accepts_everything(self):
        auth = info().parse_authresults(headers(self.HEADER))
        self.assertEqual([e['result'] for e in auth['dkim']], ['pass', 'fail'])

    def test_comparison_is_case_insensitive(self):
        auth = info(trusted_authserv=['MX.Example.ORG']).parse_authresults(headers(self.HEADER))
        self.assertEqual([e['result'] for e in auth['dkim']], ['fail'])

    def test_a_trailing_comment_on_the_authserv_id_is_ignored(self):
        auth = info(trusted_authserv=['mx.example.org']).parse_authresults(headers(
            'Authentication-Results: mx.example.org (amavisd-new); dkim=pass header.d=a.test\n'
            '\nbody\n'))
        self.assertEqual(len(auth['dkim']), 1)

    def test_a_forged_header_still_shows_up_raw(self):
        # Filtering applies to the verdict, not to what the user may inspect.
        raw = info(trusted_authserv=['mx.example.org']).raw_headers(headers(self.HEADER))
        self.assertEqual(len(raw), 2)


class TestExtractDomain(unittest.TestCase):
    """Finding each method's domain inside one Authentication-Results entry."""

    def test_dkim_prefers_header_d(self):
        self.assertEqual(
            info().extract_domain('dkim', 'dkim=pass header.i=@sub.other.test header.d=a.test'),
            'a.test')

    def test_dkim_falls_back_to_header_i(self):
        self.assertEqual(info().extract_domain('dkim', 'dkim=pass header.i=@sub.a.test'),
                         'sub.a.test')

    def test_spf_accepts_mailfrom_helo_and_envelope_from(self):
        self.assertEqual(info().extract_domain('spf', 'spf=pass smtp.mailfrom=user@a.test'),
                         'a.test')
        self.assertEqual(info().extract_domain('spf', 'spf=pass smtp.helo=mail.a.test'),
                         'mail.a.test')
        self.assertEqual(info().extract_domain('spf', 'spf=pass envelope-from=<user@a.test>'),
                         'a.test')

    def test_dmarc_reads_header_from(self):
        self.assertEqual(info().extract_domain('dmarc', 'dmarc=pass header.from=A.Test'),
                         'a.test')

    def test_missing_domain_is_none(self):
        self.assertIsNone(info().extract_domain('dkim', 'dkim=none'))
        self.assertIsNone(info().extract_domain('spf', 'spf=none'))


class TestSpfFromReceived(unittest.TestCase):
    """The Received-SPF fallback (RFC 7208)."""

    def test_parses_result_and_envelope_domain(self):
        self.assertEqual(info().spf_from_received(headers(PASS_EML)),
                         {'result': 'pass', 'domain': 'example.com'})

    def test_angle_brackets_are_stripped(self):
        self.assertEqual(
            info().spf_from_received(headers(
                'Received-SPF: Neutral (mailfrom) envelope-from=<postmaster@a.test>;\n\nbody\n')),
            {'result': 'neutral', 'domain': 'a.test'})

    def test_result_without_a_domain(self):
        self.assertEqual(info().spf_from_received(headers('Received-SPF: None\n\nbody\n')),
                         {'result': 'none', 'domain': None})

    def test_first_header_wins(self):
        self.assertEqual(
            info().spf_from_received(headers('Received-SPF: Fail\nReceived-SPF: Pass\n\nbody\n')),
            {'result': 'fail', 'domain': None})

    def test_absent_header_is_none(self):
        self.assertIsNone(info().spf_from_received(headers('From: a@b.test\n\nbody\n')))

    def test_unparsable_header_is_none(self):
        self.assertIsNone(info().spf_from_received(headers('Received-SPF: (no result)\n\nbody\n')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
