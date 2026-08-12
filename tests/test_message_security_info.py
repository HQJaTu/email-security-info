#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Unit tests for message-security-info.py. See README.md in this directory.

Run them from anywhere with either

    python -m unittest discover -s tests -v
    python -m pytest tests

The module under test lives one directory up and keeps its hyphenated,
executable-style name, which is not a valid Python identifier — so it is loaded
by path here instead of imported. Everything else is stdlib unittest.
"""

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).resolve().parent.parent / 'message-security-info.py'


def _load_module():
    """Import ``message-security-info.py`` under the name ``message_security_info``."""
    spec = importlib.util.spec_from_file_location('message_security_info', MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    return module


msi = _load_module()


def headers(text: str) -> 'msi.MessageHeaders':
    """A MessageHeaders built from a header block (str or bytes)."""
    if isinstance(text, str):
        text = text.encode('utf-8', 'surrogateescape')

    return msi.load_headers_from_bytes(text)


def info(**config) -> 'msi.MessageSecurityInfo':
    """A MessageSecurityInfo with the given config overrides."""
    return msi.MessageSecurityInfo(msi.Config(**config))


# -- sample messages -------------------------------------------------------

PASS_EML = b"""Received: from mail.example.com (mail.example.com [198.51.100.7])
\tby mx.example.org (Postfix) with ESMTPS id 4B2Cd1
\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384)
\tfor <bob@example.org>; Tue, 11 Aug 2026 10:00:01 +0200 (CEST)
Authentication-Results: mx.example.org;
\tdkim=pass header.d=example.com header.i=@example.com;
\tspf=pass smtp.mailfrom=example.com;
\tdmarc=pass header.from=example.com
Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=198.51.100.7;
\thelo=mail.example.com; envelope-from=alice@example.com;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1;
\th=from:to:subject; bh=abc=; b=xyz=
From: Alice Example <alice@example.com>
To: bob@example.org
Subject: Hello
X-Spam-Status: No, score=-1.2
Message-ID: <1@example.com>

body
"""

FAIL_EML = b"""Received: from evil.test by mx.example.org with SMTP id 1; Tue, 11 Aug 2026 10:00:01 +0200
Authentication-Results: mx.example.org; dkim=fail header.d=paypal.com;
\tspf=fail smtp.mailfrom=evil.test; dmarc=fail header.from=paypal.com
From: "PayPal\xe2\x80\xae" <billing@evil.test>
Subject: Invoice

body
"""

UNALIGNED_EML = b"""Received: from relay.mailer.net by mx.example.org with ESMTPSA id 9zz; Tue, 11 Aug 2026 10:00:01 +0200
Authentication-Results: mx.example.org; dkim=pass header.d=mailer.net;
\tspf=softfail smtp.mailfrom=bank.example
From: =?utf-8?B?QmFuayBTdXBwb3J0?= <support@bank.example>
Subject: Your account

body
"""

UNVERIFIED_EML = b"""Received: from mail.example.com by mx.example.org with ESMTPA id 2; Tue, 11 Aug 2026 10:00:01 +0200
DKIM-Signature: v=1; a=rsa-sha256; d=news.example.com; s=k1; b=zzz=
From: news@news.example.com

body
"""


# -- header handling -------------------------------------------------------

class TestMessageHeaders(unittest.TestCase):
    """Reading, unfolding and repairing raw header values."""

    def test_unfolds_continuation_lines(self):
        h = headers('Authentication-Results: mx.example.org;\n\tdkim=pass\n\nbody\n')
        self.assertEqual(h.get('Authentication-Results'),
                         ['mx.example.org; dkim=pass'])

    def test_returns_every_occurrence_in_order(self):
        h = headers('Received: first\nReceived: second\n\nbody\n')
        self.assertEqual(h.get('Received'), ['first', 'second'])

    def test_lookup_is_case_insensitive(self):
        h = headers('dkim-signature: v=1; d=example.com\n\nbody\n')
        self.assertEqual(h.get('DKIM-Signature'), ['v=1; d=example.com'])

    def test_missing_and_empty_headers_are_dropped(self):
        h = headers('X-Empty:\nX-Blank:   \n\nbody\n')
        self.assertEqual(h.get('X-Empty'), [])
        self.assertEqual(h.get('X-Absent'), [])
        self.assertEqual(h.get('X-Blank'), [])

    def test_first_returns_none_when_absent(self):
        h = headers('From: a@b.test\n\nbody\n')
        self.assertEqual(h.first('From'), 'a@b.test')
        self.assertIsNone(h.first('DKIM-Signature'))

    def test_raw_utf8_bytes_are_recovered(self):
        # Non-ASCII bytes in a header would otherwise stringify to U+FFFD.
        h = headers(b'Subject: caf\xc3\xa9\n\nbody\n')
        self.assertEqual(h.get('Subject'), ['café'])

    def test_undecodable_bytes_stay_printable(self):
        h = headers(b'Subject: caf\xe9\n\nbody\n')
        value = h.first('Subject')
        self.assertEqual(value, 'caf�')
        value.encode('utf-8')  # must not raise

    def test_body_is_not_parsed_as_headers(self):
        h = headers('From: a@b.test\n\nFrom: body@spoof.test\n')
        self.assertEqual(h.get('From'), ['a@b.test'])


class TestHelpers(unittest.TestCase):
    """The small string helpers."""

    def test_unfold_collapses_folding_whitespace_only(self):
        self.assertEqual(msi._unfold('a\r\n\tb\n  c'), 'a b c')
        self.assertEqual(msi._unfold('  a  b  '), 'a  b')

    def test_strip_formatting_removes_control_and_format_chars(self):
        # U+202E right-to-left override, U+200B zero width space, U+0007 bell.
        self.assertEqual(msi._strip_formatting('Pay‮Pal​\x07'), 'PayPal')
        self.assertEqual(msi._strip_formatting('Ünicode ok'), 'Ünicode ok')

    def test_gettext_substitutes_variables(self):
        self.assertEqual(msi.gettext('notaligned', {'from': 'example.com'}),
                         'does not match From (example.com)')

    def test_gettext_falls_back_to_the_key(self):
        self.assertEqual(msi.gettext('nosuchlabel'), 'nosuchlabel')


# -- Authentication-Results parsing ----------------------------------------

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


# -- transport encryption --------------------------------------------------

class TestTlsInfo(unittest.TestCase):
    """Reading TLS state off the topmost Received header."""

    def received(self, clause: str) -> 'msi.MessageHeaders':
        return headers('Received: from a.test by mx.example.org {}; '
                       'Tue, 11 Aug 2026 10:00:01 +0200\n\nbody\n'.format(clause))

    def test_esmtps_is_encrypted_with_version_detail(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(headers(PASS_EML)),
                         {'encrypted': True, 'detail': 'TLSv1.3'})

    def test_esmtpsa_is_encrypted(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(self.received('with ESMTPSA id 1')),
                         {'encrypted': True, 'detail': None})

    def test_lmtps_is_encrypted(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(self.received('with LMTPS id 1')),
                         {'encrypted': True, 'detail': None})

    def test_utf8smtps_is_encrypted(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(self.received('with UTF8SMTPS id 1')),
                         {'encrypted': True, 'detail': None})

    def test_plain_esmtp_is_not_encrypted(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(self.received('with ESMTP id 1')),
                         {'encrypted': False, 'detail': None})

    def test_esmtpa_is_authentication_without_tls(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(self.received('with ESMTPA id 1')),
                         {'encrypted': False, 'detail': None})

    def test_a_version_clause_alone_implies_tls(self):
        self.assertEqual(msi.MessageSecurityInfo.tls_info(
            self.received('(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384)')),
            {'encrypted': True, 'detail': 'TLS1.3'})

    def test_only_the_topmost_hop_is_read(self):
        h = headers('Received: from a by mx with ESMTP id 2; Tue, 11 Aug 2026 10:00:02 +0200\n'
                    'Received: from b by a with ESMTPS id 1; Tue, 11 Aug 2026 10:00:01 +0200\n'
                    '\nbody\n')
        self.assertEqual(msi.MessageSecurityInfo.tls_info(h), {'encrypted': False, 'detail': None})

    def test_no_received_header_is_undeterminable(self):
        self.assertIsNone(msi.MessageSecurityInfo.tls_info(headers('From: a@b.test\n\nbody\n')))

    def test_unrecognised_received_is_undeterminable(self):
        self.assertIsNone(msi.MessageSecurityInfo.tls_info(self.received('via local delivery')))


# -- alignment and signature domain ----------------------------------------

class TestAligned(unittest.TestCase):
    """Relaxed From-alignment."""

    def test_equal_domains_are_aligned(self):
        self.assertTrue(msi.MessageSecurityInfo.aligned('example.com', 'EXAMPLE.com'))

    def test_subdomain_either_way_is_aligned(self):
        self.assertTrue(msi.MessageSecurityInfo.aligned('example.com', 'mail.example.com'))
        self.assertTrue(msi.MessageSecurityInfo.aligned('mail.example.com', 'example.com'))

    def test_unrelated_domains_are_not_aligned(self):
        self.assertFalse(msi.MessageSecurityInfo.aligned('mailer.net', 'bank.example'))

    def test_a_shared_suffix_is_not_enough(self):
        self.assertFalse(msi.MessageSecurityInfo.aligned('notexample.com', 'example.com'))

    def test_missing_side_is_not_aligned(self):
        self.assertFalse(msi.MessageSecurityInfo.aligned(None, 'example.com'))
        self.assertFalse(msi.MessageSecurityInfo.aligned('example.com', None))
        self.assertFalse(msi.MessageSecurityInfo.aligned('', ''))


class TestSignatureDomain(unittest.TestCase):
    """The d= tag of a raw DKIM-Signature."""

    def test_reads_the_signing_domain(self):
        self.assertEqual(
            msi.MessageSecurityInfo.signature_domain('v=1; a=rsa-sha256; d=Example.COM; s=k1'),
            'example.com')

    def test_tolerates_whitespace_around_the_tag(self):
        self.assertEqual(msi.MessageSecurityInfo.signature_domain('v=1;  d = example.com ; s=k1'),
                         'example.com')

    def test_accepts_the_tag_first(self):
        self.assertEqual(msi.MessageSecurityInfo.signature_domain('d=example.com; v=1'),
                         'example.com')

    def test_is_not_confused_by_other_tags_ending_in_d(self):
        self.assertEqual(msi.MessageSecurityInfo.signature_domain('v=1; bh=abcd=; d=a.test'),
                         'a.test')

    def test_missing_tag_is_none(self):
        self.assertIsNone(msi.MessageSecurityInfo.signature_domain('v=1; a=rsa-sha256; s=k1'))


# -- the From header -------------------------------------------------------

class TestFromHeader(unittest.TestCase):
    """Decoding, sanitizing and displaying the visible sender."""

    def test_display_name_and_address(self):
        self.assertEqual(info().from_parts(headers(PASS_EML)),
                         {'name': 'Alice Example', 'addr': 'alice@example.com'})
        self.assertEqual(info().from_address(headers(PASS_EML)),
                         'Alice Example <alice@example.com>')
        self.assertEqual(info().from_domain(headers(PASS_EML)), 'example.com')

    def test_encoded_words_are_decoded(self):
        self.assertEqual(info().from_parts(headers(UNALIGNED_EML))['name'], 'Bank Support')

    def test_bidi_override_is_stripped_from_the_name(self):
        parts = info().from_parts(headers(FAIL_EML))
        self.assertEqual(parts, {'name': 'PayPal', 'addr': 'billing@evil.test'})

    def test_address_only_from_has_no_name(self):
        h = headers('From: news@News.Example.com\n\nbody\n')
        self.assertEqual(info().from_parts(h), {'name': '', 'addr': 'news@news.example.com'})
        self.assertEqual(info().from_address(h), 'news@news.example.com')

    def test_a_name_repeating_the_address_is_dropped(self):
        h = headers('From: alice@example.com <alice@example.com>\n\nbody\n')
        self.assertEqual(info().from_parts(h)['name'], '')
        self.assertEqual(info().from_address(h), 'alice@example.com')

    def test_only_the_first_address_is_used(self):
        h = headers('From: Alice <alice@example.com>, Bob <bob@other.test>\n\nbody\n')
        self.assertEqual(info().from_domain(h), 'example.com')

    def test_no_from_header(self):
        h = headers('Subject: x\n\nbody\n')
        self.assertIsNone(info().from_parts(h))
        self.assertIsNone(info().from_address(h))
        self.assertIsNone(info().from_domain(h))

    def test_unparsable_from_is_salvaged_by_regex(self):
        h = headers('From: alice(at)example.com <mangled>\n\nbody\n')
        self.assertIsNone(info().from_domain(h))

    def test_address_without_a_domain_has_no_from_domain(self):
        h = headers('From: undisclosed-recipients:;\n\nbody\n')
        self.assertIsNone(info().from_domain(h))

    def test_raw_utf8_display_name(self):
        h = headers(b'From: J\xc3\xbcrgen M\xc3\xbcller <jm@example.com>\n\nbody\n')
        self.assertEqual(info().from_parts(h)['name'], 'Jürgen Müller')


# -- per-method and combined verdicts --------------------------------------

class TestMethodStatus(unittest.TestCase):
    """Mapping one SPF/DKIM result to a status."""

    def test_spf_pass_is_pass_regardless_of_alignment(self):
        entry = {'result': 'pass', 'domain': 'other.test'}
        self.assertEqual(info().method_status('spf', entry, 'example.com'), 'pass')

    def test_aligned_dkim_pass_is_pass(self):
        entry = {'result': 'pass', 'domain': 'mail.example.com'}
        self.assertEqual(info().method_status('dkim', entry, 'example.com'), 'pass')

    def test_unaligned_dkim_pass_is_a_warning(self):
        entry = {'result': 'pass', 'domain': 'mailer.net'}
        self.assertEqual(info().method_status('dkim', entry, 'bank.example'), 'warn')

    def test_fail_is_fail(self):
        self.assertEqual(info().method_status('spf', {'result': 'fail', 'domain': None}, None),
                         'fail')

    def test_soft_results_are_warnings(self):
        for result in ('softfail', 'neutral', 'policy', 'permerror'):
            with self.subTest(result=result):
                self.assertEqual(
                    info().method_status('spf', {'result': result, 'domain': None}, None), 'warn')

    def test_temperror_is_unknown(self):
        self.assertEqual(info().method_status('spf', {'result': 'temperror', 'domain': None}, None),
                         'unknown')

    def test_none_does_not_contribute(self):
        self.assertEqual(info().method_status('spf', {'result': 'none', 'domain': None}, None),
                         'none')


class TestCombineStatuses(unittest.TestCase):
    """Reducing per-method statuses to one."""

    def test_nothing_to_check_is_a_warning(self):
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses([]), 'warn')
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses(['none', 'none']), 'warn')

    def test_worst_wins(self):
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses(['pass', 'warn', 'fail']), 'fail')
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses(['pass', 'warn']), 'warn')
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses(['pass', 'pass']), 'pass')

    def test_pass_outranks_unknown(self):
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses(['unknown', 'pass']), 'pass')

    def test_only_unknown_stays_unknown(self):
        self.assertEqual(msi.MessageSecurityInfo.combine_statuses(['unknown', 'none']), 'unknown')


class TestEvaluate(unittest.TestCase):
    """The overall verdict."""

    def evaluate(self, message, **config):
        engine = info(**config)
        h = headers(message)

        return engine.evaluate(h, engine.parse_authresults(h))

    def test_dmarc_pass_is_authoritative(self):
        # SPF/DKIM are absent, yet DMARC pass alone is a green verdict.
        verdict = self.evaluate('Authentication-Results: mx; dmarc=pass header.from=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'pass')
        self.assertEqual(verdict['summary'], msi.gettext('summarypass'))

    def test_dmarc_fail_is_authoritative(self):
        verdict = self.evaluate('Authentication-Results: mx; dkim=pass header.d=a.test; '
                                'dmarc=fail header.from=a.test\nFrom: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'fail')

    def test_inconclusive_dmarc_falls_through_to_spf_and_dkim(self):
        verdict = self.evaluate('Authentication-Results: mx; dmarc=none; dkim=fail header.d=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'fail')

    def test_a_disabled_dmarc_does_not_decide(self):
        verdict = self.evaluate('Authentication-Results: mx; dmarc=fail header.from=a.test; '
                                'dkim=pass header.d=a.test\nFrom: a@a.test\n\nbody\n',
                                check_dmarc=False)
        self.assertEqual(verdict['status'], 'pass')

    def test_full_pass(self):
        self.assertEqual(self.evaluate(PASS_EML)['status'], 'pass')

    def test_full_fail(self):
        self.assertEqual(self.evaluate(FAIL_EML)['status'], 'fail')

    def test_unaligned_dkim_pass_with_softfail_spf_warns(self):
        self.assertEqual(self.evaluate(UNALIGNED_EML)['status'], 'warn')

    def test_unverified_signature_is_unknown(self):
        verdict = self.evaluate(UNVERIFIED_EML)
        self.assertEqual(verdict['status'], 'unknown')
        self.assertEqual(verdict['summary'], msi.gettext('summaryunknown'))

    def test_no_authentication_data_at_all_warns(self):
        self.assertEqual(self.evaluate('From: a@a.test\n\nbody\n')['status'], 'warn')

    def test_received_spf_is_used_when_authentication_results_is_absent(self):
        verdict = self.evaluate('Received-SPF: Fail (mailfrom) envelope-from=a@a.test;\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'fail')

    def test_authentication_results_wins_over_received_spf(self):
        verdict = self.evaluate('Authentication-Results: mx; spf=pass smtp.mailfrom=a.test\n'
                                'Received-SPF: Fail\nFrom: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'pass')

    def test_disabling_spf_hides_its_failure(self):
        message = ('Authentication-Results: mx; spf=fail smtp.mailfrom=a.test; '
                   'dkim=pass header.d=a.test\nFrom: a@a.test\n\nbody\n')
        self.assertEqual(self.evaluate(message)['status'], 'fail')
        self.assertEqual(self.evaluate(message, check_spf=False)['status'], 'pass')

    def test_disabling_dkim_hides_its_failure(self):
        message = ('Authentication-Results: mx; spf=pass smtp.mailfrom=a.test; '
                   'dkim=fail header.d=a.test\nFrom: a@a.test\n\nbody\n')
        self.assertEqual(self.evaluate(message)['status'], 'fail')
        self.assertEqual(self.evaluate(message, check_dkim=False)['status'], 'pass')


class TestDkimFromMarker(unittest.TestCase):
    """The DKIM/From marker, independent of the overall verdict."""

    def marker(self, message, **config):
        engine = info(**config)
        h = headers(message)

        return engine.dkim_from_marker(h, engine.parse_authresults(h))

    def test_aligned_pass_is_pass(self):
        self.assertEqual(self.marker(PASS_EML), 'pass')

    def test_unaligned_pass_is_fail(self):
        self.assertEqual(self.marker(UNALIGNED_EML), 'fail')

    def test_dkim_fail_is_fail(self):
        self.assertEqual(self.marker(FAIL_EML), 'fail')

    def test_no_verified_result_is_none(self):
        # An unverified DKIM-Signature is not a verdict to show on the From line.
        self.assertEqual(self.marker(UNVERIFIED_EML), 'none')

    def test_signature_domain_fills_in_a_missing_result_domain(self):
        message = ('Authentication-Results: mx; dkim=pass\n'
                   'DKIM-Signature: v=1; d=example.com; s=k1\n'
                   'From: a@example.com\n\nbody\n')
        self.assertEqual(self.marker(message), 'pass')

    def test_a_pass_without_any_domain_is_fail(self):
        self.assertEqual(self.marker('Authentication-Results: mx; dkim=pass\n'
                                     'From: a@example.com\n\nbody\n'), 'fail')

    def test_only_the_first_signature_is_judged(self):
        # Known limitation, faithful to the PHP plugin: a message signed by both
        # an ESP and the sender's own domain is judged on the first entry only,
        # so an aligned pass further down the header does not count. Most of the
        # samples in tests/emails/ hit this (see TestRealMessages).
        self.assertEqual(self.marker('Authentication-Results: mx; dkim=pass header.d=esp.test; '
                                     'dkim=pass header.d=example.com\n'
                                     'From: a@example.com\n\nbody\n'), 'fail')

    def test_a_pass_without_a_from_header_is_fail(self):
        self.assertEqual(self.marker('Authentication-Results: mx; dkim=pass header.d=a.test\n'
                                     '\nbody\n'), 'fail')


# -- formatting ------------------------------------------------------------

class TestFormatting(unittest.TestCase):
    """The result lines shown for each method."""

    def test_format_method_with_and_without_a_domain(self):
        self.assertEqual(info().format_method({'result': 'pass', 'domain': 'a.test'}),
                         'PASS — a.test')
        self.assertEqual(info().format_method({'result': 'neutral', 'domain': None}), 'NEUTRAL')

    def test_format_method_without_a_result(self):
        self.assertEqual(info().format_method(None), msi.gettext('notpresent'))

    def test_format_dkim_aligned_pass_has_no_note(self):
        self.assertEqual(
            info().format_dkim({'result': 'pass', 'domain': 'example.com'}, None, 'example.com'),
            'PASS — example.com')

    def test_format_dkim_unaligned_pass_notes_the_mismatch_on_its_own_line(self):
        self.assertEqual(
            info().format_dkim({'result': 'pass', 'domain': 'mailer.net'}, None, 'bank.example'),
            'PASS — mailer.net\ndoes not match From (bank.example)')

    def test_format_dkim_non_pass_notes_alignment_in_parentheses(self):
        self.assertEqual(
            info().format_dkim({'result': 'fail', 'domain': 'a.test'}, None, 'a.test'),
            'FAIL — a.test (aligned with From)')
        self.assertEqual(
            info().format_dkim({'result': 'fail', 'domain': 'a.test'}, None, 'b.test'),
            'FAIL — a.test (does not match From (b.test))')

    def test_format_dkim_falls_back_to_the_signature_domain(self):
        self.assertEqual(info().format_dkim({'result': 'pass', 'domain': None},
                                            'example.com', 'example.com'),
                         'PASS — example.com')

    def test_format_dkim_reports_an_unverified_signature(self):
        self.assertEqual(info().format_dkim(None, 'news.example.com', 'news.example.com'),
                         msi.gettext('unverified') + ' — news.example.com')
        self.assertEqual(info().format_dkim(None, None, 'a.test'), msi.gettext('notpresent'))

    def test_no_alignment_note_without_both_domains(self):
        self.assertEqual(info().dkim_alignment_note('fail', 'a.test', None), '')
        self.assertEqual(info().dkim_alignment_note('fail', None, 'a.test'), '')

    def test_format_tls(self):
        self.assertEqual(msi.MessageSecurityInfo.format_tls(None), msi.gettext('tlsunknown'))
        self.assertEqual(msi.MessageSecurityInfo.format_tls({'encrypted': False, 'detail': None}),
                         msi.gettext('tlsplain'))
        self.assertEqual(msi.MessageSecurityInfo.format_tls({'encrypted': True, 'detail': None}),
                         msi.gettext('tlsencrypted'))
        self.assertEqual(msi.MessageSecurityInfo.format_tls({'encrypted': True,
                                                             'detail': 'TLSv1.3'}),
                         msi.gettext('tlsencrypted') + ' — TLSv1.3')


# -- assembled result ------------------------------------------------------

class TestSummaryRows(unittest.TestCase):
    """Which rows the details contain, and what they say."""

    def rows(self, message, **config):
        engine = info(**config)
        h = headers(message)

        return {r['label']: r for r in engine.summary_rows(h, engine.parse_authresults(h))}

    def test_all_rows_by_default(self):
        rows = self.rows(PASS_EML)
        self.assertEqual(list(rows), ['From', 'SPF', 'DKIM', 'DMARC', 'Transport (TLS)'])
        self.assertEqual(rows['From']['value'], 'Alice Example <alice@example.com>')
        self.assertEqual(rows['SPF']['value'], 'PASS — example.com')
        self.assertEqual(rows['DKIM']['value'], 'PASS — example.com')
        self.assertEqual(rows['DMARC']['value'], 'PASS — example.com')
        self.assertEqual(rows['Transport (TLS)']['value'], 'Encrypted — TLSv1.3')

    def test_disabled_methods_are_dropped(self):
        rows = self.rows(PASS_EML, check_spf=False, check_dmarc=False, check_tls=False)
        self.assertEqual(list(rows), ['From', 'DKIM'])

    def test_the_dkim_row_carries_the_from_marker(self):
        self.assertEqual(self.rows(PASS_EML)['DKIM']['marker'], 'pass')
        self.assertEqual(self.rows(FAIL_EML)['DKIM']['marker'], 'fail')

    def test_the_from_row_falls_back_to_not_present(self):
        self.assertEqual(self.rows('Subject: x\n\nbody\n')['From']['value'],
                         msi.gettext('notpresent'))

    def test_spf_row_uses_the_received_spf_fallback(self):
        rows = self.rows('Received-SPF: Pass (mailfrom) envelope-from=a@a.test;\n'
                         'From: a@a.test\n\nbody\n')
        self.assertEqual(rows['SPF']['value'], 'PASS — a.test')


class TestRawHeaders(unittest.TestCase):
    """The raw header lines shown below the summary."""

    def test_authentication_headers_come_first_then_the_extras(self):
        raw = info(extra_headers=['X-Spam-Status', 'Message-ID']).raw_headers(headers(PASS_EML))
        self.assertEqual([h['name'] for h in raw],
                         ['Authentication-Results', 'Received-SPF', 'X-Spam-Status', 'Message-ID'])
        self.assertEqual(raw[2]['value'], 'No, score=-1.2')

    def test_absent_headers_are_omitted(self):
        raw = info(extra_headers=['X-Nonexistent']).raw_headers(headers(UNVERIFIED_EML))
        self.assertEqual(raw, [])

    def test_every_occurrence_of_an_extra_header_is_listed(self):
        raw = info(extra_headers=['X-Twice']).raw_headers(
            headers('X-Twice: a\nX-Twice: b\n\nbody\n'))
        self.assertEqual([h['value'] for h in raw], ['a', 'b'])

    def test_values_are_unfolded(self):
        raw = info().raw_headers(headers(PASS_EML))
        self.assertNotIn('\n', raw[0]['value'])
        self.assertIn('dkim=pass header.d=example.com', raw[0]['value'])


class TestConfig(unittest.TestCase):
    """Config validation."""

    def test_method_enabled_defaults_to_true(self):
        config = msi.Config()
        for method in ('spf', 'dkim', 'dmarc', 'tls'):
            self.assertTrue(config.method_enabled(method))
        self.assertFalse(msi.Config(check_tls=False).method_enabled('tls'))

    def test_invalid_header_names_are_rejected(self):
        config = msi.Config(extra_headers=['X-Ok', 'bad header!', 'also:bad', '', '   '])
        with self.assertLogs(msi.log, level='WARNING'):
            self.assertEqual(config.valid_extra_headers(), ['X-Ok'])

    def test_duplicates_are_removed_case_insensitively(self):
        config = msi.Config(extra_headers=['X-Spam', ' x-spam ', 'Message-ID'])
        self.assertEqual(config.valid_extra_headers(), ['X-Spam', 'Message-ID'])


class TestEvaluateHeaders(unittest.TestCase):
    """The complete result structure."""

    def test_result_shape(self):
        result = info(extra_headers=['X-Spam-Status']).evaluate_headers(headers(PASS_EML))
        self.assertEqual(set(result), {'status', 'summary', 'rows', 'headers', 'dkim_from'})
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['dkim_from'], 'pass')
        self.assertTrue(all({'label', 'value'} <= set(r) for r in result['rows']))
        self.assertTrue(all(set(h) == {'name', 'value'} for h in result['headers']))

    def test_no_dkim_marker_when_dkim_is_disabled(self):
        result = info(check_dkim=False).evaluate_headers(headers(PASS_EML))
        self.assertNotIn('dkim_from', result)

    def test_all_mechanisms_disabled_yields_nothing(self):
        engine = info(check_spf=False, check_dkim=False, check_dmarc=False)
        with self.assertLogs(msi.log, level='WARNING'):
            self.assertIsNone(engine.evaluate_headers(headers(PASS_EML)))

    def test_the_result_is_json_serializable(self):
        result = info().evaluate_headers(headers(FAIL_EML))
        self.assertEqual(json.loads(json.dumps(result)), result)


# -- text report -----------------------------------------------------------

class TestFormatReport(unittest.TestCase):
    """Rendering the result as plain text."""

    def report(self, message, color=False, **config):
        return msi.format_report(info(**config).evaluate_headers(headers(message)), color)

    def test_headline_carries_the_status_and_summary(self):
        first = self.report(PASS_EML).splitlines()[0]
        self.assertEqual(first, 'Message Security: ✓ PASS Sender authentication passed.')

    def test_rows_and_raw_headers_are_labelled(self):
        lines = self.report(PASS_EML, extra_headers=['X-Spam-Status']).splitlines()
        self.assertIn('Authentication results:', lines)
        self.assertTrue(any('SPF' in line and 'PASS — example.com' in line for line in lines))
        self.assertTrue(any(line.strip().startswith('X-Spam-Status') for line in lines))

    def test_the_from_marker_sentence_is_included(self):
        self.assertIn(msi.gettext('frommarkerpass'), self.report(PASS_EML))
        self.assertIn(msi.gettext('frommarkernone'), self.report(UNVERIFIED_EML))

    def test_multiline_values_are_aligned_under_the_value_column(self):
        lines = self.report(UNALIGNED_EML).splitlines()
        dkim = next(i for i, line in enumerate(lines) if 'DKIM' in line)
        note = lines[dkim + 1]
        self.assertEqual(note.strip(), 'does not match From (bank.example)')
        self.assertEqual(note.index('does'), lines[dkim].index('PASS'))

    def test_color_is_opt_in(self):
        self.assertNotIn('\033[', self.report(FAIL_EML))
        self.assertIn('\033[31m', self.report(FAIL_EML, color=True))

    def test_color_does_not_shift_the_columns(self):
        plain = self.report(PASS_EML).splitlines()
        colored = self.report(PASS_EML, color=True).splitlines()
        strip = lambda line: line.replace('\033[32m', '').replace('\033[0m', '')  # noqa: E731
        self.assertEqual([strip(line) for line in colored], plain)

    def test_the_marker_column_exists_only_when_a_row_has_a_marker(self):
        def value_column(report):
            return next(line.index('Alice') for line in report.splitlines() if 'Alice' in line)

        without = self.report(PASS_EML, check_dkim=False)
        self.assertEqual(value_column(self.report(PASS_EML)) - value_column(without), 2)
        # The glyph in the headline is not part of a row.
        self.assertNotIn('✓', without.split('\n', 1)[1])


class TestUseColor(unittest.TestCase):
    """The --color decision."""

    def test_explicit_choices(self):
        self.assertTrue(msi._use_color('always'))
        self.assertFalse(msi._use_color('never'))

    def test_auto_follows_the_tty(self):
        with mock.patch.object(sys, 'stdout', io.StringIO()):
            self.assertFalse(msi._use_color('auto'))

    def test_auto_honours_no_color(self):
        stdout = mock.Mock(isatty=lambda: True)
        with mock.patch.object(sys, 'stdout', stdout), \
                mock.patch.dict(os.environ, {'NO_COLOR': '1'}):
            self.assertFalse(msi._use_color('auto'))
        with mock.patch.object(sys, 'stdout', stdout), \
                mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(msi._use_color('auto'))


# -- command line ----------------------------------------------------------

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
            handle.name, msi.Config(check_spf=False, check_dmarc=False, check_tls=False))
        self.assertEqual([r['label'] for r in result['rows']], ['From', 'DKIM'])


EMAIL_DIR = pathlib.Path(__file__).resolve().with_name('emails')


@unittest.skipUnless(EMAIL_DIR.is_dir(), 'no emails/ sample messages')
class TestRealMessages(unittest.TestCase):
    """Smoke test over the sample messages in tests/emails/.

    Real headers are far messier than hand-written ones (many Received hops,
    several DKIM signatures, encoded words, odd whitespace), so these assert
    only what must hold for any message — never anything about their content,
    which lets the samples be replaced or obfuscated freely.
    """

    @classmethod
    def setUpClass(cls):
        cls.paths = sorted(EMAIL_DIR.glob('*.eml'))

    def test_every_sample_evaluates(self):
        for path in self.paths:
            with self.subTest(message=path.name):
                result = msi.evaluate_message_security_info(
                    str(path), msi.Config(extra_headers=['Message-ID', 'Return-Path']))

                self.assertIn(result['status'], ('pass', 'warn', 'fail', 'unknown'))
                self.assertIn(result['dkim_from'], ('pass', 'fail', 'none'))
                self.assertEqual(result['summary'], msi.gettext('summary' + result['status']))
                # From, SPF, DKIM, DMARC and TLS rows, all with a value.
                self.assertEqual(len(result['rows']), 5)
                self.assertTrue(all(r['value'] for r in result['rows']))
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

                self.assertIn(msi.gettext('linktitle'), report)
                self.assertIn(msi.gettext('frommarker' + result['dkim_from']), report)
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
                    str(path), msi.Config(trusted_authserv=['nobody.invalid']))
                rows = {r['label']: r['value'] for r in filtered['rows']}

                self.assertEqual(filtered['dkim_from'], 'none')
                self.assertNotIn('PASS', rows['DKIM'])
                self.assertEqual(rows['DMARC'], msi.gettext('notpresent'))

                # A Received-SPF header carries no authserv-id, so it cannot be
                # trust-filtered and may still produce a pass on its own; without
                # one there is nothing left to pass on.
                if not msi.load_headers(str(path)).get('Received-SPF'):
                    self.assertIn(filtered['status'], ('warn', 'unknown'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
