#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""The verdicts: per-method statuses, how they combine, and the DKIM/From marker.

See README.md in this directory for how to run these.
"""

import unittest

from support import (FAIL_EML, PASS_EML, UNALIGNED_EML, UNVERIFIED_EML, headers,
                     info, msi)


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
        self.assertEqual(verdict['summary'], msi.i18n_gettext('summarypass'))

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
        self.assertEqual(verdict['summary'], msi.i18n_gettext('summaryunknown'))

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
        # samples in emails/ hit this (see test_real_messages.py).
        self.assertEqual(self.marker('Authentication-Results: mx; dkim=pass header.d=esp.test; '
                                     'dkim=pass header.d=example.com\n'
                                     'From: a@example.com\n\nbody\n'), 'fail')

    def test_a_pass_without_a_from_header_is_fail(self):
        self.assertEqual(self.marker('Authentication-Results: mx; dkim=pass header.d=a.test\n'
                                     '\nbody\n'), 'fail')


if __name__ == '__main__':
    unittest.main(verbosity=2)
