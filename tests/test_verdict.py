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


class TestBestDkim(unittest.TestCase):
    """Choosing between several DKIM signatures, where the best one wins."""

    def best(self, entries, from_domain='example.com', sig_domain=None):
        return info().best_dkim(entries, from_domain, sig_domain)

    def test_no_signatures_at_all_is_none(self):
        self.assertIsNone(self.best([]))

    def test_the_only_signature_is_the_best_one(self):
        entry = {'result': 'fail', 'domain': 'esp.test'}
        self.assertIs(self.best([entry]), entry)

    def test_an_aligned_pass_beats_an_unaligned_one(self):
        aligned = {'result': 'pass', 'domain': 'mail.example.com'}
        entries = [{'result': 'pass', 'domain': 'esp.test'}, aligned]
        self.assertIs(self.best(entries), aligned)

    def test_a_pass_beats_a_fail(self):
        good = {'result': 'pass', 'domain': 'esp.test'}
        self.assertIs(self.best([{'result': 'fail', 'domain': 'esp.test'}, good]), good)

    def test_an_unsigned_result_never_outranks_a_real_one(self):
        # dkim=none says the message carried no signature; it is not a rival
        # answer to one that verified, and it must not raise on the way past.
        good = {'result': 'pass', 'domain': 'esp.test'}
        self.assertIs(self.best([{'result': 'none', 'domain': None}, good]), good)

    def test_an_unsigned_result_is_reported_when_it_is_all_there_is(self):
        # It still has to come back — that is how the finding learns there was
        # nothing to check.
        entry = {'result': 'none', 'domain': None}
        self.assertIs(self.best([entry]), entry)

    def test_an_unrecognised_result_ranks_last(self):
        # Anything method_status does not recognise is no evidence either, and
        # a header this program has never seen before must not crash it.
        bad = {'result': 'fail', 'domain': 'esp.test'}
        self.assertIs(self.best([{'result': 'wat', 'domain': 'esp.test'}, bad]), bad)

    def test_equally_good_signatures_keep_the_first(self):
        first = {'result': 'pass', 'domain': 'esp.test'}
        self.assertIs(self.best([first, {'result': 'pass', 'domain': 'other.test'}]), first)

    def test_the_signature_domain_fills_in_a_missing_result_domain(self):
        # Judged on the domain the caller will display, so a result naming no
        # domain of its own is ranked by the DKIM-Signature it falls back to.
        bare = {'result': 'pass', 'domain': None}
        entries = [{'result': 'pass', 'domain': 'esp.test'}, bare]
        self.assertIs(self.best(entries, sig_domain='mail.example.com'), bare)


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
    """The overall verdict: the worst of the per-mechanism verdicts."""

    def evaluate(self, message, **config):
        engine = info(**config)
        h = headers(message)

        return engine.evaluate(engine.security_fields(h, engine.parse_authresults(h)))

    def test_the_status_is_the_worst_of_the_mechanisms(self):
        # The whole rule in one message: two mechanisms are happy and the
        # verdict is the third one's.
        verdict = self.evaluate('Authentication-Results: mx; spf=pass smtp.mailfrom=a.test; '
                                'dkim=fail header.d=a.test; dmarc=pass header.from=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'fail')

    def test_a_dmarc_pass_does_not_excuse_a_weaker_mechanism(self):
        # DMARC passing means the domain owner's policy was met on one of the
        # two mechanisms; it does not mean they agreed, and the disagreement is
        # the interesting part. An unaligned DKIM pass beside it still warns.
        verdict = self.evaluate('Authentication-Results: mx; spf=pass smtp.mailfrom=a.test; '
                                'dkim=pass header.d=esp.test; dmarc=pass header.from=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'warn')

    def test_a_forwarded_message_is_not_failed_on_its_broken_spf(self):
        # The one exception to the rule above, and it is not made here: a
        # mailing list breaks SPF while the aligned signature survives, and the
        # sender's own DMARC policy has already accepted that. The SPF finding
        # is demoted to warn in security_fields, so the headline still reads
        # straight off the rows. See _soften_relayed_spf.
        verdict = self.evaluate('Authentication-Results: mx; spf=fail smtp.mailfrom=list.test; '
                                'dkim=pass header.d=a.test; dmarc=pass header.from=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'warn')

    def test_an_unsigned_message_is_evaluated_rather_than_refused(self):
        # dkim=none is what an unsigned message gets, and it is ordinary. The
        # DKIM finding then contributes nothing and SPF carries the verdict.
        verdict = self.evaluate('Authentication-Results: mx; spf=pass smtp.mailfrom=a.test; '
                                'dkim=none\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'pass')

    def test_dmarc_alone_can_carry_the_verdict(self):
        # Not because DMARC is authoritative — because there is nothing worse
        # beside it to find.
        verdict = self.evaluate('Authentication-Results: mx; dmarc=pass header.from=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'pass')
        self.assertEqual(verdict['summary'], msi.i18n_gettext('summarypass'))

    def test_a_dmarc_fail_is_a_fail(self):
        verdict = self.evaluate('Authentication-Results: mx; dkim=pass header.d=a.test; '
                                'dmarc=fail header.from=a.test\nFrom: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'fail')

    def test_a_dmarc_none_does_not_soften_a_dkim_fail(self):
        verdict = self.evaluate('Authentication-Results: mx; dmarc=none; dkim=fail header.d=a.test\n'
                                'From: a@a.test\n\nbody\n')
        self.assertEqual(verdict['status'], 'fail')

    def test_a_disabled_dmarc_is_left_out_entirely(self):
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


class TestDkimVerdict(unittest.TestCase):
    """The DKIM finding's own verdict — what the report's glyph and `dkim_from` show.

    There is only one DKIM answer: `security['dkim']['verdict']` is what the row
    glyph is drawn from and what `dkim_from` is lifted out of, so a PASS that is
    not aligned reads `warn` in all three places rather than `warn` in one and
    `fail` in another.
    """

    def verdict(self, message, **config):
        engine = info(**config)
        h = headers(message)

        return engine.security_fields(h, engine.parse_authresults(h))['dkim']['verdict']

    def test_aligned_pass_is_pass(self):
        self.assertEqual(self.verdict(PASS_EML), 'pass')

    def test_unaligned_pass_is_a_warning_not_a_failure(self):
        # The signature verified — something really did sign this message. What
        # is wrong is that it was not the sender, which is a warning, and saying
        # 'fail' beside a PASS status only confuses the reader.
        self.assertEqual(self.verdict(UNALIGNED_EML), 'warn')

    def test_dkim_fail_is_fail(self):
        self.assertEqual(self.verdict(FAIL_EML), 'fail')

    def test_an_unverified_signature_is_unknown(self):
        # Signed, but your server did not check it: not a pass, and not a
        # failure either — nobody looked.
        self.assertEqual(self.verdict(UNVERIFIED_EML), 'unknown')

    def test_nothing_at_all_is_none(self):
        self.assertEqual(self.verdict('From: a@example.com\n\nbody\n'), 'none')

    def test_signature_domain_fills_in_a_missing_result_domain(self):
        message = ('Authentication-Results: mx; dkim=pass\n'
                   'DKIM-Signature: v=1; d=example.com; s=k1\n'
                   'From: a@example.com\n\nbody\n')
        self.assertEqual(self.verdict(message), 'pass')

    def test_a_pass_without_any_domain_warns(self):
        self.assertEqual(self.verdict('Authentication-Results: mx; dkim=pass\n'
                                      'From: a@example.com\n\nbody\n'), 'warn')

    def test_the_best_signature_is_judged_not_the_first(self):
        # A message signed by both an ESP and the sender's own domain is common,
        # and the two signatures are alternatives rather than separate claims:
        # the aligned one authenticates the message wherever it sits in the
        # header. (Contrast the mechanisms, where the worst wins — see
        # TestEvaluate.) Most of the samples in emails/ are signed twice.
        self.assertEqual(self.verdict('Authentication-Results: mx; dkim=pass header.d=esp.test; '
                                      'dkim=pass header.d=example.com\n'
                                      'From: a@example.com\n\nbody\n'), 'pass')

    def test_a_broken_signature_beside_an_aligned_one_does_not_count(self):
        # Order is irrelevant in both directions: the aligned pass wins whether
        # it comes first or last.
        self.assertEqual(self.verdict('Authentication-Results: mx; dkim=pass header.d=example.com; '
                                      'dkim=fail header.d=esp.test\n'
                                      'From: a@example.com\n\nbody\n'), 'pass')

    def test_the_first_signature_wins_a_tie(self):
        self.assertEqual(self.verdict('Authentication-Results: mx; dkim=pass header.d=esp.test; '
                                      'dkim=pass header.d=other.test\n'
                                      'From: a@example.com\n\nbody\n'), 'warn')

    def test_a_pass_without_a_from_header_warns(self):
        self.assertEqual(self.verdict('Authentication-Results: mx; dkim=pass header.d=a.test\n'
                                      '\nbody\n'), 'warn')

    def test_dkim_from_is_the_same_answer(self):
        # Lifted from the finding, never recomputed — the two cannot drift apart.
        for message in (PASS_EML, UNALIGNED_EML, FAIL_EML, UNVERIFIED_EML):
            with self.subTest(message=message.splitlines()[0]):
                result = info().evaluate_headers(headers(message))
                self.assertEqual(result['dkim_from'], result['security']['dkim']['verdict'])

    def test_a_disabled_dkim_check_reports_no_marker_at_all(self):
        result = info(check_dkim=False).evaluate_headers(headers(PASS_EML))
        self.assertNotIn('dkim_from', result)
        self.assertNotIn('dkim', result['security'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
