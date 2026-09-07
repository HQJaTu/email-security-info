#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""The assembled result: the info fields, the security findings, the raw headers.

See README.md in this directory for how to run these.
"""

import json
import unittest

from support import (FAIL_EML, LOCAL_EML, PASS_EML, RELAYED_EML, UNALIGNED_EML, UNVERIFIED_EML,
                     headers, info, msi)


class TestInfoFields(unittest.TestCase):
    """The descriptive, non-verdict fields."""

    def fields(self, message, **config):
        return info(**config).info_fields(headers(message))

    def test_both_fields_by_default(self):
        self.assertEqual(self.fields(PASS_EML),
                         {'header-from': 'Alice Example <alice@example.com>',
                          'transport': 'Encrypted — TLSv1.3'})

    def test_transport_is_dropped_when_the_tls_check_is_off(self):
        self.assertEqual(list(self.fields(PASS_EML, check_tls=False)), ['header-from'])

    def test_the_sender_falls_back_to_not_present(self):
        self.assertEqual(self.fields('Subject: x\n\nbody\n')['header-from'],
                         msi.i18n_gettext('notpresent'))


class TestSecurityFields(unittest.TestCase):
    """The per-mechanism findings: which appear, and what each one says."""

    def fields(self, message, **config):
        engine = info(**config)
        h = headers(message)

        return engine.security_fields(h, engine.parse_authresults(h))

    def test_every_enabled_mechanism_appears_in_order(self):
        self.assertEqual(list(self.fields(PASS_EML)), ['spf', 'dkim', 'dmarc'])

    def test_disabled_mechanisms_are_absent(self):
        self.assertEqual(list(self.fields(PASS_EML, check_spf=False, check_dmarc=False)),
                         ['dkim'])

    def test_every_entry_has_the_same_keys(self):
        keys = {'present', 'verified', 'status', 'domain', 'aligned', 'verdict',
                'description'}
        for message in (PASS_EML, FAIL_EML, UNALIGNED_EML, UNVERIFIED_EML):
            for method, entry in self.fields(message).items():
                with self.subTest(message=message[:20], method=method):
                    self.assertEqual(set(entry), keys)

    def test_a_clean_pass(self):
        self.assertEqual(self.fields(PASS_EML)['spf'],
                         {'present': True, 'verified': True, 'status': 'PASS',
                          'domain': 'example.com', 'aligned': None, 'verdict': 'pass',
                          'description': None})

    def test_an_aligned_dkim_pass(self):
        self.assertEqual(self.fields(PASS_EML)['dkim'],
                         {'present': True, 'verified': True, 'status': 'PASS',
                          'domain': 'example.com', 'aligned': True, 'verdict': 'pass',
                          'description': msi.i18n_gettext('aligned')})

    def test_an_unaligned_dkim_pass(self):
        entry = self.fields(UNALIGNED_EML)['dkim']
        self.assertEqual(entry['status'], 'PASS')
        self.assertEqual(entry['domain'], 'mailer.net')
        self.assertFalse(entry['aligned'])
        self.assertEqual(entry['verdict'], 'warn')
        self.assertEqual(entry['description'],
                         msi.i18n_gettext('notaligned', {'from': 'bank.example'}))

    def test_a_signature_nobody_verified(self):
        # Signed, but the receiving server left no result: present, unverified,
        # and alignment deliberately unanswered.
        self.assertEqual(self.fields(UNVERIFIED_EML)['dkim'],
                         {'present': True, 'verified': False, 'status': None,
                          'domain': 'news.example.com', 'aligned': None,
                          'verdict': 'unknown',
                          'description': msi.i18n_gettext('unverified')})

    def test_a_mechanism_with_no_evidence_at_all(self):
        self.assertEqual(self.fields(UNVERIFIED_EML)['dmarc'],
                         {'present': False, 'verified': False, 'status': None,
                          'domain': None, 'aligned': None, 'verdict': 'none',
                          'description': msi.i18n_gettext('notpresent')})

    def test_a_none_result_is_reported_but_not_present(self):
        # dmarc=none means the sending domain has no DMARC: a real, verified
        # result saying the mechanism is not in effect.
        entry = self.fields('Authentication-Results: mx; dmarc=none header.from=a.test\n'
                            'From: a@a.test\n\nbody\n')['dmarc']
        self.assertFalse(entry['present'])
        self.assertTrue(entry['verified'])
        self.assertEqual(entry['status'], 'NONE')
        self.assertEqual(entry['verdict'], 'none')

    def test_a_relayed_spf_fail_is_demoted_but_still_shown(self):
        # A mailing list breaks SPF and the aligned signature carries DMARC.
        # The result stays FAIL — that is what the server said — while the
        # severity read from it drops to warn, with the row saying why.
        entry = self.fields(RELAYED_EML)['spf']
        self.assertEqual(entry['status'], 'FAIL')
        self.assertEqual(entry['verdict'], 'warn')
        self.assertEqual(entry['description'], msi.i18n_gettext('spfrelayed'))

    def test_a_relayed_spf_fail_is_demoted_with_dkim_switched_off(self):
        # The demotion rests on the server's DMARC evaluation, not on the DKIM
        # finding beside it, so switching DKIM off does not bring the fail back.
        self.assertEqual(self.fields(RELAYED_EML, check_dkim=False)['spf']['verdict'], 'warn')

    def test_an_spf_fail_dmarc_did_not_accept_stays_a_fail(self):
        # Nothing forgave this one: no DMARC result, so no policy weighed the
        # SPF failure and there is nothing to demote it on.
        entry = self.fields('Authentication-Results: mx; spf=fail smtp.mailfrom=list.test; '
                            'dkim=pass header.d=a.test\n'
                            'From: a@a.test\n\nbody\n')['spf']
        self.assertEqual(entry['verdict'], 'fail')
        self.assertIsNone(entry['description'])

    def test_an_spf_fail_beside_a_failing_dmarc_stays_a_fail(self):
        entry = self.fields('Authentication-Results: mx; spf=fail smtp.mailfrom=list.test; '
                            'dmarc=fail header.from=a.test\n'
                            'From: a@a.test\n\nbody\n')['spf']
        self.assertEqual(entry['verdict'], 'fail')

    def test_a_dmarc_pass_does_not_touch_a_softfail(self):
        # Only a fail is demoted. A softfail is already a warn, and a DMARC
        # pass must not turn any of this into a pass.
        entry = self.fields('Authentication-Results: mx; spf=softfail smtp.mailfrom=a.test; '
                            'dmarc=pass header.from=a.test\n'
                            'From: a@a.test\n\nbody\n')['spf']
        self.assertEqual(entry['verdict'], 'warn')
        self.assertNotEqual(entry['description'], msi.i18n_gettext('spfrelayed'))

    def test_a_local_submissions_spf_and_dmarc_stop_counting(self):
        # Mail the reader handed to their own server: SPF failed because the
        # client is a laptop on the LAN, which is not what SPF is a check on.
        # The results stay exactly as the server reported them; only the
        # severity read from them goes, and the row says why.
        fields = self.fields(LOCAL_EML)
        for method in ('spf', 'dmarc'):
            with self.subTest(method=method):
                self.assertEqual(fields[method]['status'], 'FAIL')
                self.assertEqual(fields[method]['verdict'], 'none')
                self.assertEqual(fields[method]['description'],
                                 msi.i18n_gettext('localsubmission'))

    def test_a_local_submission_is_not_promoted_to_a_pass(self):
        # Authenticating proves the account, not the address in From, so the
        # message ends up unjudged rather than trusted. This one carries no
        # signature either, so excusing SPF and DMARC leaves nothing at all to
        # judge — and combine_statuses answers that with a visible warn, which
        # is what stops the excuse from being a way to go quiet.
        engine = info()
        h = headers(LOCAL_EML)
        self.assertEqual(engine.evaluate_headers(h)['status'], 'warn')
        self.assertEqual(engine.info_fields(h)['submission'],
                         'Authenticated as joe.user, from 192.168.8.126')

    def test_the_submission_check_can_be_switched_off(self):
        # The one check here that changes the verdict and can be turned off:
        # with it off the results are counted exactly as the server reported
        # them, which is what you want when reading somebody else's mail.
        fields = self.fields(LOCAL_EML, check_submission=False)
        self.assertEqual(fields['spf']['verdict'], 'fail')
        self.assertEqual(fields['dmarc']['verdict'], 'fail')
        self.assertIsNone(fields['spf']['description'])

    def test_switching_the_submission_check_off_drops_its_row_too(self):
        # The flag is read in one place, so the row and the verdict cannot
        # disagree about whether this message was submitted.
        self.assertNotIn('submission',
                         info(check_submission=False).info_fields(headers(LOCAL_EML)))

    def test_a_local_submissions_passing_mechanism_is_left_alone(self):
        # Only a false alarm is removed. What did hold still gets to say so.
        fields = self.fields(LOCAL_EML.replace(b'spf=fail', b'spf=pass'))
        self.assertEqual(fields['spf']['verdict'], 'pass')
        self.assertIsNone(fields['spf']['description'])

    def test_a_message_relayed_before_it_arrived_keeps_its_failures(self):
        # The same submission hop, over a journey that had already happened.
        # See submission_info: this is the laundering case.
        fields = self.fields(LOCAL_EML.replace(
            b'From: Joe User',
            b'Received: from evil.test by mx.example.org with ESMTPS id 1;'
            b' Tue, 11 Aug 2026 09:00:00 +0200\nFrom: Joe User'))
        self.assertEqual(fields['spf']['verdict'], 'fail')
        self.assertEqual(fields['dmarc']['verdict'], 'fail')

    def test_spf_uses_the_received_spf_fallback(self):
        entry = self.fields('Received-SPF: Pass (mailfrom) envelope-from=a@a.test;\n'
                            'From: a@a.test\n\nbody\n')['spf']
        self.assertEqual((entry['status'], entry['domain'], entry['verified']),
                         ('PASS', 'a.test', True))


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


class TestEvaluateHeaders(unittest.TestCase):
    """The complete result structure."""

    def test_result_shape(self):
        result = info(extra_headers=['X-Spam-Status']).evaluate_headers(headers(PASS_EML))
        self.assertEqual(set(result),
                         {'status', 'summary', 'info', 'security', 'headers', 'dkim_from'})
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['dkim_from'], 'pass')
        self.assertEqual(set(result['info']), {'header-from', 'transport'})
        self.assertEqual(list(result['security']), ['spf', 'dkim', 'dmarc'])
        self.assertTrue(all(set(h) == {'name', 'value'} for h in result['headers']))

    def test_no_dkim_verdict_when_dkim_is_disabled(self):
        result = info(check_dkim=False).evaluate_headers(headers(PASS_EML))
        self.assertNotIn('dkim_from', result)

    def test_all_mechanisms_disabled_yields_nothing(self):
        engine = info(check_spf=False, check_dkim=False, check_dmarc=False)
        with self.assertLogs(msi.log, level='WARNING'):
            self.assertIsNone(engine.evaluate_headers(headers(PASS_EML)))

    def test_the_result_is_json_serializable(self):
        result = info().evaluate_headers(headers(FAIL_EML))
        self.assertEqual(json.loads(json.dumps(result)), result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
