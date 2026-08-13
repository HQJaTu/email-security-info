#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""The assembled result: which rows and raw headers it contains, and its shape.

See README.md in this directory for how to run these.
"""

import json
import unittest

from support import FAIL_EML, PASS_EML, UNVERIFIED_EML, headers, info, msi


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
                         msi.i18n_gettext('notpresent'))

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
