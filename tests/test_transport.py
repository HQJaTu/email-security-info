#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Detecting the transport encryption of the last hop from the Received header.

See README.md in this directory for how to run these.
"""

import unittest

from support import PASS_EML, headers, msi


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
