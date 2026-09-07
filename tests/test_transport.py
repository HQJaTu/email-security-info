#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Reading the last hop off the Received header: its encryption, and whether it
was a message the reader submitted themselves.

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


class TestSubmissionInfo(unittest.TestCase):
    """Recognising a message the reader handed to their own server.

    What this detects is acted on in `_excuse_local_submission`, which stops
    counting SPF and DMARC, so the false negatives to guard against are messages
    that arrived some other way and would have their failures excused.
    """

    def submission(self, eml: str):
        return msi.MessageSecurityInfo.submission_info(headers(eml))

    def received(self, clause: str, client: str = 'from a.test'):
        return self.submission('Received: {} by mx.example.org {}; '
                               'Tue, 11 Aug 2026 10:00:01 +0200\n\nbody\n'.format(client, clause))

    def test_the_authenticated_transmission_types_are_recognised(self):
        # RFC 3848: the trailing A, with or without the S for TLS before it.
        for clause in ('with ESMTPA id 1', 'with ESMTPSA id 1',
                       'with LMTPA id 1', 'with LMTPSA id 1', 'with UTF8SMTPSA id 1'):
            with self.subTest(clause=clause):
                self.assertEqual(self.received(clause), {'user': None, 'client': None})

    def test_an_unauthenticated_hop_is_not_a_submission(self):
        # The whole distinction: same server, same TLS, no login. This is what
        # ordinary internet mail looks like, and it must keep its verdict.
        for clause in ('with ESMTP id 1', 'with ESMTPS id 1', 'with LMTP id 1'):
            with self.subTest(clause=clause):
                self.assertIsNone(self.received(clause))

    def test_the_authenticated_user_is_read_when_the_mta_logged_it(self):
        self.assertEqual(self.received('(Authenticated sender: joe.user) with ESMTPSA id 1'),
                         {'user': 'joe.user', 'client': None})

    def test_the_client_address_is_read_from_the_from_clause(self):
        self.assertEqual(
            self.received('with ESMTPSA id 1', 'from client (unknown [192.168.8.126])'),
            {'user': None, 'client': '192.168.8.126'})

    def test_an_ipv6_client_address_is_read(self):
        self.assertEqual(self.received('with ESMTPSA id 1', 'from client ([IPv6:2001:db8::1])'),
                         {'user': None, 'client': '2001:db8::1'})

    def test_the_receiving_servers_own_address_is_not_the_client(self):
        # Everything past "by" describes this end of the connection.
        self.assertEqual(
            msi.MessageSecurityInfo.submission_info(headers(
                'Received: from client by mx.example.org ([10.0.0.1]) with ESMTPSA id 1; '
                'Tue, 11 Aug 2026 10:00:01 +0200\n\nbody\n')),
            {'user': None, 'client': None})

    def test_a_message_with_an_earlier_hop_is_not_a_submission(self):
        # A message re-injected through your own server — a client's "redirect",
        # say — is an authenticated submission of something that travelled to
        # get here, and the results below belong to that journey. Excusing them
        # would let any forgery be laundered by bouncing it to yourself.
        self.assertIsNone(self.submission(
            'Received: from client by mx.example.org with ESMTPSA id 2; '
            'Tue, 11 Aug 2026 10:00:02 +0200\n'
            'Received: from evil.test by mx.example.org with ESMTPS id 1; '
            'Tue, 11 Aug 2026 10:00:01 +0200\n\nbody\n'))

    def test_no_received_header_is_not_a_submission(self):
        self.assertIsNone(self.submission('From: a@b.test\n\nbody\n'))

    def test_an_unrecognised_received_is_not_a_submission(self):
        self.assertIsNone(self.received('via local delivery'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
