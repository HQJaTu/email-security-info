#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Shared machinery for the test files in this directory. Not a test file itself.

The module under test lives one directory up and keeps its hyphenated,
executable-style name, which is not a valid Python identifier — so it is loaded
by path here instead of imported, once, and shared as ``support.msi``.

Every ``test_*.py`` in this directory starts with a plain ``import support``,
which works because unittest discovery, pytest and direct execution all put this
directory on ``sys.path``. See README.md.
"""

import importlib.util
import pathlib
import sys

MODULE_PATH = pathlib.Path(__file__).resolve().parent.parent / 'message-security-info.py'

EMAIL_DIR = pathlib.Path(__file__).resolve().with_name('emails')


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
    return msi.MessageSecurityInfo(msi.SecurityInfoConfig(**config))


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
