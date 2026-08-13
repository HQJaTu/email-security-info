#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Message security info — a command line port of the Roundcube plugin.

Reports a received message's sender-authentication status (SPF / DKIM / DMARC)
for an RFC 822 message (``.eml`` file or stdin), plus the transport encryption
of the last hop and any additional raw headers you care to inspect.

How the verdict is determined
-----------------------------
The cryptographic checks are the job of the receiving mail server, which
records the outcome in the `Authentication-Results` header (RFC 8601), e.g.

    Authentication-Results: mx.example.org; dkim=pass header.d=example.com;
        spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com

This tool reads that header for the pass/fail results and the relevant domains,
and compares the DKIM signing domain to the visible From address. When no
`Authentication-Results` is present it falls back to detecting the raw
`DKIM-Signature` header (reported as "present but unverified"); it does not
verify the signature itself.

Because `Authentication-Results` headers added by hops you don't control can be
forged, pass ``--trusted-authserv`` with your own mail server's authserv-id(s)
for a trustworthy result.

Differences from the Roundcube plugin
------------------------------------
The IMAP/webmail-specific parts have no counterpart here: there is no
`fetch_headers` step (a local message has all of its headers), no Sent/Drafts
folder skipping and no per-user preference storage — the equivalent of the
plugin's admin config is the command line / config file.

@license GNU GPLv3+
@author Claude
"""

import argparse
import email.errors
import email.header
import email.parser
import email.policy
import email.utils
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field

import configargparse
import unicodedata

log = logging.getLogger(__name__)

#: Exit code per verdict for --exit-status (2 stays argparse's usage error).
EXIT_STATUS = {'pass': 0, 'warn': 3, 'fail': 4, 'unknown': 5}

#: User-visible strings, ported from the plugin's localization/en_US.inc.
I18N_LABELS = {
    'linktitle': 'Message Security',

    # Authentication-results report
    'authresults': 'Authentication results',
    'from': 'From',
    'spf': 'SPF',
    'dkim': 'DKIM',
    'dmarc': 'DMARC',
    'notpresent': 'not present',
    'aligned': 'aligned with From',
    'notaligned': 'does not match From ($from)',
    'unverified': 'present, not verified by your server',

    # DKIM marker on the message's From header
    'frommarkerpass': 'DKIM: signed and matches the sender address.',
    'frommarkerfail': 'DKIM: signature does not match the sender, or verification failed.',
    'frommarkernone': 'DKIM: this message is not signed.',

    # Transport encryption (informational; does not affect the verdict)
    'tls': 'Transport (TLS)',
    'tlsencrypted': 'Encrypted',
    'tlsplain': 'Not encrypted',
    'tlsunknown': 'unknown',

    # Overall verdict summary. Reflects DMARC when available, otherwise the
    # combined SPF + DKIM result.
    'summarypass': 'Sender authentication passed.',
    'summarywarn': 'Sender authentication is incomplete or not aligned.',
    'summaryfail': 'Sender authentication failed — the sender may be forged.',
    'summaryunknown': 'Sender authentication could not be verified.',
}

#: Glyph + ANSI colour per overall status, and per DKIM/From marker state.
REPORT_STATUS_STYLE = {
    'pass': ('✓', '32'),  # green
    'warn': ('!', '33'),  # amber
    'fail': ('✗', '31'),  # red
    'unknown': ('?', '90'),  # grey
}
REPORT_MARKER_STYLE = {
    'pass': ('✓', '32'),
    'fail': ('✗', '31'),
    'none': ('?', '33'),
}


def _setup_logger(options: configargparse.Namespace) -> None:
    log_level: int = logging.getLevelName(options.log_level)
    if not log_level:
        raise ValueError("Unkown logging level '{}'!".format(options.log_level))

    logging.basicConfig(
        format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  [%(name)s] %(message)s",
        level=log_level
    )


def i18n_gettext(name: str, variables: dict[str, str] | None = None) -> str:
    """
    One localized label, with the plugin's ``$var`` placeholders filled in.
    """
    text = I18N_LABELS.get(name, name)

    for key, value in (variables or {}).items():
        text = text.replace('$' + key, value)

    return text


@dataclass
class SecurityInfoConfig:
    """The tool's settings; the counterpart of the plugin's config.inc.php."""

    #: Only trust `Authentication-Results` headers stamped by these authserv-ids
    #: (typically your own inbound mail server's hostname — the first token of
    #: the header, before the first ';'). Empty considers every
    #: Authentication-Results header, which is convenient but can be spoofed by
    #: upstream hops you don't control. STRONGLY recommended to set.
    trusted_authserv: list[str] = field(default_factory=list)

    #: Which authentication mechanisms to evaluate and display. Disable any your
    #: mail server does not stamp results for, so you aren't shown a perpetual
    #: warning for a check that is simply not deployed. A disabled mechanism is
    #: dropped from the verdict AND from the details. With all three disabled
    #: there is nothing to evaluate and no result is produced.
    check_spf: bool = True
    check_dkim: bool = True
    check_dmarc: bool = True

    #: Report whether the message reached your server over an encrypted (TLS)
    #: SMTP connection, read from the topmost Received header. Informational
    #: only: it is shown but never changes the pass/warn/fail verdict.
    check_tls: bool = True

    #: Additional raw message headers to show below the parsed SPF / DKIM /
    #: DMARC summary and the Authentication-Results / Received-SPF lines.
    #: Useful for surfacing spam scores, routing, message ids, ... Headers not
    #: present on a message are simply omitted.
    extra_headers: list[str] = field(default_factory=list)

    def method_enabled(self, method: str) -> bool:
        """Whether a given check (spf, dkim, dmarc, tls) is enabled."""
        return bool(getattr(self, 'check_' + method, True))

    def valid_extra_headers(self) -> list[str]:
        """The configured extra headers: valid names only, de-duplicated."""
        headers: list[str] = []
        seen: set[str] = set()

        for name in self.extra_headers:
            name = str(name).strip()
            if not name:
                continue

            if not re.fullmatch(r'[A-Za-z0-9-]+', name):
                log.warning("Ignoring invalid header name '%s'", name)
                continue

            if name.lower() not in seen:
                seen.add(name.lower())
                headers.append(name)

        return headers


class RawCompat32(email.policy.Compat32):
    """A policy that hands back header values exactly as they were parsed.

    The default compat32 policy wraps a header holding non-ASCII bytes in an
    ``email.header.Header`` of unknown charset, which stringifies to replacement
    characters — losing e.g. the raw UTF-8 a display name was written in.
    Keeping the parser's surrogate-escaped string lets `_decode_bytes` recover
    the original bytes instead.
    """

    def header_fetch_parse(self, name, value):
        return value


def _decode_bytes(value: str) -> str:
    """
    Repair a header string the parser decoded as latin-1/surrogateescape.

    Raw headers are supposed to be ASCII, but real-world mail puts raw UTF-8
    (or worse) in them. Recover the original bytes and decode them as UTF-8,
    replacing whatever still doesn't decode so the value stays printable.
    """
    try:
        raw = value.encode('utf-8', 'surrogateescape')
    except UnicodeEncodeError:
        return value

    return raw.decode('utf-8', 'replace')


def _unfold(value: str) -> str:
    """
    Join a folded header value into a single line (RFC 5322 unfolding).
    """
    return re.sub(r'[ \t]*\r?\n[ \t]+', ' ', value).strip()


def _strip_formatting(text: str) -> str:
    """
    Drop control/formatting characters (bidi overrides, zero-width, ...).

    They can be used to spoof what a display name looks like; the visible —
    possibly confusable — glyphs are kept as-is.
    """
    return ''.join(c for c in text if unicodedata.category(c) not in ('Cc', 'Cf'))


class MessageHeaders:
    """
    The header set of one message, in the shape the ported logic expects.
    """

    def __init__(self, message: email.message.Message):
        self.message = message

    def get(self, name: str) -> list[str]:
        """
        Every value of a header, unfolded; missing/empty ones are dropped.

        The counterpart of Roundcube's ``$headers->get($name, false)`` plus the
        plugin's ``normalize()``.
        """
        values = []

        for value in self.message.get_all(name, []):
            value = _unfold(_decode_bytes(str(value)))
            if value:
                values.append(value)

        return values

    def first(self, name: str) -> str | None:
        """
        The first value of a header, or None when it is not present.
        """
        values = self.get(name)

        return values[0] if values else None

    @property
    def from_(self) -> str | None:
        """
        The raw (still RFC 2047 encoded) From header value.
        """
        return self.first('From')


class MessageSecurityInfo:
    """
    Evaluates the sender authentication of a message's headers.
    """

    #: Where to look for each method's domain inside an Authentication-Results
    #: entry.
    DOMAIN_KEYS = {
        'dkim': (r'header\.d', r'header\.i'),
        'spf': (r'smtp\.mailfrom', r'smtp\.helo', r'envelope-from'),
        'dmarc': (r'header\.from',),
    }

    def __init__(self, config: SecurityInfoConfig | None = None):
        self.config = config or SecurityInfoConfig()

    def evaluate_headers(self, headers: MessageHeaders) -> dict | None:
        """The verdict and the details for one message.

        Returns the same structure the plugin hands to its client: ``status``
        (pass/warn/fail/unknown), a one-line ``summary``, the parsed ``rows``,
        the ``headers`` to show raw and the DKIM/From marker ``dkim_from``.
        None when every authentication mechanism is disabled — there is then
        nothing to evaluate.
        """
        config = self.config

        if not (config.method_enabled('spf') or config.method_enabled('dkim')
                or config.method_enabled('dmarc')):
            log.warning('All of SPF, DKIM and DMARC are disabled — nothing to evaluate.')
            return None

        auth = self.parse_authresults(headers)
        verdict = self.evaluate(headers, auth)

        result = {
            'status': verdict['status'],
            'summary': verdict['summary'],
            'rows': self.summary_rows(headers, auth),
            'headers': self.raw_headers(headers),
        }

        # A DKIM/From marker for the message's From header ('pass' = signed &
        # aligned, 'fail' = signed-but-unaligned or failed, 'none' = unsigned).
        if config.method_enabled('dkim'):
            result['dkim_from'] = self.dkim_from_marker(headers, auth)

        return result

    def evaluate(self, headers: MessageHeaders, auth: dict) -> dict:
        """Overall sender-authentication verdict driving the status/summary.

        DMARC, when it actually evaluated, is authoritative — it already implies
        an aligned SPF or DKIM pass. Otherwise the present SPF and DKIM results
        are combined, omitting whichever is missing. Disabled mechanisms are
        excluded entirely.
        """
        config = self.config

        # DMARC is the overall verdict when enabled and it yielded a real result.
        if config.method_enabled('dmarc'):
            dmarc = auth['dmarc'][0]['result'] if auth['dmarc'] else None
            if dmarc == 'pass':
                return {'status': 'pass', 'summary': i18n_gettext('summarypass')}
            if dmarc == 'fail':
                return {'status': 'fail', 'summary': i18n_gettext('summaryfail')}

        # No usable DMARC: combine the SPF and DKIM results that are present.
        from_domain = self.from_domain(headers)
        statuses = []

        if config.method_enabled('spf'):
            spf = (auth['spf'][0] if auth['spf'] else None) or self.spf_from_received(headers)
            if spf:
                statuses.append(self.method_status('spf', spf, from_domain))

        if config.method_enabled('dkim'):
            if auth['dkim']:
                statuses.append(self.method_status('dkim', auth['dkim'][0], from_domain))
            elif headers.get('DKIM-Signature'):
                # Signature present but not verified by the receiving server.
                statuses.append('unknown')

        status = self.combine_statuses(statuses)

        return {'status': status, 'summary': i18n_gettext('summary' + status)}

    def method_status(self, method: str, entry: dict, from_domain: str | None) -> str:
        """Map one SPF/DKIM result to pass / warn / fail / unknown / none.

        DKIM also weighs From-alignment. "none" means it does not contribute.
        """
        result = entry['result']

        if result == 'pass':
            if method == 'dkim' and not self._aligned(entry.get('domain'), from_domain):
                return 'warn'
            return 'pass'
        if result == 'fail':
            return 'fail'
        if result in ('softfail', 'neutral', 'policy', 'permerror'):
            return 'warn'
        if result == 'temperror':
            return 'unknown'

        return 'none'  # none, etc.

    @staticmethod
    def combine_statuses(statuses: list[str]) -> str:
        """Reduce per-method statuses to one.

        Worst wins (fail > warn > pass); "none" entries are dropped; only-unknown
        stays unknown; nothing to check at all is a (visible) warning.
        """
        statuses = [s for s in statuses if s != 'none']

        if not statuses:
            return 'warn'
        for level in ('fail', 'warn', 'pass'):
            if level in statuses:
                return level

        return 'unknown'

    def parse_authresults(self, headers: MessageHeaders) -> dict:
        """Parse all DKIM/SPF/DMARC results from the Authentication-Results header(s)."""
        trusted = [a.lower() for a in self.config.trusted_authserv]
        out: dict[str, list[dict]] = {'dkim': [], 'spf': [], 'dmarc': []}

        for authresults in headers.get('Authentication-Results'):
            authresults = re.sub(r'\s+', ' ', authresults).strip()
            segments = authresults.split(';')
            first = segments[0].split()
            authserv = first[0].lower() if first else ''

            if trusted and authserv not in trusted:
                log.debug("Ignoring Authentication-Results of untrusted '%s'", authserv)
                continue

            for segment in segments[1:]:  # segments[0] is the authserv-id
                match = re.match(r'\s*(dkim|spf|dmarc)\s*=\s*([a-z]+)', segment, re.I)
                if not match:
                    continue

                method = match.group(1).lower()
                out[method].append({
                    'result': match.group(2).lower(),
                    'domain': self.extract_domain(method, segment),
                })

        return out

    def extract_domain(self, method: str, segment: str) -> str | None:
        """Pull the relevant domain out of one Authentication-Results method entry."""
        for key in self.DOMAIN_KEYS.get(method, ()):
            match = re.search(key + r'\s*=\s*@?([^\s;]+)', segment, re.I)
            if match:
                value = match.group(1).strip('<>').lower()

                return value.rpartition('@')[2] if '@' in value else value

        return None

    def spf_from_received(self, headers: MessageHeaders) -> dict | None:
        """Parse a Received-SPF header (RFC 7208) into {result, domain}.

        Example: "Pass (mailfrom) identity=mailfrom; client-ip=1.2.3.4;
                  envelope-from=user@example.com; ..."
        """
        for line in headers.get('Received-SPF'):
            match = re.match(r'\s*([a-z]+)', line, re.I)
            if not match:
                continue

            domain = None
            envelope = re.search(r'envelope-from\s*=\s*<?([^\s;>]+)', line, re.I)
            if envelope:
                value = envelope.group(1).strip('<>').lower()
                domain = value.rpartition('@')[2] if '@' in value else value

            return {'result': match.group(1).lower(), 'domain': domain}

        return None

    @staticmethod
    def tls_info(headers: MessageHeaders) -> dict | None:
        """Whether the message reached us over an encrypted SMTP connection.

        Read from the topmost Received header (the most recent hop — typically
        your own receiving server). Informational only; never affects the
        verdict. Returns {encrypted, detail}, or None when undeterminable.
        """
        received = headers.get('Received')
        if not received:
            return None

        top = re.sub(r'\s+', ' ', received[0])

        # Cipher/version detail, when the receiving MTA logged it, e.g.
        # "(using TLSv1.3 ...)" or "(version=TLS1_3 cipher=...)".
        detail = None
        version = re.search(r'\b(TLSv?[\d._]+|SSLv?[\d._]+)', top, re.I)
        if version:
            detail = version.group(1).replace('_', '.')

        # RFC 3848 transmission types: an "S" right after the SMTP/LMTP base
        # means STARTTLS/TLS was used (ESMTPS, ESMTPSA, LMTPS, ...). An "A"
        # (ESMTPA) is authentication without TLS.
        transmission = re.search(r'\bwith\s+(?:UTF8)?(?:ESMTP|SMTP|LMTP)(S)?A?\b', top, re.I)
        if transmission:
            return {'encrypted': bool(transmission.group(1)), 'detail': detail}

        # A version clause without a recognised transmission type still implies TLS.
        return {'encrypted': True, 'detail': detail} if detail is not None else None

    def summary_rows(self, headers: MessageHeaders, auth: dict) -> list[dict]:
        """The parsed SPF/DKIM/DMARC (and From/TLS) rows of the report."""
        config = self.config
        from_domain = self.from_domain(headers)
        signature = headers.first('DKIM-Signature')
        sig_domain = self._signature_domain(signature) if signature else None

        # SPF is often only in a Received-SPF header, not Authentication-Results.
        spf = (auth['spf'][0] if auth['spf'] else None) or self.spf_from_received(headers)

        # The sender address the SPF/DKIM/DMARC results are judged against.
        rows = [{
            'label': i18n_gettext('from'),
            'value': self.from_address(headers) or i18n_gettext('notpresent'),
        }]

        if config.method_enabled('spf'):
            rows.append({'label': i18n_gettext('spf'), 'value': self.format_method(spf)})

        if config.method_enabled('dkim'):
            rows.append({
                'label': i18n_gettext('dkim'),
                'value': self.format_dkim(auth['dkim'][0] if auth['dkim'] else None,
                                          sig_domain, from_domain),
                # Same verdict as the From-header marker, so the two can be
                # tied together visually.
                'marker': self.dkim_from_marker(headers, auth),
            })

        if config.method_enabled('dmarc'):
            rows.append({
                'label': i18n_gettext('dmarc'),
                'value': self.format_method(auth['dmarc'][0] if auth['dmarc'] else None),
            })

        if config.method_enabled('tls'):
            rows.append({'label': i18n_gettext('tls'), 'value': self.format_tls(self.tls_info(headers))})

        return rows

    def raw_headers(self, headers: MessageHeaders) -> list[dict]:
        """Raw header lines to show below the summary.

        Authentication-Results, Received-SPF, then any configured extras.
        Absent headers are skipped.
        """
        out = []

        for name in ['Authentication-Results', 'Received-SPF'] + self.config.valid_extra_headers():
            for value in headers.get(name):
                out.append({'name': name, 'value': value})

        return out

    @staticmethod
    def format_method(entry: dict | None) -> str:
        """Format an SPF/DMARC result line, e.g. "PASS — example.com"."""
        if not entry:
            return i18n_gettext('notpresent')

        value = entry['result'].upper()

        return value + ' — ' + entry['domain'] if entry.get('domain') else value

    def format_dkim(self, entry: dict | None, sig_domain: str | None,
                    from_domain: str | None) -> str:
        """Format the DKIM result line, including From-alignment."""
        if not entry:
            return (i18n_gettext('unverified') + ' — ' + sig_domain if sig_domain
                    else i18n_gettext('notpresent'))

        domain = entry.get('domain') or sig_domain
        value = entry['result'].upper()

        if domain:
            value += ' — ' + domain

        return value + self.dkim_alignment_note(entry['result'], domain, from_domain)

    def dkim_alignment_note(self, result: str, domain: str | None,
                            from_domain: str | None) -> str:
        """The From-alignment suffix appended to a DKIM result line.

        Empty for a clean aligned PASS, a newline-prefixed mismatch note for an
        unaligned PASS, or a parenthesised aligned/mismatch note for any
        non-pass result.
        """
        if not from_domain or not domain:
            return ''

        aligned = self._aligned(domain, from_domain)
        mismatch = i18n_gettext('notaligned', {'from': from_domain})

        if result.lower() == 'pass':
            # Positive result: a clean, aligned PASS shows nothing further; a
            # PASS whose signing domain isn't aligned adds the mismatch note on
            # its own line (no surrounding parentheses).
            return '' if aligned else '\n' + mismatch

        # Non-pass: parenthesised alignment note.
        return ' (' + (i18n_gettext('aligned') if aligned else mismatch) + ')'

    @staticmethod
    def format_tls(tls: dict | None) -> str:
        """Format the transport (TLS) result line."""
        if tls is None:
            return i18n_gettext('tlsunknown')
        if not tls.get('encrypted'):
            return i18n_gettext('tlsplain')

        return (i18n_gettext('tlsencrypted') + ' — ' + tls['detail'] if tls.get('detail')
                else i18n_gettext('tlsencrypted'))

    def from_domain(self, headers: MessageHeaders) -> str | None:
        """The domain of the visible From address."""
        parts = self.from_parts(headers)
        if not parts or '@' not in parts['addr']:
            return None

        return parts['addr'].rpartition('@')[2] or None

    @staticmethod
    def from_parts(headers: MessageHeaders) -> dict | None:
        """
        The decoded From display name and address as {name, addr}.

        None when there is no From header. The name has control/formatting
        characters (bidi overrides, zero-width, ...) stripped so it can't spoof
        the output, while keeping the visible — possibly confusable — glyphs.
        `name` is empty when there is no real display name.
        """
        raw = headers.from_
        if not raw:
            return None

        try:
            decoded = str(email.header.make_header(email.header.decode_header(raw)))
        except (UnicodeDecodeError, ValueError, email.errors.HeaderParseError):
            log.debug('Undecodable From header: %r', raw)
            decoded = raw

        addresses = email.utils.getaddresses([decoded])
        name, addr = addresses[0] if addresses else ('', '')

        name = name.strip()
        addr = addr.strip().lower()

        if not addr:
            match = re.search(r'[\w.+-]+@[\w.-]+', decoded)
            if match:
                addr = match.group(0).lower()

        name = _strip_formatting(name).strip()

        # Drop the name when it is really just the address repeated.
        if name and name.lower() == addr:
            name = ''

        return {'name': name, 'addr': addr}

    def from_address(self, headers: MessageHeaders) -> str | None:
        """
        The visible From value for display, as ``Name <local@domain>``.

        Showing both makes a deceptive/obfuscated display name — a common
        phishing trick — obvious next to the real address the DKIM/SPF/DMARC
        checks apply to. None when there is no From header.
        """
        parts = self.from_parts(headers)
        if not parts:
            return None

        if not parts['addr']:
            return parts['name'] or None

        return parts['name'] + ' <' + parts['addr'] + '>' if parts['name'] else parts['addr']

    def dkim_from_marker(self, headers: MessageHeaders, auth: dict) -> str:
        """
        From-header marker verdict, DKIM-specific and independent of the overall status.

        'pass' (a DKIM PASS aligned with the From domain), 'fail' (a PASS that
        isn't aligned, or any non-pass DKIM result) or 'none' (no verified DKIM
        result to judge).
        """
        entry = auth['dkim'][0] if auth['dkim'] else None
        if not entry:
            return 'none'

        if entry['result'].lower() != 'pass':
            return 'fail'

        from_domain = self.from_domain(headers)
        domain = entry.get('domain')

        if not domain:
            signature = headers.first('DKIM-Signature')
            if signature:
                domain = self._signature_domain(signature)

        return 'pass' if self._aligned(domain, from_domain) else 'fail'

    @staticmethod
    def _signature_domain(signature: str) -> str | None:
        """
        The d= signing domain of a raw DKIM-Signature header value.
        """
        match = re.search(r'(?:^|;)\s*d\s*=\s*([^;\s]+)', signature, re.I)

        return match.group(1).strip().lower() if match else None

    @staticmethod
    def _aligned(domain: str | None, from_domain: str | None) -> bool:
        """
        Relaxed alignment: equal, or one a subdomain of the other.

        Note: this is a pragmatic check, not a Public-Suffix-List organizational
        domain comparison, so e.g. two unrelated `*.co.uk` domains are not
        treated as aligned, but a true org-domain match is also not guaranteed.
        """
        if not domain or not from_domain:
            return False

        domain = domain.lower()
        from_domain = from_domain.lower()

        return (domain == from_domain
                or from_domain.endswith('.' + domain)
                or domain.endswith('.' + from_domain))


def _header_parser() -> email.parser.BytesParser:
    """
    A parser that reads headers only, keeping their bytes intact.
    """
    return email.parser.BytesParser(policy=RawCompat32())


def load_headers_from_bytes(data: bytes) -> MessageHeaders:
    """
    The headers of a raw RFC 822 message; its body is not parsed.
    """
    return MessageHeaders(_header_parser().parsebytes(data, headersonly=True))


def load_headers(eml_path: str) -> MessageHeaders:
    """
    Read a message's headers from an .eml file, or from stdin for '-'.
    """
    if eml_path == '-':
        log.debug('Reading message from stdin')
        return MessageHeaders(_header_parser().parse(sys.stdin.buffer, headersonly=True))

    log.debug("Reading message from '%s'", eml_path)
    with open(eml_path, 'rb') as handle:
        return MessageHeaders(_header_parser().parse(handle, headersonly=True))


def evaluate_message_security_info(eml_path: str, config: SecurityInfoConfig | None = None) -> dict | None:
    """
    Evaluate one message file: {status, summary, rows, headers, dkim_from}.

    None when every authentication mechanism is disabled.
    """
    return MessageSecurityInfo(config).evaluate_headers(load_headers(eml_path))


def _message_source(email: str | None) -> str | None:
    """
    Resolve where to read the message from: the given path, or stdin when the
    argument was omitted, which is how mail clients invoke a pipe command.

    None when nothing was given and stdin is a terminal — silently waiting for
    a message nobody is going to type by hand only looks like a hang.
    """
    if email:
        return email

    return None if sys.stdin.isatty() else '-'


def _report_use_color(when: str) -> bool:
    """Whether to colourize, honouring --color and the NO_COLOR convention."""
    if when == 'never':
        return False
    if when == 'always':
        return True

    return sys.stdout.isatty() and not os.environ.get('NO_COLOR')


def format_report(result: dict, color: bool = False) -> str:
    """Render the verdict, the parsed rows and the raw headers as plain text."""

    def paint(text: str, ansi: str) -> str:
        return '\033[' + ansi + 'm' + text + '\033[0m' if color else text

    status = result['status']
    glyph, ansi = REPORT_STATUS_STYLE.get(status, REPORT_STATUS_STYLE['unknown'])

    lines = [
        '{}: {} {}'.format(i18n_gettext('linktitle'),
                           paint(glyph + ' ' + status.upper(), ansi),
                           result['summary']),
        '',
        i18n_gettext('authresults') + ':',
    ]

    rows = result.get('rows', [])
    raw = result.get('headers', [])
    # One label column wide enough for the parsed rows and the raw header names.
    width = max([len(r['label']) for r in rows] + [len(h['name']) for h in raw] + [0])

    # Label column, plus room for the DKIM marker glyph when any row has one.
    marked = any(r.get('marker') for r in rows)
    label_width = width + (2 if marked else 0)

    def add(label: str, value: str, marker: str | None = None) -> None:
        """Append one label/value line, aligning any continuation lines."""
        head = label.ljust(width)

        if marker:
            # Padded uncoloured, so the ANSI escapes don't count towards width.
            head += ' ' + paint(*REPORT_MARKER_STYLE.get(marker, REPORT_MARKER_STYLE['none']))
        elif marked:
            head += '  '

        for i, part in enumerate(str(value).split('\n')):
            lines.append('  {}  {}'.format(head if i == 0 else ' ' * label_width, part))

    for row in rows:
        add(row['label'], row['value'], row.get('marker'))

    if 'dkim_from' in result:
        lines += ['', '  ' + i18n_gettext('frommarker' + result['dkim_from'])]

    if raw:
        lines.append('')
        for header in raw:
            add(header['name'], header['value'])

    return '\n'.join(lines)


def _parse_args(argv: list[str] | None = None) -> configargparse.Namespace:
    """
    Argument parser setup and incoming argument parsing.
    Note: This is a separate function for testability.
    :param argv: arguments
    :return: result of argument parsing
    """
    parser = configargparse.ArgParser(
        description='Email Message Security Info',
        epilog='Config file keys are the long option names without the leading '
               'dashes, in a [message-security-info] TOML table, e.g. '
               'check-tls = false or extra-headers = ["X-Spam-Status"].',
        config_file_parser_class=configargparse.TomlConfigParser(
            ['message-security-info']
        ),
    )
    parser.add_argument('email',
                        nargs='?',
                        metavar='EMAIL-TO-EVALUATE',
                        help=".eml file path, or '-' for stdin. Default: stdin, so a message "
                             'can simply be piped in (mail clients pipe the raw message)')
    parser.add_argument('--trusted-authserv',
                        action='append',
                        default=[],
                        metavar='AUTHSERV-ID',
                        help='Only trust Authentication-Results stamped by this authserv-id '
                             '(your own inbound mail server; the token before the first ";"). '
                             'Repeatable. Default: trust every Authentication-Results header, '
                             'which is convenient but spoofable by upstream hops')
    for method in ('spf', 'dkim', 'dmarc'):
        parser.add_argument('--check-' + method,
                            action=argparse.BooleanOptionalAction,
                            default=True,
                            help='Evaluate and report {}. A disabled mechanism is dropped from '
                                 'both the verdict and the details. Default: enabled'
                            .format(method.upper()))
    parser.add_argument('--check-tls',
                        action=argparse.BooleanOptionalAction,
                        default=True,
                        help='Report the transport encryption of the last hop, read from the '
                             'topmost Received header. Informational only — it never changes '
                             'the verdict. Default: enabled')
    parser.add_argument('--extra-headers',
                        action='append',
                        default=[],
                        metavar='HEADER',
                        help='Additional raw header to show below the summary (e.g. '
                             'X-Spam-Status). Repeatable; headers absent from the message '
                             'are omitted')
    parser.add_argument('--json',
                        action='store_true',
                        help='Print the result as JSON instead of a text report')
    parser.add_argument('--color',
                        default='auto',
                        choices=['auto', 'always', 'never'],
                        help='Colourize the text report. Default: auto (when stdout is a TTY '
                             'and NO_COLOR is unset)')
    parser.add_argument('--exit-status',
                        action='store_true',
                        help='Exit 0 on pass, 3 on warn, 4 on fail, 5 on unknown, instead of '
                             '0 whenever the message could be evaluated')
    parser.add_argument('--log-level',
                        default='WARNING',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        env_var='LOG_LEVEL',
                        help="Python logger log level. Default: WARNING")
    parser.add_argument('-c', '--config',
                        is_config_file=True,
                        help='Config file path')

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """
    The main stuff
    :param argv: arguments
    :return: exit code
    """
    args = _parse_args(argv)
    _setup_logger(args)

    source = _message_source(args.email)
    if source is None:
        log.error('No message given: pass an .eml file path, or pipe a message in')
        return 2

    config = SecurityInfoConfig(
        trusted_authserv=args.trusted_authserv,
        check_spf=args.check_spf,
        check_dkim=args.check_dkim,
        check_dmarc=args.check_dmarc,
        check_tls=args.check_tls,
        extra_headers=args.extra_headers,
    )

    try:
        result = evaluate_message_security_info(source, config)
    except OSError as error:
        log.error('Cannot read the message: %s', error)
        return 1

    if result is None:
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(format_report(result, _report_use_color(args.color)))

    return EXIT_STATUS.get(result['status'], 0) if args.exit_status else 0


if __name__ == '__main__':
    sys.exit(main())
