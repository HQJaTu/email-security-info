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

The overall status is the *worst* of the per-mechanism verdicts: SPF, DKIM and
DMARC are independent assertions about the same message, so the weakest one
governs, and a DMARC pass does not excuse a weaker result beside it. The single
exception is relayed mail, whose SPF a mailing list breaks and whose own DMARC
policy has already forgiven that; it is applied to the SPF finding rather than
to the status, so the headline still reads straight off the rows. Within DKIM
the rule is reversed — several signatures are alternatives, so the best of them
is the one reported. `evaluate`, `_soften_relayed_spf` and `best_dkim` carry the
reasoning.

Differences from the Roundcube plugin
------------------------------------
The IMAP/webmail-specific parts have no counterpart here: there is no
`fetch_headers` step (a local message has all of its headers), no Sent/Drafts
folder skipping and no per-user preference storage — the equivalent of the
plugin's admin config is the command line / config file.

The verdict is stricter. The plugin let a DMARC result decide on its own and
judged only the first DKIM signature; this combines every mechanism worst-first
and picks the best signature, so an ESP-signed message with an aligned second
signature now passes, and a message whose mechanisms disagree now warns instead
of being waved through on DMARC alone.

The From-header marker is gone as a separate answer. The plugin computed a
pass/fail marker beside the DKIM verdict, which meant an unaligned PASS could
read `warn` in one place and `fail` in another; here `dkim_from` is the DKIM
verdict itself, so the row glyph, the sentence below the table and the JSON all
say the same thing.

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
    'spfrelayed': 'DMARC accepted it on the signature',

    # The DKIM verdict spelled out, one sentence per value it can take.
    'frommarkerpass': 'DKIM: signed and matches the sender address.',
    'frommarkerwarn': 'DKIM: signed, but the signature does not match the sender address.',
    'frommarkerfail': 'DKIM: signature verification failed.',
    'frommarkerunknown': 'DKIM: signed, but your server did not verify the signature.',
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

#: Glyph + ANSI colour per verdict — the same five for the headline and the rows.
#:
#: One table on purpose: a reader who sees ✓ beside SPF and ! beside DKIM should
#: be able to read the ! on the headline as "the DKIM one won", which only works
#: while the same verdict always draws the same glyph.
REPORT_GLYPH_STYLE = {
    'pass': ('✓', '32'),  # green
    'warn': ('!', '33'),  # amber
    'fail': ('✗', '31'),  # red
    'unknown': ('?', '90'),  # grey
    'none': ('·', '90'),  # grey — nothing was reported, which is not a failing
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

    #: The security mechanisms reported, in report order.
    METHODS = ('spf', 'dkim', 'dmarc')

    #: DKIM verdicts from best to worst, for picking between signatures. 'none'
    #: is last on purpose: it reports the absence of a signature rather than a
    #: verdict on one, so any real result outranks it.
    DKIM_PREFERENCE = ('pass', 'warn', 'unknown', 'fail', 'none')

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

        Returns ``status`` (pass/warn/fail/unknown), a one-line ``summary``, the
        descriptive ``info`` fields, the ``security`` findings per mechanism, the
        ``headers`` to show raw and the DKIM verdict ``dkim_from``. None when
        every authentication mechanism is disabled — there is then nothing to
        evaluate.
        """
        config = self.config

        if not (config.method_enabled('spf') or config.method_enabled('dkim')
                or config.method_enabled('dmarc')):
            log.warning('All of SPF, DKIM and DMARC are disabled — nothing to evaluate.')
            return None

        auth = self.parse_authresults(headers)
        security = self.security_fields(headers, auth)
        verdict = self.evaluate(security)

        result = {
            'status': verdict['status'],
            'summary': verdict['summary'],
            'info': self.info_fields(headers),
            'security': security,
            'headers': self.raw_headers(headers),
        }

        # The DKIM verdict, lifted out for callers that only want the one
        # question "did the sender sign this themselves?" — and it is lifted,
        # not recomputed, so it can never disagree with the finding it names.
        if 'dkim' in security:
            result['dkim_from'] = security['dkim']['verdict']

        return result

    def evaluate(self, security: dict) -> dict:
        """Overall sender-authentication verdict driving the status/summary.

        The worst of the per-mechanism verdicts, and nothing else: the status is
        exactly ``combine_statuses`` over the ``verdict`` fields the caller can
        already see in `security`, so nothing decides the outcome off to one
        side where a reader of the output cannot follow it.

        Deliberately, a DMARC pass does not excuse a weaker result beside it.
        DMARC passing means the domain owner's policy was met; it does not mean
        every mechanism agreed, and the disagreement is the interesting part.

        The one case where a mechanism is not taken at face value — relayed
        mail, whose SPF the sender's own DMARC policy has already forgiven — is
        settled before this method sees it, in `_soften_relayed_spf`, so that
        the softened row is the one the reader can see. Nothing may be forgiven
        here: an exception applied at this point would put a `warn` headline
        above a visible `✗ FAIL` row, with no rule connecting the two.
        """
        status = self.combine_statuses([entry['verdict'] for entry in security.values()])

        return {'status': status, 'summary': i18n_gettext('summary' + status)}

    def best_dkim(self, entries: list[dict], from_domain: str | None,
                  sig_domain: str | None = None) -> dict | None:
        """The DKIM result that counts, out of every signature the server checked.

        A message is commonly signed twice — by the sending platform and by the
        sender's own domain — and the two are alternatives rather than
        independent claims: one signature that verifies and is aligned with the
        From domain authenticates the message, whatever the other one says. So
        the best result wins here, which is the exact opposite of how the
        mechanisms combine in `combine_statuses`, where the worst wins.

        A 'none' result is not one of the alternatives: it says the message
        carried no signature at all, so it ranks below every real result and
        wins only when it is the only thing reported.

        Ties keep the earliest signature. None when the server verified none.
        """
        if not entries:
            return None

        def rank(entry: dict) -> int:
            # Judge on the same domain the caller will display, falling back to
            # the raw DKIM-Signature when the result named no domain of its own.
            if sig_domain and not entry.get('domain'):
                entry = {**entry, 'domain': sig_domain}

            status = self.method_status('dkim', entry, from_domain)

            # A status this does not rank says nothing about a signature, so it
            # loses to every ranked one rather than raising here.
            return (self.DKIM_PREFERENCE.index(status) if status in self.DKIM_PREFERENCE
                    else len(self.DKIM_PREFERENCE))

        return min(entries, key=rank)

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
        """Reduce the per-mechanism statuses to one.

        Worst wins (fail > warn > pass): the mechanisms are independent
        assertions about the same message, so the weakest of them governs. (Not
        to be confused with `best_dkim`, which picks between several signatures
        *within* DKIM, where the best wins.)

        "none" entries are dropped; only-unknown stays unknown; nothing to check
        at all is a (visible) warning.
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

    def info_fields(self, headers: MessageHeaders) -> dict:
        """Descriptive facts about the message, as ready-to-display strings.

        Not verdicts — just what the message says about itself. 'header-from' is
        the sender address the SPF/DKIM/DMARC results are judged against;
        'transport' is present only while the TLS check is enabled.
        """
        info = {'header-from': self.from_address(headers) or i18n_gettext('notpresent')}

        if self.config.method_enabled('tls'):
            info['transport'] = self.format_tls(self.tls_info(headers))

        return info

    def security_fields(self, headers: MessageHeaders, auth: dict) -> dict:
        """The SPF/DKIM/DMARC findings: one fixed-shape entry per enabled mechanism.

        A disabled mechanism is absent entirely — nothing was evaluated, so
        there is nothing to report. Every entry present has the same keys, so a
        caller can read them without special-casing:

        present     the mechanism is in effect for this message. False when
                    nothing was reported at all, and equally when the reported
                    result was 'none' (no SPF/DKIM/DMARC on the sending side).
        verified    your receiving server checked this, rather than the message
                    merely carrying an unverified claim (an unchecked
                    DKIM-Signature is present but not verified).
        status      the raw protocol result, upper case (PASS, FAIL, SOFTFAIL,
                    NONE, TEMPERROR, ...), or None when there is no result.
        domain      the domain the result is about — DKIM's signing domain, or
                    the envelope/From domain SPF and DMARC judged.
        aligned     whether `domain` matches the From domain (DKIM only, since
                    that is the only mechanism this compares); None where the
                    question does not apply or cannot be answered.
        verdict     the normalised severity: pass, warn, fail, unknown, or none
                    (none = contributes nothing to the overall status). This is
                    also what the report draws its glyph from, so a finding can
                    never show a glyph that disagrees with its own verdict.
        description a human-readable note: the alignment note, why there is no
                    result, or why a failed SPF is not counted as a failure.
                    None when there is nothing to add.
        """
        config = self.config
        from_domain = self.from_domain(headers)
        signature = headers.first('DKIM-Signature')
        sig_domain = self._signature_domain(signature) if signature else None

        # SPF is often only in a Received-SPF header, not Authentication-Results.
        results = {
            'spf': (auth['spf'][0] if auth['spf'] else None) or self.spf_from_received(headers),
            'dkim': self.best_dkim(auth['dkim'], from_domain, sig_domain),
            'dmarc': auth['dmarc'][0] if auth['dmarc'] else None,
        }

        findings = {method: self._security_entry(method, results[method], from_domain,
                                                 sig_domain)
                    for method in self.METHODS if config.method_enabled(method)}

        return self._soften_relayed_spf(findings)

    @staticmethod
    def _soften_relayed_spf(findings: dict) -> dict:
        """Demote an SPF fail the sender's own DMARC policy has already accepted.

        A forwarder or a mailing list rewrites the envelope and breaks SPF while
        the aligned signature survives, so legitimately relayed mail arrives as
        spf=fail + dkim=pass + dmarc=pass. A DMARC pass beside an SPF fail can
        only rest on that aligned signature, which means the domain owner's
        published policy has already weighed this exact failure and accepted the
        message; reporting it as a failure is then a false alarm on the ordinary
        case of relayed mail.

        DMARC alone decides that, without consulting the DKIM finding: it is the
        receiving server's own DMARC evaluation, and it stays available when the
        DKIM check is switched off.

        Only the severity read from the result changes. The raw SPF result is
        still reported as FAIL, and the row says why it is not counted as one.
        This belongs here, on the finding, and never in `evaluate`: the headline
        has to stay exactly the worst of the verdicts printed beneath it, so the
        row and the headline have to move together.
        """
        spf, dmarc = findings.get('spf'), findings.get('dmarc')

        if not (spf and dmarc) or spf['verdict'] != 'fail' or dmarc['verdict'] != 'pass':
            return findings

        return {**findings,
                'spf': {**spf, 'verdict': 'warn', 'description': i18n_gettext('spfrelayed')}}

    def _security_entry(self, method: str, entry: dict | None, from_domain: str | None,
                        sig_domain: str | None) -> dict:
        """One mechanism's finding in the fixed shape security_fields documents."""
        if entry is None:
            # No verified result. A DKIM-Signature with nothing to confirm it is
            # still worth reporting: the message is signed, your server did not
            # check it. Alignment is deliberately left unanswered — an unverified
            # signature can claim any domain, so matching means nothing here.
            signed = method == 'dkim' and sig_domain is not None

            return {
                'present': signed,
                'verified': False,
                'status': None,
                'domain': sig_domain if signed else None,
                'aligned': None,
                'verdict': 'unknown' if signed else 'none',
                'description': i18n_gettext('unverified' if signed else 'notpresent'),
            }

        result = entry['result'].lower()
        domain = entry.get('domain') or (sig_domain if method == 'dkim' else None)
        aligned = None
        description = None

        if method == 'dkim' and domain and from_domain:
            aligned = self._aligned(domain, from_domain)
            description = (i18n_gettext('aligned') if aligned
                           else i18n_gettext('notaligned', {'from': from_domain}))

        return {
            'present': result != 'none',
            'verified': True,
            'status': result.upper(),
            'domain': domain,
            'aligned': aligned,
            # Judged on the domain the row displays, not on the raw result: a
            # result that named no domain of its own falls back to the
            # DKIM-Signature above, and the verdict has to follow it there or it
            # would contradict the line it is printed beside.
            'verdict': self.method_status(method, {**entry, 'domain': domain}, from_domain),
            'description': description,
        }

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
    Evaluate one message file: {status, summary, info, security, headers,
    dkim_from}.

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


def security_line(entry: dict) -> str:
    """One security finding as a display line, e.g. "PASS — example.com".

    An unaligned PASS carries its mismatch note on a second line; any other
    noteworthy result carries it parenthesised.
    """
    if entry['status'] is None:
        # Nothing was verified: either no result at all, or a signature your
        # server did not check. Either way the description says which.
        return (entry['description'] + ' — ' + entry['domain'] if entry['domain']
                else entry['description'])

    value = entry['status']

    if entry['domain']:
        value += ' — ' + entry['domain']

    if not entry['description']:
        return value

    if entry['status'] == 'PASS':
        # A clean, aligned PASS needs no further comment.
        return value if entry['aligned'] else value + '\n' + entry['description']

    return value + ' (' + entry['description'] + ')'


def report_rows(result: dict) -> list[tuple[str, str, str | None]]:
    """The result as (label, value, verdict) display rows, in report order.

    The verdict is what the row's glyph is drawn from, and None for the rows
    that carry no verdict at all — the From address and the transport.
    """
    info = result.get('info', {})
    rows = []

    if 'header-from' in info:
        rows.append((i18n_gettext('from'), info['header-from'], None))

    for method, entry in result.get('security', {}).items():
        rows.append((i18n_gettext(method), security_line(entry), entry['verdict']))

    if 'transport' in info:
        rows.append((i18n_gettext('tls'), info['transport'], None))

    return rows


def format_report(result: dict, color: bool = False) -> str:
    """Render the verdict, the findings and the raw headers as plain text."""

    def paint(text: str, ansi: str) -> str:
        return '\033[' + ansi + 'm' + text + '\033[0m' if color else text

    status = result['status']
    glyph, ansi = REPORT_GLYPH_STYLE.get(status, REPORT_GLYPH_STYLE['unknown'])

    lines = [
        '{}: {} {}'.format(i18n_gettext('linktitle'),
                           paint(glyph + ' ' + status.upper(), ansi),
                           result['summary']),
        '',
        i18n_gettext('authresults') + ':',
    ]

    rows = report_rows(result)
    raw = result.get('headers', [])
    # One label column wide enough for the findings and the raw header names.
    width = max([len(label) for label, _, _ in rows] + [len(h['name']) for h in raw] + [0])

    # Label column, plus room for the verdict glyph when any row has one.
    marked = any(verdict for _, _, verdict in rows)
    label_width = width + (2 if marked else 0)

    def add(label: str, value: str, verdict: str | None = None) -> None:
        """Append one label/value line, aligning any continuation lines."""
        head = label.ljust(width)

        if verdict:
            # Padded uncoloured, so the ANSI escapes don't count towards width.
            head += ' ' + paint(*REPORT_GLYPH_STYLE.get(verdict, REPORT_GLYPH_STYLE['unknown']))
        elif marked:
            head += '  '

        for i, part in enumerate(str(value).split('\n')):
            lines.append('  {}  {}'.format(head if i == 0 else ' ' * label_width, part))

    for label, value, verdict in rows:
        add(label, value, verdict)

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
