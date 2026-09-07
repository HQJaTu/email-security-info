message-security-info
=====================

Tells you whether a received email really came from who it says it did.

It reads a message's sender-authentication results — SPF, DKIM and DMARC —
compares the DKIM signing domain against the visible `From:` address, and prints
a verdict with the evidence it was based on. It also reports whether the last
hop was encrypted, and can show any other raw headers you care to inspect.

This is a command-line port of the Roundcube `message_security_info` plugin, for
use outside webmail: from a shell, from a mail client such as NeoMutt, or from
another program via `--json`.

    $ message-security-info.py message.eml
    Message Security: ! WARN Sender authentication is incomplete or not aligned.

    Authentication results:
      From                      ebookers Travel Information <noreply@n.ebookers.com>
      SPF                    ✓  PASS — mailer.ebookers.com
      DKIM                   !  PASS — mailer.ebookers.com
                                does not match From (n.ebookers.com)
      DMARC                  ·  NONE — n.ebookers.com
      Transport (TLS)           Encrypted — TLSv1.3

      DKIM: signed, but the signature does not match the sender address.

      Authentication-Results    mta-in.example.com; dmarc=none (p=none …
      Received-SPF              Pass (mailfrom) identity=mailfrom; client-ip=…

SPF passed here, so the message did leave a host the envelope domain authorises
— but the signature is `mailer.ebookers.com` while the visible sender says
`n.ebookers.com`, and no DMARC policy tied the two together. That gap is what
the warning is about, and it is the kind of thing a green "authenticated" badge
in a webmail client hides.

Each mechanism carries its own glyph and the headline carries the worst of them,
so the verdict can always be traced to the line that produced it — here, the `!`
on the headline is the `!` on the DKIM row:

    ✓  pass      the mechanism is satisfied
    !  warn      a result that verified, but does not add up (an unaligned
                 signature, a softfail, a neutral)
    ✗  fail      the mechanism says the message is not what it claims to be
    ?  unknown   a temporary error, or a signature nobody verified
    ·  none      nothing was reported — not a failing, and not counted as one


What it does and does not do
----------------------------

The cryptographic work is the receiving mail server's job, not this tool's. Your
server verifies the signatures and records the outcome in an
`Authentication-Results` header (RFC 8601):

    Authentication-Results: mx.example.org; dkim=pass header.d=example.com;
        spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com

This tool **reads and interprets** that header: it extracts the results and the
domains, applies the From-alignment comparison the header does not make for you,
and turns the whole thing into one verdict. It does **not** verify signatures
itself, and it performs no DNS lookups and no network access of any kind.

Two consequences worth knowing:

- If your mail server does not stamp `Authentication-Results`, there is little
  to report. A bare `DKIM-Signature` is detected and shown as *present but
  unverified*, and a `Received-SPF` header is used as an SPF fallback.
- `Authentication-Results` headers can be **forged by any hop upstream of your
  own server**. Pass `--trusted-authserv` with your own inbound server's
  authserv-id so only its verdict is believed. Without it, every such header is
  trusted — convenient, and spoofable.

The verdict itself is **the worst of the mechanisms**, and nothing else: SPF,
DKIM and DMARC are independent assertions about the same message, so the weakest
one governs and the headline can always be traced back to a line printed beneath
it. A DMARC pass does not excuse a weaker result beside it — DMARC passing means
the domain owner's policy was met, not that every mechanism agreed, and the
disagreement is the interesting part. Mechanisms that reported nothing, or that
you disabled, are left out rather than counted against the message. TLS is
informational and never changes the verdict.

Within DKIM the opposite rule applies, because it answers a different question: a
message is commonly signed twice, by the sending platform and by the sender's own
domain, and those two signatures are alternatives rather than separate claims.
One signature that verifies and is aligned with the `From:` domain authenticates
the message, whatever the other one says, so the best of them is the one
reported.

Two kinds of message are the exception, and both are settled on the mechanism
rather than on the headline.

**Forwarders and mailing lists break SPF** while the aligned DKIM signature
survives, so relayed mail arrives as `spf=fail` + `dkim=pass` + `dmarc=pass`. A
DMARC pass beside an SPF fail can only rest on that aligned signature, which
means the sending domain's own published policy has already weighed this exact
failure and accepted the message — so the SPF finding is demoted to a warning,
and says why:

      SPF                    !  FAIL — lists.example.net (DMARC accepted it on
                                       the signature)

**Mail you submitted yourself never travelled**, so SPF and DMARC were not a
check on it. Handing a message to your own server over an authenticated session
is not relay, and SPF is a rule about relay: it asks whether the connecting
address may send for the domain, and for a laptop on your own network the answer
is no — correctly, and about nothing at all. DMARC then fails as arithmetic on
that. Both stop counting, and a row names the evidence they were read in the
light of:

      SPF                    ·  FAIL — example.com (submitted from your own
                                       server, not relayed)
      DMARC                  ·  FAIL — example.com (submitted from your own
                                       server, not relayed)
      Submission                Authenticated as joe.user, from 192.168.8.126

This is recognised only when the message has a single hop and your server
recorded that its client authenticated — so a message that reached you any other
way cannot claim it, including one re-injected through your own server by a mail
client's "redirect", which keeps the hops that brought it. Nothing is promoted:
authenticating proves the account, not the address in `From:`, and a message left
with nothing to judge reads as a warning rather than a pass.

In both cases the result itself is untouched and still shown as FAIL. Only the
severity read from it changes, and it changes on the row, so the headline is
still exactly the worst of the lines beneath it. Nothing else is ever forgiven:
an SPF fail with no DMARC pass behind it fails, and a softfail stays a warning.


Requirements and installation
-----------------------------

Python 3.11 or newer, and one dependency:

    pip install -r requirements.txt        # ConfigArgParse

The program is a single self-contained file. There is nothing to build and
nothing to install: copy `message-security-info.py` wherever you like, make it
executable, and run it.

    chmod +x message-security-info.py
    cp message-security-info.py ~/.local/bin/message-security-info


Usage
-----

Give it an `.eml` file, or pipe a raw message in:

    message-security-info.py message.eml
    message-security-info.py < message.eml
    message-security-info.py -               # explicit stdin
    cat message.eml | message-security-info.py

With no argument, stdin is read whenever it is not a terminal, so the tool drops
straight into a pipeline. Run it with no argument *on* a terminal and it refuses
rather than hanging, since that is almost always a mistake.

Only the first message is read: piping an mbox or several concatenated messages
reports on the first one.

### Options

    --trusted-authserv AUTHSERV-ID   Only believe Authentication-Results stamped
                                     by this authserv-id — your own inbound mail
                                     server, the token before the first ';'.
                                     Repeatable. Strongly recommended.
    --no-check-spf                   Skip SPF entirely: dropped from both the
    --no-check-dkim                  verdict and the details. Use for whatever
    --no-check-dmarc                 your server does not stamp results for, so
                                     a check that is simply not deployed does
                                     not read as a permanent warning.
    --no-check-tls                   Do not report transport encryption.
    --extra-headers HEADER           Also show this raw header below the summary
                                     (e.g. X-Spam-Status). Repeatable; headers
                                     absent from the message are omitted.
    --json                           Print the result as JSON.
    --color auto|always|never        Colourize the text report. Default: auto —
                                     on when stdout is a TTY and NO_COLOR is
                                     unset.
    --exit-status                    Map the verdict onto the exit code.
    --log-level LEVEL                DEBUG … CRITICAL, default WARNING. Also
                                     read from $LOG_LEVEL.
    -c, --config PATH                Config file to read.

Each `--no-check-*` has a matching `--check-*` for turning it back on over a
config file that disabled it.

### Exit codes

By default the exit code says whether the message could be evaluated at all, not
what the verdict was:

    0   evaluated and reported
    1   the message could not be read, or every check was disabled
    2   no message given on a terminal, or a usage error

With `--exit-status` the verdict is reported instead, which is what you want in
a script:

    0   pass        4   fail
    3   warn        5   unknown

Since the verdict is the worst of the mechanisms, a script that only accepts 0
rejects more than forgeries: mailing-list and forwarded mail warns (its SPF is
broken by the relay), as does anything your server reported nothing for, and
your own submitted mail comes back 3 or 5 because nothing judged it. Accept 0
and 3 if that matters, or turn off the check your server does not stamp results
for.

### Configuration file

Anything you would rather not repeat goes in a TOML file, under a
`[message-security-info]` table, keyed by the long option name without the
leading dashes:

    [message-security-info]
    trusted-authserv = ["mx.example.org"]
    check-dmarc = false
    extra-headers = ["X-Spam-Status", "X-Mailer"]
    color = "always"

Pass it with `-c ~/.config/message-security-info.toml`. Command-line options
override the file.


JSON output
-----------

`--json` prints one object built for parsing rather than for reading. Its shape
is fixed: every mechanism entry always carries the same seven keys, whatever the
message says.

    {
      "status": "warn",
      "summary": "Sender authentication is incomplete or not aligned.",
      "info": {
        "header-from": "ebookers Travel Information <noreply@n.ebookers.com>",
        "transport": "Encrypted — TLSv1.3"
      },
      "security": {
        "spf": {
          "present": true, "verified": true, "status": "PASS",
          "domain": "mailer.ebookers.com", "aligned": null,
          "verdict": "pass", "description": null
        },
        "dkim": {
          "present": true, "verified": true, "status": "PASS",
          "domain": "mailer.ebookers.com", "aligned": false,
          "verdict": "warn",
          "description": "does not match From (n.ebookers.com)"
        },
        "dmarc": {
          "present": false, "verified": true, "status": "NONE",
          "domain": "n.ebookers.com", "aligned": null,
          "verdict": "none", "description": null
        }
      },
      "dkim_from": "warn",
      "headers": [
        {"name": "Authentication-Results", "value": "mta-in.example.com; …"}
      ]
    }

| Key | Meaning |
| --- | --- |
| `status` | The overall verdict: `pass`, `warn`, `fail` or `unknown`. Always the worst of the `verdict` fields in `security`. |
| `summary` | The one-sentence version of `status`. |
| `info` | Descriptive, non-verdict fields, each a display string. |
| `security` | One entry per **enabled** mechanism, in SPF → DKIM → DMARC order. |
| `dkim_from` | The DKIM verdict, lifted out for callers that only want it. Always equal to `security.dkim.verdict`; absent when the DKIM check is disabled. |
| `headers` | The raw header lines shown below the summary, unfolded. |

And within a `security` entry:

| Key | Meaning |
| --- | --- |
| `present` | The mechanism is in effect for this message. False when nothing was reported, and equally when the result was `none` — no SPF/DKIM/DMARC on the sending side. |
| `verified` | Your server checked this, rather than the message merely carrying an unverified claim (an unchecked `DKIM-Signature`). |
| `status` | The raw protocol result, upper case: `PASS`, `FAIL`, `SOFTFAIL`, `NONE`, `TEMPERROR`, … or `null` when there is no result. |
| `domain` | The domain the result is about: DKIM's signing domain, or the envelope/From domain SPF and DMARC judged. When a message carries several DKIM signatures, this is the one that was reported — the best of them. |
| `aligned` | Whether `domain` matches the From domain. DKIM only — the only mechanism this compares — and `null` where the question cannot be answered. |
| `verdict` | That mechanism's severity on its own: `pass`, `warn`, `fail`, `unknown` or `none`. `none` contributes nothing to `status`. This is also what the report's glyph is drawn from. |
| `description` | A human-readable note — the alignment note, why there is no result, or why a failed result is not counted as a failure. `null` when there is nothing to add. |

The `info` fields are `header-from` always, `transport` unless `--no-check-tls`,
and `submission` only on a message you submitted yourself, where it says who
authenticated and from where. A mechanism is missing from `security` only when
its check is disabled. Nothing else appears or disappears based on the message.


NeoMutt integration
-------------------

Bind a key to pipe the current message in:

    macro index,pager \Cs "<pipe-message>message-security-info.py --color always | less -R<enter>" "message security info"

Two settings matter, and getting them wrong makes every message look
unauthenticated:

    set pipe_decode = no

`pipe_decode` weeds headers on the way out, which strips
`Authentication-Results` — the tool would then find nothing to report and say
so, with no hint that NeoMutt removed the evidence. If you need `pipe_decode`
for other macros, set `unset pipe_decode_weed` instead so the full header block
survives.

`pipe_split` is irrelevant for a single message but matters when the macro is
run on a tagged set: leave it at its default and only the first message of the
batch is reported on. Add `set wait_key` if you want the output to stay on
screen without piping through a pager.


Development
-----------

    message-security-info.py    the whole program
    requirements.txt            ConfigArgParse — the only runtime dependency
    requirements-dev.txt        pytest, optional (the suite is stdlib unittest)
    tests/                      the test suite, its helpers and sample messages
    tests/emails/               real-world sample messages
    tests/expected/             the result recorded for each of them

The program is one file on purpose: it is distributed by copying it, and a
single file is the whole story — no package, no entry point, no install step.
The tests are not held to that; they are split by area under `tests/`. Inside
the file the layout is conventional: the i18n label table and
`SecurityInfoConfig` first, then header parsing, then `MessageSecurityInfo`
(which holds all of the evaluation logic), then the module-level presentation
helpers, then the CLI.

The result structure is the seam between the two halves. `evaluate_headers()`
produces it and knows nothing about display; `security_line()`, `report_rows()`
and `format_report()` consume it and hold all the formatting. Keep new
evaluation logic on the first side and new presentation on the second — that
separation is what makes the JSON output stable enough to parse.

### Running the tests

From the project root:

    python -m unittest discover -s tests          # quiet
    python -m unittest discover -s tests -v       # one line per test

One area at a time, straight from a file — this works from any directory:

    python tests/test_verdict.py                  # verbose by default
    python tests/test_verdict.py TestEvaluate
    python tests/test_verdict.py TestEvaluate.test_full_pass

With pytest, if you want its output and `-k` filtering:

    pip install -r requirements-dev.txt
    python -m pytest tests
    python -m pytest tests -k tls

Expect ~190 tests in well under a second. The suite needs no network, no DNS and
no fixtures beyond the sample messages in `tests/emails/`.

The dotted form (`python -m unittest tests.test_verdict`) deliberately does not
work: there is no `tests/__init__.py`, so `tests` is not a package. Use file
paths or `-k`.

### Recorded results for the sample messages

`tests/expected/<name>.json` holds the complete result the program produces for
`tests/emails/<name>.eml` under default settings, and every test run compares
the two. So a change in what the program *says* about a real message — a
verdict, a domain, a rendered note, a raw header — fails a test with a diff of
exactly what moved, instead of passing quietly.

    python tests/update_expected.py            # re-record what changed
    python tests/update_expected.py --check    # report only, exit 1 if anything differs

Run it after adding a sample message, or after deliberately changing what the
program reports — and in that second case read the diff before committing it,
because that diff is the only place a reviewer sees what the change did to
real-world output. Do not hand-edit the recorded files; a test checks they are
still in the form the tool writes.

See `tests/README.md` for what each test file covers, how the shared
`support.py` helpers work, how to add and redact your own sample messages, and
the tests that pin down deliberate behaviour and the one known limitation.

### Style

Four-space indents, single quotes, ~99 columns, a blank line before each
`return`. Public functions and methods carry docstrings; comments explain why
rather than what. `pyflakes message-security-info.py tests/*.py` should stay
silent.


Credits and licence
-------------------

A port of the Roundcube `message_security_info` plugin, and GNU GPLv3+ like the
original.
