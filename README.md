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
      From                      Joel @ ngrok <team@m.ngrok.com>
      SPF                       PASS — 21124867m.ngrok.com
      DKIM                   ✗  PASS — 21124867m.ngrok.com
                                does not match From (m.ngrok.com)
      DMARC                     NONE — m.ngrok.com
      Transport (TLS)           Encrypted — TLSv1.2

      DKIM: signature does not match the sender, or verification failed.

      Authentication-Results    mta-in.example.com; dmarc=none (p=none …
      Received-SPF              Pass (mailfrom) identity=mailfrom; client-ip=…


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

The verdict itself: DMARC decides when it produced a real result (it already
implies an aligned SPF or DKIM pass); otherwise the present SPF and DKIM results
are combined, with anything missing or disabled left out. TLS is informational
and never changes the verdict.


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
is fixed: every mechanism entry always carries the same eight keys, whatever the
message says.

    {
      "status": "warn",
      "summary": "Sender authentication is incomplete or not aligned.",
      "info": {
        "header-from": "Joel @ ngrok <team@m.ngrok.com>",
        "transport": "Encrypted — TLSv1.2"
      },
      "security": {
        "spf": {
          "present": true, "verified": true, "status": "PASS",
          "domain": "21124867m.ngrok.com", "aligned": null,
          "verdict": "pass", "marker": null, "description": null
        },
        "dkim": {
          "present": true, "verified": true, "status": "PASS",
          "domain": "21124867m.ngrok.com", "aligned": false,
          "verdict": "warn", "marker": "fail",
          "description": "does not match From (m.ngrok.com)"
        },
        "dmarc": {
          "present": false, "verified": true, "status": "NONE",
          "domain": "m.ngrok.com", "aligned": null,
          "verdict": "none", "marker": null, "description": null
        }
      },
      "dkim_from": "fail",
      "headers": [
        {"name": "Authentication-Results", "value": "mta-in.example.com; …"}
      ]
    }

| Key | Meaning |
| --- | --- |
| `status` | The overall verdict: `pass`, `warn`, `fail` or `unknown`. |
| `summary` | The one-sentence version of `status`. |
| `info` | Descriptive, non-verdict fields, each a display string. |
| `security` | One entry per **enabled** mechanism, in SPF → DKIM → DMARC order. |
| `dkim_from` | The DKIM/From marker for the sender: `pass`, `fail` or `none`. Absent when the DKIM check is disabled. |
| `headers` | The raw header lines shown below the summary, unfolded. |

And within a `security` entry:

| Key | Meaning |
| --- | --- |
| `present` | The mechanism is in effect for this message. False when nothing was reported, and equally when the result was `none` — no SPF/DKIM/DMARC on the sending side. |
| `verified` | Your server checked this, rather than the message merely carrying an unverified claim (an unchecked `DKIM-Signature`). |
| `status` | The raw protocol result, upper case: `PASS`, `FAIL`, `SOFTFAIL`, `NONE`, `TEMPERROR`, … or `null` when there is no result. |
| `domain` | The domain the result is about: DKIM's signing domain, or the envelope/From domain SPF and DMARC judged. |
| `aligned` | Whether `domain` matches the From domain. DKIM only — the only mechanism this compares — and `null` where the question cannot be answered. |
| `verdict` | That mechanism's severity on its own: `pass`, `warn`, `fail`, `unknown` or `none`. |
| `marker` | The DKIM/From marker, mirroring the top-level `dkim_from`. `null` for SPF and DMARC. |
| `description` | A human-readable note — the alignment note, or why there is no result. `null` when there is nothing to add. |

A mechanism is missing from `security` only when its check is disabled, and
`transport` is missing from `info` only under `--no-check-tls`. Nothing else
appears or disappears based on the message.


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

Expect ~175 tests in well under a second. The suite needs no network, no DNS and
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
the two tests that pin down known limitations inherited from the PHP plugin.

### Style

Four-space indents, single quotes, ~99 columns, a blank line before each
`return`. Public functions and methods carry docstrings; comments explain why
rather than what. `pyflakes message-security-info.py tests/*.py` should stay
silent.


Credits and licence
-------------------

A port of the Roundcube `message_security_info` plugin, and GNU GPLv3+ like the
original.
