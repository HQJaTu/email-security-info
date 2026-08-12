Tests for message-security-info
===============================

Everything test-related lives in this directory: the test suite itself and the
sample messages it runs against. The program under test is the single file one
level up, `../message-security-info.py`.


Requirements
------------

Python 3.11+ and `configargparse` (the program's only dependency — the tests
import the program, so they need it too):

    pip install configargparse

Nothing else. The suite is stdlib `unittest`, so no test framework is required;
`pytest` works too if you prefer it.


Running them
------------

From the project root:

    python -m unittest discover -s tests          # quiet
    python -m unittest discover -s tests -v       # one line per test

Or straight from a file, which works from any directory:

    python tests/test_message_security_info.py    # verbose by default

With pytest, if you'd rather have its output and `-k` filtering:

    python -m pytest tests
    python -m pytest tests -k tls

Run one class or one test while working on it:

    python -m unittest tests.test_message_security_info.TestTlsInfo
    python -m unittest tests.test_message_security_info.TestTlsInfo.test_esmtpsa_is_encrypted

Expect ~150 tests in well under a second. There is no network access, no DNS and
no temporary state outside `tempfile` directories that clean themselves up.


Layout
------

    tests/
      README.md                        this file
      test_message_security_info.py    the whole suite
      emails/*.eml                     real-world sample messages (optional)

The suite is one file because the program is one file. Its classes are grouped
in the same order as the code they cover — header handling, Authentication-Results
parsing, trust filtering, TLS detection, alignment, the From header, verdicts,
formatting, the assembled result, the text report, and the command line.

`test_message_security_info.py` loads `../message-security-info.py` **by path**,
using `importlib`, rather than importing it. That is deliberate: the program
keeps its hyphenated, executable-style filename, which is not a valid Python
identifier, so `import message-security-info` is a syntax error. If the program
is ever renamed to `message_security_info.py`, the `_load_module()` helper at the
top of the suite can collapse into a plain `import`.


The sample messages in emails/
------------------------------

`TestRealMessages` runs the whole evaluation over every `emails/*.eml` file.
Real headers are far messier than hand-written ones — a dozen `Received` hops,
several DKIM signatures, encoded words, odd folding — so these samples catch
things the unit tests cannot anticipate.

The class asserts **only invariants that must hold for any message**, never
anything about the content of these particular ones: the status is one of the
four known values, the summary matches it, all five rows have a value, no raw
header value is left folded, the result survives a JSON round-trip, the report
renders without stray surrogates, and evaluation is deterministic.

That means you can add, replace, redact or obfuscate the samples freely without
touching the suite. Nothing depends on their bodies either — the program only
ever reads headers and never verifies signatures cryptographically, so
mangled MIME parts or rewritten bodies do not affect the results.

To add a message: drop the raw source in as `emails/<name>.eml` (in Roundcube:
*More → Download → As source*; in most other clients: *Save as* / *Show
original*). Redact what you like, but keep `Authentication-Results`,
`Received-SPF`, `DKIM-Signature`, `Received` and `From` intact — and keep them
mutually consistent, because rewriting a domain in `From` but not in
`Authentication-Results` (or vice versa) will change the alignment verdicts and
make the sample misleading rather than merely anonymous.

If this directory is missing or empty, `TestRealMessages` skips itself and the
rest of the suite still runs.


Two tests that document known limitations
----------------------------------------

These pin down behaviour inherited from the Roundcube PHP plugin that is
faithful but arguably wrong. They are written to fail loudly if someone changes
the behaviour, so that fixing it is a deliberate act, not an accident:

- `TestDkimFromMarker.test_only_the_first_signature_is_judged` — when a message
  carries several DKIM signatures (an ESP's plus the sender's own, which is
  common), only the first one is judged, so an aligned pass further down the
  header does not count. Most samples in `emails/` hit this.
- `TestRealMessages.test_a_trust_list_drops_all_untrusted_evidence` — a
  `Received-SPF` header carries no authserv-id, so `--trusted-authserv` cannot
  filter it and an SPF pass from it survives even when every
  `Authentication-Results` header is distrusted.

If either limitation is fixed, update the corresponding test rather than
deleting it.
