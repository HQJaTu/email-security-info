Tests for message-security-info
===============================

Everything test-related lives in this directory: the test files, the shared
helpers they use, and the sample messages they run against. The program under
test is the single file one level up, `../message-security-info.py`.


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

Or one area at a time, straight from a file, which works from any directory:

    python tests/test_verdict.py                  # verbose by default
    python tests/test_verdict.py TestEvaluate
    python tests/test_verdict.py TestEvaluate.test_full_pass

With pytest, if you'd rather have its output and `-k` filtering:

    python -m pytest tests
    python -m pytest tests/test_verdict.py
    python -m pytest tests -k tls

Expect ~190 tests in well under a second. There is no network access, no DNS and
no temporary state outside `tempfile` directories that clean themselves up.

Note that the dotted form (`python -m unittest tests.test_verdict`) does *not*
work: there is deliberately no `tests/__init__.py`, so this is not a package.
Use file paths or `-k` instead.


Layout
------

The program is one file because that is how it is distributed; the tests are
not, and split along the seams of what they cover:

    tests/
      README.md                 this file
      support.py                shared helpers — not a test file
      test_headers.py           reading raw headers: unfolding, repeats, bytes
      test_authresults.py       Authentication-Results, Received-SPF, trust filtering
      test_transport.py         TLS detection from the last Received hop
      test_alignment.py         relaxed From-alignment, DKIM signing domain
      test_sender.py            the From header: decoding, sanitizing, display
      test_verdict.py           per-method statuses, how they combine, the DKIM verdict
      test_formatting.py        one security finding → its displayed line
      test_result.py            the assembled result: info, security, raw headers
      test_report.py            the text report and the colour decision
      test_config.py            settings, the command line and the config file
      test_cli.py               the command line end to end: input, output, exit codes
      test_real_messages.py     emails/ against expected/, plus what must always hold
      update_expected.py        re-records expected/ — a tool, not a test
      emails/*.eml              real-world sample messages (optional)
      expected/*.json           the result recorded for each of them

Files roughly follow the order of the code they cover, from raw input to
rendered output. When you add a test, put it with the behaviour it exercises
rather than with the function it happens to call.

`support.py` holds everything shared: the module loader, the `headers()` and
`info()` constructors, the sample header blocks (`PASS_EML`, `FAIL_EML`,
`UNALIGNED_EML`, `LOCAL_EML`, `RELAYED_EML`, `UNVERIFIED_EML`) and `EMAIL_DIR`. Each test file imports it
plainly:

    import unittest

    from support import PASS_EML, headers, info

That plain `import support` works because unittest discovery, pytest and direct
execution all put this directory on `sys.path`.

`support.py` loads `../message-security-info.py` **by path**, using `importlib`,
rather than importing it, and exposes it as `support.msi`. That is deliberate:
the program keeps its hyphenated, executable-style filename, which is not a
valid Python identifier, so `import message-security-info` is a syntax error. If
the program is ever renamed to `message_security_info.py`, `_load_module()` can
collapse into a plain `import`.


The sample messages in emails/
------------------------------

`test_real_messages.py` runs the whole evaluation over every `emails/*.eml`
file. Real headers are far messier than hand-written ones — a dozen `Received`
hops, several DKIM signatures, encoded words, odd folding — so these samples
catch things the unit tests cannot anticipate.

It checks them in two ways, because the two catch different mistakes.

### Recorded results: expected/

`expected/<name>.json` holds the **complete result** the program produces for
`emails/<name>.eml` — status, summary, `info`, `security`, `dkim_from` and the
raw headers — evaluated under plain default settings: all four checks on, no
authserv-id trusted in particular, no extra headers. Every run re-evaluates each
sample and compares it against its recorded file, so any change in what the
program *says* about a real message fails, with a unified diff of exactly what
moved:

    AssertionError: test-01.eml no longer evaluates as recorded. If the new
    answer is the correct one, re-record it with `python tests/update_expected.py`.

    --- expected/test-01.eml
    +++ actual
    @@ -22,5 +22,5 @@
           "domain": "21124867m.ngrok.com",
    -      "aligned": false,
    +      "aligned": true,

**A failure here is not automatically a bug.** It means the reported answer
moved. Read the diff, decide whether the new answer is the better one, and if it
is, re-record it and commit the re-recorded file *together with* the change that
caused it — that diff is the review, and it is the only place a reviewer can see
what a refactor did to real-world output.

    python tests/update_expected.py            # write what changed
    python tests/update_expected.py --check    # report only, exit 1 if anything differs
    python tests/update_expected.py --prune    # also delete files whose .eml is gone

Never hand-edit a file in `expected/`: `test_the_recorded_results_are_current_format`
compares each one against its own re-serialization and fails if it is not in the
form the tool writes. The point of these files is that a human never types them.

### Invariants: whatever the samples happen to be

The rest of `test_real_messages.py` asserts **only what must hold for any
message**, never anything about the content of these particular ones: the status
is one of the four known values, the summary matches it, the status is
exactly the worst of the per-mechanism verdicts printed beneath it, `dkim_from`
is exactly the DKIM finding's verdict, every `info`
field carries a string, every mechanism in `security` has the same fixed set of
keys with values drawn from the known vocabularies, no raw header value is left
folded, the result survives a JSON round-trip, the report renders without stray
surrogates, and evaluation is deterministic.

These keep holding when the samples are replaced wholesale, and they are what
catches a *malformed* result — which a recorded file, being a recording, would
happily preserve.

### Adding, replacing or redacting a message

Drop the raw source in as `emails/<name>.eml` (in Roundcube: *More → Download →
As source*; in most other clients: *Save as* / *Show original*), then record its
result:

    python tests/update_expected.py

Redact what you like, but keep `Authentication-Results`, `Received-SPF`,
`DKIM-Signature`, `Received` and `From` intact — and keep them mutually
consistent, because rewriting a domain in `From` but not in
`Authentication-Results` (or vice versa) will change the alignment verdicts and
make the sample misleading rather than merely anonymous. Editing a sample means
re-recording it, and the resulting diff is worth a glance: it tells you whether
your redaction changed the verdict.

Nothing depends on the message bodies — the program only ever reads headers and
never verifies signatures cryptographically, so mangled MIME parts or rewritten
bodies do not affect the results.

Note that a recorded result contains the sender address, the authentication
domains and the raw header lines of its sample, in clear. That is the same
content as the `.eml` beside it, so it discloses nothing new — but it does mean
redacting a sample is only finished once its recorded result has been rewritten
too.

If `emails/` is missing or empty, `test_real_messages.py` skips itself and the
rest of the suite still runs.


Tests that pin down deliberate behaviour
----------------------------------------

These tests exist to fail loudly if someone changes behaviour that was chosen on
purpose, so that changing it again is a deliberate act rather than an accident.

- `test_verdict.py`, `TestDkimVerdict.test_dkim_from_is_the_same_answer` — there is
  exactly one DKIM answer. The row glyph, the sentence below the table and the
  JSON's `dkim_from` are all the DKIM finding's `verdict`, never recomputed
  alongside it. They used to be computed twice and drifted apart, so an unaligned
  PASS showed `verdict: warn` beside a `✗`.
- `test_verdict.py`, `TestEvaluate.test_a_dmarc_pass_does_not_excuse_a_weaker_mechanism`
  — the verdict is the worst of SPF, DKIM and DMARC, and a DMARC pass does not
  lift a warning beside it. The Roundcube plugin let DMARC decide on its own;
  this does not.
- `test_verdict.py`, `TestEvaluate.test_a_forwarded_message_is_not_failed_on_its_broken_spf`
  and `test_result.py`, `TestSecurityFields.test_a_relayed_spf_fail_is_demoted_but_still_shown`
  — one of the two exceptions to the rule above, and where it is made. A mailing
  list breaks SPF while the aligned signature survives, and the sending domain's
  own DMARC policy has already accepted that, so the SPF *finding* is demoted to
  `warn`. It is demoted there and never in `evaluate()`, because the headline
  must stay exactly the worst of the verdicts printed beneath it — an exception
  applied to the headline would put `warn` above a visible `✗ FAIL` row. The
  other exception, below, is made in the same place for the same reason.
- `test_result.py`,
  `TestSecurityFields.test_a_local_submissions_spf_and_dmarc_stop_counting` and
  `test_transport.py`,
  `TestSubmissionInfo.test_a_message_with_an_earlier_hop_is_not_a_submission` —
  mail the reader submitted to their own server never travelled, so SPF and
  DMARC never judged it and both findings go to `none`. Two things hold this
  down. It is recognised only from the topmost `Received` header, on a message
  that has exactly one — anything else carries the hops that brought it, so a
  message re-injected through your own server cannot launder its failures this
  way. And nothing is promoted: `test_a_local_submission_is_not_promoted_to_a_pass`
  pins that a message with nothing left to judge comes back `warn`, which is
  what stops the excuse from being a route to silence.
- `test_transport.py`, `TestSubmissionInfo.test_an_unauthenticated_hop_is_not_a_submission`
  — `ESMTPS` and `ESMTPSA` differ by one letter and by everything else: the
  RFC 3848 `A` is the receiving server recording that the client logged in.
  Two sample blocks in `support.py` once carried a stray `A` and were quietly
  treated as submissions when this landed, which is what this test is for.
- `test_real_messages.py`,
  `TestRealMessages.test_a_trust_list_drops_all_untrusted_evidence` — a
  `Received-SPF` header carries no authserv-id, so `--trusted-authserv` cannot
  filter it and an SPF pass from it survives even when every
  `Authentication-Results` header is distrusted. This one is a genuine
  limitation, not a choice; if it is fixed, update the test rather than deleting
  it.
