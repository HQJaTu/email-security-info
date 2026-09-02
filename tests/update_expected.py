#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Record the expected result of every sample message in emails/.

Writes one ``expected/<name>.json`` per ``emails/<name>.eml``, holding the
complete result the program produces for it under default settings.
``test_real_messages.py`` compares against these on every run, so a change in
what the program *says* about a real message shows up as a failing test rather
than passing quietly.

Run it from anywhere:

    python tests/update_expected.py            # write what changed
    python tests/update_expected.py --check    # report, change nothing
    python tests/update_expected.py --prune    # also delete orphaned files

Nothing here is a test. It is the tool you run after adding a sample message,
or after deliberately changing what the program reports — and in that second
case, read the diff it prints before committing it: that diff is the review.
"""

import argparse
import sys

from support import (EMAIL_DIR, EXPECTED_DIR, evaluate_sample, expected_path,
                     format_expected, sample_messages)


def _orphans() -> list:
    """Recorded results whose sample message is gone."""
    if not EXPECTED_DIR.is_dir():
        return []

    return sorted(path for path in EXPECTED_DIR.glob('*.json')
                  if not (EMAIL_DIR / (path.stem + '.eml')).is_file())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--check', action='store_true',
                        help='Report what would change and exit non-zero, writing nothing')
    parser.add_argument('--prune', action='store_true',
                        help='Delete recorded results whose sample message is gone')
    args = parser.parse_args(argv)

    messages = sample_messages()
    if not messages:
        print('No sample messages in emails/ — nothing to record.')

        return 0

    if not args.check:
        EXPECTED_DIR.mkdir(exist_ok=True)

    written = []
    for message in messages:
        recorded = expected_path(message)
        current = recorded.read_text('utf-8') if recorded.is_file() else None
        fresh = format_expected(evaluate_sample(message))

        if current == fresh:
            continue

        written.append(recorded)
        print(('new     ' if current is None else 'changed ') + recorded.name)
        if not args.check:
            recorded.write_text(fresh, 'utf-8')

    orphans = _orphans()
    for orphan in orphans:
        print('orphan  ' + orphan.name + ('' if args.prune else ' (--prune to delete)'))
        if args.prune and not args.check:
            orphan.unlink()

    if not written and not orphans:
        print('All {} sample messages match their recorded result.'.format(len(messages)))

        return 0

    print('{} of {} sample messages {}{}.'.format(
        len(written), len(messages),
        'differ from their recorded result' if args.check else 'recorded',
        ', {} orphaned file{}'.format(len(orphans), '' if len(orphans) == 1 else 's')
        if orphans else ''))

    return 1 if args.check else 0


if __name__ == '__main__':
    sys.exit(main())
