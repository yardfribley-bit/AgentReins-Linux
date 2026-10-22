#!/usr/bin/env python3
"""Negative cases for the new rules, including S23 learning and key reordering. Exits 0 only when none of them alert."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.capability_cases import run_cases


def main(argv=None):
    out = Path((argv or sys.argv[1:])[0] if (argv or sys.argv[1:]) else '.')
    out.mkdir(parents=True, exist_ok=True)
    summary = run_cases('baseline')
    (out / 'baseline.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    if not summary['ok']:
        failed = [item['id'] for item in summary['cases'] if not item['ok']]
        print('baseline failed: ' + ', '.join(failed), file=sys.stderr)
        return 1
    print('baseline ok %d cases' % len(summary['cases']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
