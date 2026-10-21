#!/usr/bin/env python3
"""Read-only overlay upperdir snapshot.

Volumes and bind mounts are not in UpperDir and are reported as a blind spot.
The script never writes into the container filesystem and never follows symlinks.
Whiteouts (character device 0:0, or a .wh. name) are deletions.
"""
import argparse
import difflib
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

try:
    from runtime.redact import redact_text
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from runtime.redact import redact_text

BLIND = 'volumes and bind mounts are not in the overlay upperdir'
MAX_HASH = 8 * 1024 * 1024
MAX_DIFF = 8192
MAX_LINES = 80


def coverage_record(name, phase, driver, mounts, upper, note=None):
    return {
        'kind': 'coverage',
        'container': name,
        'phase': phase,
        'driver': driver,
        'upperdir': upper,
        'mountsNotCovered': mounts,
        'blindSpots': [BLIND, 'symlinks are recorded but not followed', 'files larger than 8 MiB are size-only'],
        'note': note,
    }


def digest_file(path, size):
    if size > MAX_HASH:
        return None
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        # A symlink would have been filtered; O_NOFOLLOW also refuses it.
        info = os.fstat(fd)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return None
        hasher = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            hasher.update(block)
        return hasher.hexdigest()
    finally:
        os.close(fd)


def is_whiteout(name, mode, rdev):
    if name.startswith('.wh.') or name == '.wh..wh..opq':
        return True
    return stat.S_ISCHR(mode) and os.major(rdev) == 0 and os.minor(rdev) == 0


def scan_upper(upper, name, phase='snapshot', driver='overlay2', mounts=None):
    upper = str(upper)
    records = [coverage_record(name, phase, driver, mounts or [], upper)]
    root = Path(upper)
    if not root.is_dir():
        records[0]['note'] = 'upperdir missing'
        return records
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        kept = []
        for dirname in dirnames:
            full = Path(dirpath) / dirname
            try:
                st = full.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                records.append(_entry(root, full, st, 'symlink', name, phase))
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            try:
                st = full.lstat()
            except OSError:
                continue
            records.append(_entry(root, full, st, None, name, phase))
    return records


def _entry(root, full, st, forced, name, phase):
    rel = '/' + full.relative_to(root).as_posix()
    mode = st.st_mode
    if forced == 'symlink' or stat.S_ISLNK(mode):
        kind = 'symlink'
    elif is_whiteout(full.name, mode, st.st_rdev):
        kind = 'whiteout'
    elif stat.S_ISREG(mode):
        kind = 'file'
    else:
        kind = 'other'
    deleted = None
    if kind == 'whiteout' and full.name.startswith('.wh.') and full.name != '.wh..wh..opq':
        deleted = str(Path(rel).with_name(full.name[4:]))
    record = {
        'kind': kind,
        'container': name,
        'phase': phase,
        'path': deleted or rel,
        'overlayPath': rel,
        'size': st.st_size,
        'mode': oct(mode & 0o777),
        'confidence': 'correlated',
        'basis': 'overlay upperdir shows this container changed the path; process is unknown',
    }
    if kind == 'file':
        record['sha256'] = digest_file(full, st.st_size)
        if record['sha256'] is None and st.st_size > MAX_HASH:
            record['skipped'] = 'too_large'
    if kind == 'whiteout':
        record['change'] = 'deleted'
    return record


def read_limited(path):
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DIFF:
            return None
        data = os.read(fd, MAX_DIFF)
    finally:
        os.close(fd)
    if b'\0' in data:
        return None
    text = redact_text(data.decode('utf-8', 'replace'))
    return '\n'.join(text.splitlines()[:MAX_LINES])


def text_diff(before, after):
    old = (before or '').splitlines()
    new = (after or '').splitlines()
    diff = ''.join(difflib.unified_diff(old, new, lineterm='\n', n=1))
    return redact_text('\n'.join(diff.splitlines()[:MAX_LINES]))


def load_jsonl(path):
    records = []
    with open(path) as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def diff_snapshots(before, after, lower_roots=None):
    before_files = {item['path']: item for item in before if item.get('kind') in ('file', 'whiteout', 'symlink')}
    after_files = {item['path']: item for item in after if item.get('kind') in ('file', 'whiteout', 'symlink')}
    changes = []
    for path in sorted(set(before_files) | set(after_files)):
        old = before_files.get(path)
        new = after_files.get(path)
        if new and new.get('kind') == 'whiteout' and not old:
            changes.append({**new, 'change': 'deleted'})
            continue
        if old and not new:
            changes.append({**old, 'change': 'deleted'})
            continue
        if new and not old:
            changes.append({**new, 'change': 'added'})
            continue
        if not old or not new:
            continue
        if old.get('sha256') != new.get('sha256') or old.get('size') != new.get('size') or old.get('mode') != new.get('mode'):
            item = dict(new)
            item['change'] = 'modified'
            item['sha256Before'] = old.get('sha256')
            item['sha256After'] = new.get('sha256')
            changes.append(item)
    header = next((item for item in after if item.get('kind') == 'coverage'), coverage_record('', 'diff', None, [], None))
    header = dict(header)
    header['phase'] = 'diff'
    header['changeCount'] = len(changes)
    return [header] + changes


def docker_inspect(name):
    raw = subprocess.check_output(['docker', 'inspect', name], text=True, timeout=15)
    info = json.loads(raw)[0]
    graph = info.get('GraphDriver') or {}
    data = graph.get('Data') or {}
    mounts = []
    for mount in info.get('Mounts') or []:
        mounts.append({'type': mount.get('Type'), 'destination': mount.get('Destination'), 'covered': False, 'reason': BLIND})
    lower = data.get('LowerDir') or ''
    return {
        'driver': graph.get('Name'),
        'upper': data.get('UpperDir'),
        'lowers': [part for part in lower.split(':') if part],
        'mounts': mounts,
    }


def write_jsonl(path, records):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description='Read-only container upperdir change scan')
    parser.add_argument('--name', default='container')
    parser.add_argument('--phase', default='snapshot', choices=['before', 'after', 'snapshot', 'diff'])
    parser.add_argument('--upper', help='UpperDir path, for hosts where docker inspect is not used')
    parser.add_argument('--lower', action='append', default=[], help='LowerDir path, repeatable, not required for the hash diff')
    parser.add_argument('--docker', action='store_true', help='Read UpperDir from docker inspect --name')
    parser.add_argument('--baseline')
    parser.add_argument('--after')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.baseline and args.after:
        changes = diff_snapshots(load_jsonl(args.baseline), load_jsonl(args.after))
        write_jsonl(args.out, changes)
        print(json.dumps({'records': len(changes), 'out': args.out, 'blindSpots': [BLIND]}))
        return
    mounts = []
    driver = 'overlay2'
    upper = args.upper
    if args.docker:
        info = docker_inspect(args.name)
        driver = info['driver']
        upper = info['upper']
        mounts = info['mounts']
        if driver != 'overlay2' or not upper:
            note = 'driver %s has no overlay upperdir; path list only via docker diff' % driver
            records = [coverage_record(args.name, args.phase, driver, mounts, upper, note)]
            try:
                diff = subprocess.check_output(['docker', 'diff', args.name], text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as error:
                diff = ''
                records[0]['note'] = note + '; docker diff failed: ' + type(error).__name__
            for line in diff.splitlines():
                if not line.strip():
                    continue
                kind, _, path = line.partition(' ')
                records.append({'kind': 'docker_diff', 'change': {'A': 'added', 'C': 'modified', 'D': 'deleted'}.get(kind, kind), 'path': path, 'container': args.name, 'phase': args.phase, 'confidence': 'correlated', 'basis': 'docker diff path only; no hash'})
            write_jsonl(args.out, records)
            print(json.dumps({'records': len(records), 'out': args.out, 'driver': driver}))
            return
    if not upper:
        raise SystemExit('pass --upper or --docker')
    records = scan_upper(upper, args.name, args.phase, driver, mounts)
    if args.baseline:
        records = diff_snapshots(load_jsonl(args.baseline), records)
    write_jsonl(args.out, records)
    print(json.dumps({'records': len(records), 'out': args.out, 'blindSpots': [BLIND]}))


if __name__ == '__main__':
    main()
