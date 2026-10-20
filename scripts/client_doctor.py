"""Print a shareable disk-only compatibility receipt; no messages or keys."""
import argparse
import hashlib
import json
from pathlib import Path

from client_compatibility import assess_fingerprint


def inspect_dll(path):
    digest = hashlib.sha256()
    try:
        with Path(path).open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
    except OSError:
        return {'status': 'unavailable', 'reason': 'dll_file_unreadable',
                'validation_stage': 'disk_fingerprint',
                'runtime_validation_performed': False,
                'key_lookup_attempted': False, 'key_availability': 'not_assessed'}
    return assess_fingerprint(digest.hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dll', required=True, help='Actual MainFrame.dll path')
    args = parser.parse_args()
    result = inspect_dll(args.dll)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['status'] == 'recognized' else 2


if __name__ == '__main__':
    raise SystemExit(main())
