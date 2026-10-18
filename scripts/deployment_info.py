"""Record deployment provenance and check bundled files without a deployed .git."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def file_hashes(root):
    root = Path(root)
    paths = [root / name for name in ('SKILL.md', 'README.md', 'LICENSE')]
    for name in ('scripts', 'references'):
        paths.extend(path for path in (root / name).rglob('*')
                     if path.is_file() and path.suffix in ('.py', '.md')
                     and '__pycache__' not in path.relative_to(root).parts
                     and path.relative_to(root).parts[:2] != ('scripts', 'legacy'))
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths) if path.is_file()}


def source_revision(root):
    if not (Path(root) / '.git').exists():
        return None, None
    try:
        def git(*args):
            return subprocess.run(['git', '-C', str(root), *args], check=True,
                                  capture_output=True, text=True, timeout=15).stdout.strip()
        return git('rev-parse', 'HEAD'), bool(git('status', '--porcelain'))
    except (OSError, subprocess.SubprocessError):
        return None, None


def write_manifest(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    expected = file_hashes(source)
    if not all(name in expected for name in ('SKILL.md', 'README.md', 'LICENSE')):
        raise ValueError('Incomplete source skill')
    actual = file_hashes(destination)
    if any(actual.get(name) != digest for name, digest in expected.items()):
        raise ValueError('Deployment files do not match source')
    commit, dirty = source_revision(source)
    manifest = {'schema_version':1, 'source_commit':commit, 'source_dirty':dirty,
                'files_sha256':expected}
    (destination / 'deployment.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return check_deployment(destination)


def check_deployment(root):
    root = Path(root).resolve()
    path = root / 'deployment.json'
    if not path.exists():
        return {'status':'provenance_unavailable', 'skill_directory':str(root)}
    manifest = json.loads(path.read_text(encoding='utf-8'))
    expected = manifest['files_sha256']
    actual = file_hashes(root)
    changed = sorted(name for name in set(expected) | set(actual)
                     if expected.get(name) != actual.get(name))
    return {'status':'matches_deployment' if not changed else 'deployment_changed',
            'skill_directory':str(root), 'source_commit':manifest['source_commit'],
            'source_dirty':manifest['source_dirty'], 'changed_files':changed,
            'limitation':'Local provenance is not a signature or proof of latest upstream version.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--destination', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        report = (write_manifest(args.source, args.destination) if args.source
                  else check_deployment(args.destination))
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'status':'deployment_check_failed'}))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'matches_deployment' else 2


if __name__ == '__main__':
    raise SystemExit(main())
