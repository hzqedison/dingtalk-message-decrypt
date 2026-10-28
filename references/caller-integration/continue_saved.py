# Sanitized migration example; configure paths, scope and window before use.
# Import shared checks from this same skill installation, never a stale local copy.
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / 'scripts'))
import json
import subprocess
import tempfile
from pathlib import Path
from caller_checks import (mode_config, mode_args, read_rows, originals,
                           write_rows, encrypted, validate_result)

B=Path(r'D:/REDACTED_PROJECT');O=B/'cache/heartbeat-20261029-full';R=O/'raw-fetch';S=Path(__file__).resolve().parents[2]/'scripts'/'dws_decrypt.py';P=Path(sys.executable);SC='dws-auth-REDACTED'


def run_reader(source, result, expected, kind=None):
    mode = mode_config()
    cmd = [str(P), str(S), '--input', str(source), '--out', str(result),
           '--scope', SC, *mode_args(mode)]
    process = subprocess.run(cmd, cwd=B, capture_output=True, text=True, encoding='utf-8')
    # Child output can contain content; persist locally, never print it.
    result.parent.joinpath(result.name+'.stdout.txt').write_text(process.stdout, encoding='utf-8')
    result.parent.joinpath(result.name+'.stderr.txt').write_text(process.stderr, encoding='utf-8')
    result.parent.joinpath(result.name+'.invocation.json').write_text(
        json.dumps({'mode': mode, 'exitCode': process.returncode}), encoding='utf-8')
    return validate_result(result, process.returncode, expected, kind)


def main():
    rows = originals(read_rows(R/'resolved.jsonl'))
    body = next((r for r in rows if encrypted(r.get('content') or r.get('text'))), None)
    quote = next((r for r in rows if isinstance(r.get('quotedMessage'), dict)
                  and encrypted(r['quotedMessage'].get('content') or r['quotedMessage'].get('text'))
                  and (r['quotedMessage'].get('openMessageId') or r['quotedMessage'].get('messageId'))), None)
    if body is None or quote is None:
        raise ValueError('required body/quote smoke target missing')
    # Fresh directory: no old smoke, cache, pipeline or business state is overwritten.
    work = Path(tempfile.mkdtemp(prefix='caller-check-', dir=O))
    for label, row in [('body', body), ('quote', quote)]:
        source = work/(label+'.jsonl')
        write_rows(source, [row])
        run_reader(source, work/label, [row], label)
    # Explicitly unwrap only originals into a separate raw input, after BOTH pass.
    source = work/'original-input.jsonl'
    write_rows(source, rows)
    run_reader(source, work/'pipeline', rows)
    print(json.dumps({'output': str(work), 'suppliedRecordsValidated': True,
                      'businessComplete': False}))


if __name__ == '__main__':
    main()
