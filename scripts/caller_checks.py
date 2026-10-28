"""Offline caller contracts. No DWS calls or business state writes on import."""
import json
from message_pipeline import cipher_of, plaintext


def mode_config(client='auto', local_crypto='auto'):
    if client not in ('auto', 'off') or local_crypto not in ('auto', 'off'):
        raise ValueError('unsupported caller mode')
    return {'server': 'off', 'client': client,
            'localCrypto': 'off' if client == 'off' else local_crypto}


def mode_args(mode):
    if mode != mode_config(mode.get('client'), mode.get('localCrypto')):
        raise ValueError('invalid mode configuration')
    return ['--server', mode['server'], '--known-policy-disabled',
            '--client', mode['client'], '--local-crypto', mode['localCrypto']]


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()
            if line.strip()]


def originals(records):
    rows = []
    for record in records:
        row = record.get('original') if isinstance(record, dict) else None
        if (not isinstance(row, dict) or 'resolution' in row or 'original' in row
                or not (row.get('openMessageId') or row.get('messageId'))
                or not (row.get('openConversationId') or row.get('conversationId'))):
            raise ValueError('invalid original record; no payload logged')
        rows.append(row)
    if not rows:
        raise ValueError('zero raw input rows')
    return rows


def write_rows(path, rows):
    # Never overwrite old samples or evidence.
    with path.open('x', encoding='utf-8') as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + '\n')


def encrypted(value):
    return bool(cipher_of(value))


def readable(text):
    return plaintext(text)


def validate_result(result_dir, returncode, expected, kind=None):
    """Require nonempty, bound records; smoke additionally proves local recovery."""
    if returncode != 0:
        raise ValueError('reader exit was not zero')
    summary = json.loads((result_dir / 'summary.json').read_text(encoding='utf-8'))
    count = (summary.get('counts') or {}).get('input_rows')
    if type(count) is not int or count <= 0 or count != len(expected):
        raise ValueError('input_rows missing, zero, or mismatched')
    if (summary.get('status') != 'complete_for_supplied_records'
            or summary.get('resolution_complete_for_supplied_records') is not True
            or type(summary.get('unresolved_items')) is not int
            or summary['unresolved_items'] != 0):
        raise ValueError('supplied records not complete')
    local = summary.get('local_crypto')
    if not isinstance(local, dict) or 'stop_reason' not in local or local['stop_reason'] is not None:
        raise ValueError('local stop_reason missing or not clear')
    records = read_rows(result_dir / 'resolved.jsonl')
    actual = originals(records)
    canonical = lambda rows: {json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows}
    if canonical(actual) != canonical(expected):
        raise ValueError('original records differ, including parent/quote binding')
    if kind is not None:
        if kind not in ('body', 'quote') or len(expected) != 1 or len(records) != 1:
            raise ValueError('smoke requires one exact target')
        field = 'body' if kind == 'body' else 'quoted_message'
        target = expected[0] if kind == 'body' else expected[0].get('quotedMessage', {})
        if not encrypted(target.get('content') or target.get('text')):
            raise ValueError('smoke target is not an encrypted source')
        if kind == 'quote' and not (target.get('openMessageId') or target.get('messageId')):
            raise ValueError('quote identity missing')
        resolution = (records[0].get('resolution') or {}).get(field) or {}
        if (resolution.get('status') != 'decrypted_local'
                or resolution.get('crypto_decryption_proven') is not True
                or not readable(resolution.get('text'))):
            raise ValueError('smoke target not recovered locally')
    return summary
