"""Persist explicit read denials across batches within one caller-verified account scope.

This stores conversation identifiers and denial metadata only. It does not store
message contents, credentials, or keys, and never attempts a policy reset.
"""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

CONFIDENTIAL_GROUP_DENIAL = 'policy_restricted_confidential_group'


class ReadPolicyStore:
    def __init__(self, path, scope):
        if not isinstance(scope, str) or not scope.strip() or scope.strip() != scope or scope == 'output-local':
            raise ValueError('A verified account scope is required for the shared read-policy store')
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables:
                self.db.execute('CREATE TABLE policy_scope(scope TEXT NOT NULL)')
                self.db.execute('INSERT INTO policy_scope VALUES(?)', (scope,))
                self.db.execute('CREATE TABLE read_denials(cid TEXT PRIMARY KEY, reason TEXT NOT NULL, recorded_utc TEXT NOT NULL)')
                self.db.execute('PRAGMA user_version=1')
            elif tables != {'policy_scope', 'read_denials'} or self.db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise ValueError('Unknown read-policy store schema; no message reads attempted')
            if self.db.execute('SELECT scope FROM policy_scope').fetchall() != [(scope,)]:
                raise ValueError('Read-policy store belongs to another account scope')
            self.db.commit()
        except Exception:
            self.db.rollback()
            self.db.close()
            raise

    def get(self, cid):
        row = self.db.execute('SELECT reason FROM read_denials WHERE cid=?', (cid,)).fetchone()
        if row and row[0] != CONFIDENTIAL_GROUP_DENIAL:
            raise ValueError('Unknown stored read policy; no retry permitted')
        return row[0] if row else None

    def remember(self, cid, reason):
        if not isinstance(cid, str) or not cid or reason != CONFIDENTIAL_GROUP_DENIAL:
            raise ValueError('Only an explicit supported read denial can be persisted')
        with self.db:
            self.db.execute('INSERT INTO read_denials VALUES(?,?,?) ON CONFLICT(cid) DO NOTHING',
                            (cid, reason, datetime.now(timezone.utc).isoformat(timespec='seconds')))

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
