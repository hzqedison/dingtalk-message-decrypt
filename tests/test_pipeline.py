"""Offline behavioral tests: no real chat data and no real DWS invocation."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("message_pipeline_test_target", Path(__file__).parents[1] / "scripts" / "message_pipeline.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)


def cipher(seed="cipher-one"):
    return base64.b64encode(seed.encode()).decode() + "||2||1||128"


def message(mid="m1", cid="c1", content=None, **extra):
    result = {"messageId": mid, "conversationId": cid, "createTime": "2026-10-14 12:00:00",
              "sender": "fixture sender", "content": cipher() if content is None else content}
    result.update(extra)
    return result


def evidence(mid="m1", cid="c1", body="observed fixture", encrypted=None, **extra):
    row = {"evidence_type": "native_message_double_read", "text": body, "text_sha256": p.sha(body),
           "api_message_id": mid, "api_conversation_id": cid, "cipher_sha256": p.sha(encrypted or cipher()),
           "recall_metadata_checked": True, "recalled": False, "source_capture": "fixture.capture"}
    row.update(extra)
    return row


class FakeRunner:
    def __init__(self, responses=(), version="dws v1.0.64"):
        self.responses = list(responses)
        self.version = version
        self.calls = []

    def __call__(self, cmd, timeout=90, cwd=None):
        self.calls.append((cmd, cwd))
        if cmd == ["dws", "version"]:
            return 0, self.version, ""
        if not self.responses:
            raise AssertionError("Unexpected DWS command in offline test")
        response = self.responses.pop(0)
        return response if isinstance(response, tuple) else (0, json.dumps(response), "")

    @property
    def decrypt_calls(self):
        return [(cmd, cwd) for cmd, cwd in self.calls if "decrypt" in cmd]


class FakeLocal:
    def __init__(self):
        self.calls = []

    def resolve(self, row, cid, mid, encrypted):
        identity = p.message_identity(row)
        self.calls.append((cid, mid, identity))
        corp = identity.get('corpId', 'ding' + identity.get('oid', 'group'))
        return {'status':'decrypted_local', 'text':'fixture ' + corp, 'crypto_decryption_proven':True,
                'enterprise':corp, 'key_version':7, 'crypto_type':1,
                'identity_source':'message_oid_to_client_enterprise' if 'oid' in identity else 'group_conversation_info_corp_id',
                'client_dll_sha256':'fixture-dll', 'plaintext_validation':'strict_pkcs7_and_utf8',
                'independent_body_comparison':False}

    def summary(self):
        return {'calls':len(self.calls)}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test_dws_pipeline_")
        self.root = Path(self.tmp.name)
        self.source = self.root / "input.json"
        self.output = self.root / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def run_batch(self, rows, responses=(), client=(), runner=None, **options):
        self.source.write_text(json.dumps({"messages": rows}), encoding="utf-8")
        indexes = []
        if client:
            path = self.root / "client.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in client), encoding="utf-8")
            indexes.append(path)
        runner = runner or FakeRunner(responses)
        report = p.resolve_batch([self.source], self.output, scope=options.pop("scope", "fixture-account"),
                                 client_indexes=indexes, runner=runner, **options)
        def read(name):
            return [json.loads(line) for line in (self.output / name).read_text(encoding="utf-8").splitlines()]
        return report, read("messages.jsonl"), read("resolved.jsonl"), read("unresolved.jsonl"), runner

    def test_cipher_without_placeholder_is_processed(self):
        original = message(text=None)
        report, readable, resolved, _, runner = self.run_batch([original], [{"ok": True, "plaintext": "decrypted fixture"}])
        self.assertEqual(report["decrypt_calls"], 1)
        self.assertEqual(readable[0]["text"], "decrypted fixture")
        self.assertEqual(resolved[0]["original"], original)
        command, cwd = runner.decrypt_calls[0]
        self.assertEqual(command[command.index("--layer") + 1], "full")
        self.assertFalse(Path(command[command.index("--file") + 1]).is_absolute())
        self.assertTrue(Path(cwd).is_absolute())

    def test_shared_cipher_fans_out_to_every_message(self):
        report, readable, _, _, runner = self.run_batch([message("a"), message("b")], [{"ok": True, "plaintext": "shared fixture"}])
        self.assertEqual(report["decrypt_calls"], 1)
        self.assertEqual(len(runner.decrypt_calls), 1)
        self.assertEqual({row["message_id"] for row in readable}, {"a", "b"})

    def test_cipher_same_across_cids_not_reused(self):
        report, readable, _, _, _ = self.run_batch([message("a", "c1"), message("b", "c2")],
                                                  [{"ok": True, "plaintext": "first fixture"}, {"ok": True, "plaintext": "second fixture"}])
        self.assertEqual(report["decrypt_calls"], 2)
        self.assertEqual({r["text"] for r in readable}, {"first fixture", "second fixture"})

    def test_quote_resolves_without_replacing_parent_body(self):
        quote = {"openMessageId": "original", "content": cipher(), "createTime": "2026-10-13 10:00:00"}
        parent = message("reply", content="reply fixture", quotedMessage=quote)
        report, readable, resolved, _, _ = self.run_batch([message("original"), parent], [{"ok": True, "plaintext": "original fixture"}])
        self.assertEqual(report["decrypt_calls"], 1)
        self.assertEqual(report["counts"]["readable_messages"], 2)
        row = next(r for r in resolved if r["original"]["messageId"] == "reply")
        self.assertEqual(row["resolution"]["body"]["text"], "reply fixture")
        self.assertEqual(row["resolution"]["quoted_message"]["text"], "original fixture")

    def test_body_cached_still_processes_quote(self):
        self.run_batch([message()], [{"ok": True, "plaintext": "body fixture"}])
        row = message(quotedMessage={"openMessageId": "quote-id", "content": cipher("another")})
        report, _, resolved, _, runner = self.run_batch([row], [{"ok": True, "plaintext": "quote fixture"}])
        self.assertEqual(report["decrypt_calls"], 1)
        self.assertEqual(resolved[0]["resolution"]["quoted_message"]["text"], "quote fixture")
        self.assertEqual(len(runner.decrypt_calls), 1)

    def test_policy_disabled_breaks_once_and_persists(self):
        rows = [message("a"), message("b", content=cipher("two"))]
        report, readable, _, _, runner = self.run_batch(rows, [(1, json.dumps({"code": "CRYPTO_DISABLED"}), "")])
        self.assertEqual(len(runner.decrypt_calls), 1)
        self.assertEqual(report["server_stop_reason"], "CRYPTO_DISABLED")
        self.assertEqual(readable, [])
        report, _, _, _, runner = self.run_batch(rows)
        self.assertEqual(runner.calls, [])
        self.assertEqual(report["decrypt_calls"], 0)

    def test_retry_is_explicit_and_can_clear_policy(self):
        self.run_batch([message()], [(1, "CRYPTO_DISABLED", "")])
        report, readable, _, _, runner = self.run_batch([message()], [{"ok": True, "plaintext": "retry fixture"}], server="retry")
        self.assertEqual(report["decrypt_calls"], 1)
        self.assertEqual(readable[0]["text"], "retry fixture")

    def test_envelope_is_unresolved_not_cached(self):
        report, readable, _, unresolved, _ = self.run_batch([message()], [{"ok": True, "plaintext": "1_1_abcdef012345"}])
        self.assertEqual(readable, [])
        self.assertEqual(report["status"], "partial")
        self.assertEqual(unresolved[0]["reason"], "intermediate_envelope")
        _, readable, _, _, _ = self.run_batch([message()], [{"ok": True, "plaintext": "real fixture"}])
        self.assertEqual(readable[0]["text"], "real fixture")

    def test_nonzero_exit_with_ok_true_is_not_plaintext(self):
        _, readable, _, _, _ = self.run_batch([message()], [(1, json.dumps({"ok": True, "plaintext": "false success"}), "")])
        self.assertEqual(readable, [])

    def test_unknown_version_prevents_decrypt(self):
        runner = FakeRunner(version="version unknown")
        report, readable, _, _, _ = self.run_batch([message()], runner=runner)
        self.assertEqual(readable, [])
        self.assertEqual(runner.decrypt_calls, [])
        self.assertEqual(report["server_stop_reason"], "unsupported_or_unknown_dws_version")

    def test_client_index_exact_identity_works_without_server(self):
        report, readable, _, _, runner = self.run_batch([message()], client=[evidence()], server="off")
        self.assertEqual(runner.calls, [])
        self.assertEqual(readable[0]["source"], "client_observed")
        self.assertFalse(readable[0]["crypto_decryption_proven"])
        self.assertEqual(report["decrypt_calls"], 0)

    def test_client_index_rejects_identity_hash_and_recall_mismatches(self):
        variants = [evidence(mid="wrong-id"), evidence(cid="wrong-cid"), evidence(encrypted=cipher("wrong")),
                    evidence(text_sha256="0" * 64), evidence(recalled=True), evidence(recall_metadata_checked=False),
                    evidence(evidence_type="unverified_candidate")]
        for row in variants:
            with self.subTest(row=row):
                _, readable, _, _, _ = self.run_batch([message()], client=[row], server="off")
                self.assertEqual(readable, [])

    def test_client_conflicts_do_not_fall_back_to_guess(self):
        report, readable, _, unresolved, runner = self.run_batch([message()], client=[evidence(), evidence(body="other fixture")])
        self.assertEqual(readable, [])
        self.assertEqual(runner.calls, [])
        self.assertEqual(unresolved[0]["reason"], "conflicting_client_evidence")

    def test_client_evidence_does_not_fan_out_to_different_message_id(self):
        _, readable, _, unresolved, _ = self.run_batch([message("m1"), message("m2")], client=[evidence()], server="off")
        self.assertEqual([row["message_id"] for row in readable], ["m1"])
        self.assertTrue(any(row["message_id"] == "m2" for row in unresolved))

    def test_client_observation_never_becomes_cryptographic_cache(self):
        self.run_batch([message()], client=[evidence()], server="off")
        _, readable, _, _, runner = self.run_batch([message()], server="off")
        self.assertEqual(readable, [])
        self.assertEqual(runner.calls, [])

    def test_decrypt_limit_preserves_remaining_as_unresolved(self):
        report, readable, _, unresolved, runner = self.run_batch([message("a"), message("b", content=cipher("second"))],
                                                                 [{"ok": True, "plaintext": "first fixture"}], decrypt_limit=1)
        self.assertEqual(len(runner.decrypt_calls), 1)
        self.assertEqual(len(readable), 1)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any(row["reason"] == "decrypt_limit" for row in unresolved))

    def test_exact_duplicates_count_once(self):
        row = message(content="plain fixture")
        report, readable, _, _, _ = self.run_batch([row, row], server="off")
        self.assertEqual(len(readable), 1)
        self.assertEqual(report["counts"]["duplicate_rows"], 1)

    def test_differing_body_versions_are_withheld(self):
        report, readable, _, unresolved, runner = self.run_batch([message(content="first fixture"), message(content="second fixture")])
        self.assertEqual(readable, [])
        self.assertEqual(report["counts"]["conflicting_messages"], 1)
        self.assertEqual(unresolved[0]["reason"], "duplicate_variants")
        self.assertEqual(runner.calls, [])

    def test_differing_timestamp_versions_are_withheld(self):
        rows = [message(content="fixture"), message(content="fixture", createTime="2026-10-15 12:00:00")]
        report, readable, _, _, _ = self.run_batch(rows, server="off")
        self.assertEqual(readable, [])
        self.assertEqual(report["counts"]["conflicting_messages"], 1)

    def test_missing_identity_is_counted_incomplete(self):
        row = message(content="plain fixture")
        del row["conversationId"]
        report, readable, _, _, _ = self.run_batch([row], server="off")
        self.assertEqual(readable, [])
        self.assertEqual(report["counts"]["unidentified_rows"], 1)
        self.assertEqual(report["status"], "partial")

    def test_quoted_reference_without_identity_is_not_invented(self):
        report, readable, _, unresolved, runner = self.run_batch([message(content="parent fixture", quotedMessage={"content": cipher()})], server="off")
        self.assertEqual(len(readable), 1)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(unresolved[0]["reason"], "missing_quote_identity")
        self.assertEqual(runner.calls, [])

    def test_fetch_partial_kept_even_when_all_supplied_bodies_readable(self):
        report, readable, _, _, _ = self.run_batch([message(content="plain fixture")], server="off", fetch_report={"complete": False, "reason": "max_pages"})
        self.assertEqual(len(readable), 1)
        self.assertTrue(report["resolution_complete_for_supplied_records"])
        self.assertEqual(report["status"], "partial")

    def test_empty_structured_body_not_counted_as_readable(self):
        row = message(content={"mediaId": "fixture-media"}, text=None)
        report, readable, resolved, _, _ = self.run_batch([row], server="off")
        self.assertEqual(readable, [])
        self.assertEqual(report["counts"]["readable_messages"], 0)
        self.assertEqual(resolved[0]["original"], row)

    def test_output_scope_cannot_be_reused_by_another_account(self):
        self.run_batch([message(content="plain fixture")], server="off")
        with self.assertRaises(ValueError):
            self.run_batch([message()], scope="other-account", server="off")

    def test_successful_plaintext_can_discuss_crypto_disabled(self):
        text = "The CRYPTO_DISABLED error was fixed yesterday."
        report, readable, _, _, _ = self.run_batch([message()], [{"ok": True, "plaintext": text}])
        self.assertEqual([row["text"] for row in readable], [text])
        self.assertIsNone(report["server_stop_reason"])

    def test_local_same_cipher_different_enterprises_do_not_share_memo_or_cache(self):
        rows = [message('a', oid=11), message('b', oid=22), message('c', corpId='dingother')]
        local = FakeLocal()
        _, readable, _, _, _ = self.run_batch(rows, server='off', local_decryptor=local)
        self.assertEqual(len(local.calls), 3)
        self.assertEqual({r['text'] for r in readable}, {'fixture ding11','fixture ding22','fixture dingother'})
        _, replay, _, _, runner = self.run_batch(rows, server='off')
        self.assertEqual(runner.calls, [])
        self.assertEqual([r['text'] for r in replay], [r['text'] for r in readable])
        self.assertTrue(all(r['source'] == 'decrypted_local_cache' for r in replay))
        self.assertTrue(all(r['key_version'] == 7 and r['source_resolution_status'] == 'decrypted_local' for r in replay))
        self.assertEqual(replay[0]['input_identity'], {'oid':'11'})
        cache = p.Cache(self.output/'resolution_cache.sqlite3', 'fixture-account')
        try:
            self.assertEqual(cache.db.execute('SELECT count(*) FROM resolved').fetchone()[0], 0)
        finally:
            cache.close()

    def test_local_equal_identity_fans_out_and_survives_server_breaker(self):
        local = FakeLocal()
        rows = [message('a', oid=11), message('b', extension={'oid':'11'})]
        report, readable, _, _, runner = self.run_batch(rows, [(1,'CRYPTO_DISABLED','')], local_decryptor=local)
        self.assertEqual(len(runner.decrypt_calls), 1)
        self.assertEqual(len(local.calls), 1)
        self.assertEqual(len(readable), 2)
        self.assertEqual(report['server_stop_reason'], 'CRYPTO_DISABLED')
        _, replay, _, _, runner = self.run_batch(rows)
        self.assertEqual(len(replay), 2)
        self.assertEqual(runner.calls, [])

    def test_group_metadata_local_cache_replays_without_explicit_oid(self):
        self.run_batch([message()], server='off',local_decryptor=FakeLocal())
        _, readable, _, _, runner = self.run_batch([message()], server='off')
        self.assertEqual(readable[0]['source'], 'decrypted_local_cache')
        self.assertEqual(readable[0]['identity_source'], 'group_conversation_info_corp_id')
        self.assertEqual(runner.calls, [])

    def test_explicit_identity_never_reuses_unknown_legacy_cache(self):
        self.run_batch([message()], [{'ok':True,'plaintext':'legacy fixture'}])
        local = FakeLocal()
        _, readable, _, _, _ = self.run_batch([message(oid=11)], server='off', local_decryptor=local)
        self.assertEqual(readable[0]['text'], 'fixture ding11')
        self.assertEqual(len(local.calls), 1)

    def test_full_results_are_identity_scoped_but_old_full_cache_still_works(self):
        rows = [message('a', oid=11), message('b', oid=22)]
        _, readable, _, _, runner = self.run_batch(rows, [{'ok':True,'plaintext':'eleven'}, {'ok':True,'plaintext':'twenty two'}])
        self.assertEqual(len(runner.decrypt_calls), 2)
        _, replay, _, _, runner = self.run_batch(rows, server='off')
        self.assertEqual([r['text'] for r in replay], [r['text'] for r in readable])
        self.assertEqual(runner.calls, [])

    def test_local_cache_replay_259_bodies_without_client_or_runner(self):
        rows = [message(str(i), content=cipher(str(i)), oid=11 if i % 2 else 22) for i in range(259)]
        local = FakeLocal()
        _, first, _, _, _ = self.run_batch(rows, server='off', local_decryptor=local)
        def forbidden(*args, **kwargs):
            raise AssertionError('Offline replay must not access DWS or client')
        _, replay, _, _, _ = self.run_batch(rows, server='off', runner=forbidden)
        self.assertEqual(len(replay), 259)
        self.assertEqual([r['text'] for r in replay], [r['text'] for r in first])
        self.assertEqual([r['enterprise'] for r in replay], [r['enterprise'] for r in first])
        self.assertTrue(all(r['identity_source'] == 'message_oid_to_client_enterprise' for r in replay))

    def test_quote_same_id_cipher_with_conflicting_oid_is_withheld(self):
        rows = [message('original', oid=11), message('reply', content='reply', quotedMessage={
            'messageId':'original', 'content':cipher(), 'oid':22})]
        local = FakeLocal()
        _, _, resolved, unresolved, _ = self.run_batch(rows, server='off', local_decryptor=local)
        self.assertEqual(len(local.calls), 1)
        self.assertEqual(resolved[1]['resolution']['quoted_message']['reason'], 'conflicting_quote_crypto_identity')
        self.assertTrue(any(r.get('field') == 'quotedMessage' for r in unresolved))

    def test_quote_new_explicit_identity_cannot_inherit_unknown_body(self):
        rows = [message('original'), message('reply', content='reply', quotedMessage={
            'messageId':'original','content':cipher(),'oid':22})]
        local = FakeLocal()
        _, _, resolved, _, _ = self.run_batch(rows, server='off', local_decryptor=local)
        self.assertEqual(len(local.calls), 2)
        self.assertEqual(resolved[1]['resolution']['quoted_message']['enterprise'], 'ding22')

    def test_same_id_corp_variants_and_internal_oid_conflict_are_withheld(self):
        local = FakeLocal()
        report, readable, _, _, _ = self.run_batch([message(corpId='ding1'),message(corpId='ding2'),
            message('invalid',oid=1,extension={'oid':2})], server='off',local_decryptor=local)
        self.assertEqual(readable, [])
        self.assertEqual(report['counts']['conflicting_messages'], 1)
        self.assertEqual(local.calls, [])

    def test_local_enterprise_must_match_explicit_corp(self):
        class WrongLocal(FakeLocal):
            def resolve(self, *args):
                return {**super().resolve(*args), 'enterprise':'dingwrong'}
        _, readable, _, unresolved, _ = self.run_batch([message(corpId='dingright')],server='off',local_decryptor=WrongLocal())
        self.assertEqual(readable, [])
        self.assertEqual(unresolved[0]['local_reason'], 'invalid_local_result_or_identity')

    def test_local_cache_is_not_reused_for_different_cid_or_missing_oid(self):
        self.run_batch([message(oid=11)], server='off', local_decryptor=FakeLocal())
        _, readable, _, _, _ = self.run_batch([message('other','c2',oid=11),message('missing')], server='off')
        self.assertEqual(readable, [])

    def test_migration_requires_exact_identity_cipher_and_matching_legacy_text(self):
        row = message(oid=11)
        self.run_batch([row], server='off', local_decryptor=FakeLocal())
        cache = p.Cache(self.output/'resolution_cache.sqlite3', 'fixture-account')
        cache.db.execute('DELETE FROM resolved_identity')
        cache.put('c1', cipher(), 'fixture ding11')
        cache.close()
        report, readable, _, _, runner = self.run_batch([row], server='off')
        self.assertEqual(report['migrated_local_cache_entries'], 1)
        self.assertEqual(readable[0]['source'], 'decrypted_local_cache')
        self.assertEqual(readable[0]['enterprise'], 'ding11')
        self.assertEqual(runner.calls, [])

    def test_migration_rejects_text_mismatch_or_tampered_hash(self):
        for tamper_hash in (False, True):
            with self.subTest(tamper_hash=tamper_hash):
                row = message(oid=11)
                self.run_batch([row], server='off', local_decryptor=FakeLocal())
                cache = p.Cache(self.output/'resolution_cache.sqlite3', 'fixture-account')
                cache.db.execute('DELETE FROM resolved_identity')
                cache.db.execute('DELETE FROM resolved')
                cache.put('c1', cipher(), 'fixture ding11' if tamper_hash else 'different legacy text')
                cache.close()
                if tamper_hash:
                    path = self.output/'resolved.jsonl'
                    record = json.loads(path.read_text())
                    record['resolution']['body']['cipher_sha256'] = '0'*64
                    path.write_text(json.dumps(record)+'\n', encoding='utf-8')
                report, readable, _, _, _ = self.run_batch([row], server='off')
                self.assertEqual(report['migrated_local_cache_entries'], 0)
                self.assertEqual(readable, [])

    def test_migration_rejects_disagreeing_prior_local_records(self):
        rows = [message('a', oid=11),message('b', oid=11)]
        self.run_batch(rows, server='off',local_decryptor=FakeLocal())
        path = self.output/'resolved.jsonl'
        records = [json.loads(line) for line in path.read_text().splitlines()]
        records[1]['resolution']['body']['enterprise'] = 'dingdifferent'
        path.write_text(''.join(json.dumps(r)+'\n' for r in records), encoding='utf-8')
        cache = p.Cache(self.output/'resolution_cache.sqlite3', 'fixture-account')
        cache.db.execute('DELETE FROM resolved_identity')
        cache.put('c1',cipher(),'fixture ding11')
        cache.close()
        report, readable, _, _, _ = self.run_batch(rows,server='off')
        self.assertEqual(report['migrated_local_cache_entries'], 0)
        self.assertEqual(readable, [])


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test_dws_cache_")
        self.path = Path(self.tmp.name) / "cache.sqlite3"
        self.caches = []

    def tearDown(self):
        for cache in self.caches:
            cache.close()
        self.tmp.cleanup()

    def cache(self, scope="one"):
        cache = p.Cache(self.path, scope)
        self.caches.append(cache)
        return cache

    def test_scope_cid_and_cipher_are_bound(self):
        first = self.cache()
        first.put("c1", cipher(), "fixture plain")
        second = self.cache("two")
        self.assertIsNone(second.get("c1", cipher()))
        self.assertIsNone(first.get("c2", cipher()))
        self.assertIsNone(first.get("c1", cipher("other")))
        self.assertEqual(first.get("c1", cipher()), "fixture plain")

    def test_local_result_cache_binds_scope_cid_cipher_and_identity(self):
        cache = self.cache()
        identity = {'oid':'11'}
        local = FakeLocal().resolve(message(oid=11), 'c1','m1',cipher())
        cache.put_result('c1',cipher(),identity,local)
        self.assertIsNone(cache.get('c1',cipher()))
        self.assertIsNone(self.cache('other').get_result('c1',cipher(),identity))
        self.assertIsNone(cache.get_result('c2',cipher(),identity))
        self.assertIsNone(cache.get_result('c1',cipher('other'),identity))
        self.assertIsNone(cache.get_result('c1',cipher(),{'oid':'22'}))
        hit = cache.get_result('c1',cipher(),identity)
        self.assertEqual(hit['status'], 'decrypted_local_cache')
        self.assertEqual(hit['enterprise'], 'ding11')
        with self.assertRaises(ValueError):
            cache.put_result('c1',cipher(),identity,{**local,'key_version':8})

    def test_plaintext_conflicts_rejected(self):
        cache = self.cache()
        cache.put("c1", cipher(), "first fixture")
        with self.assertRaises(ValueError):
            cache.put("c1", cipher(), "second fixture")
        self.assertEqual(cache.get("c1", cipher()), "first fixture")

    def test_invalid_plaintext_rejected(self):
        cache = self.cache()
        for value in ["1_1_ab", "1_1_ABCDEF", "[加密消息，无法解码]", cipher(), "", "control\x00"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                cache.put("c1", cipher(), value)

    def test_policy_scope_isolation(self):
        first, second = self.cache(), self.cache("two")
        first.set_disabled("CRYPTO_DISABLED")
        self.assertIsNone(second.disabled())
        self.assertEqual(first.disabled(), "CRYPTO_DISABLED")

    def test_legacy_envelope_inserted_in_cache_is_not_returned(self):
        cache = self.cache()
        cache.db.execute("INSERT INTO resolved VALUES(?,?,?,?)", ("one", "c1", p.sha(cipher()), "1_1_abcdef012345"))
        cache.db.commit()
        self.assertIsNone(cache.get("c1", cipher()))


if __name__ == "__main__":
    unittest.main()
