import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("dws_fetch", Path(__file__).parents[1] / "scripts" / "dws_fetch.py")
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)
LO, HI = "2026-10-13 00:00:00", "2026-10-15 23:59:59"


def message(mid="m1", timestamp="2026-10-14 12:00:00", cid="c1", **extra):
    return dict(messageId=mid, conversationId=cid, createTime=timestamp, text="[加密消息，无法解码]", content="fixture cipher", **extra)


def page(messages, more=False, time=None):
    obj = {"messages": messages, "hasMore": more}
    if time:
        obj["nextPage"] = {"time": time}
    return obj


class Runner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, cmd, timeout=120, cwd=None):
        self.calls.append(cmd)
        if not self.responses:
            raise AssertionError("unexpected command")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        if isinstance(response, tuple):
            return response
        return 0, json.dumps(response), ""


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test_dws_fetch_")
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_fetch(self, responses, **kwargs):
        runner = Runner(responses)
        args = dict(out_dir=self.root, start=LO, end=HI, conversation_ids=["c1"], runner=runner)
        args.update(kwargs)
        path, report = fetch.fetch_snapshot(**args)
        return json.loads(path.read_text(encoding="utf-8")), report, runner

    def test_raw_cipher_preserved_not_decrypted(self):
        original = message()
        data, report, runner = self.run_fetch([page([original])])
        self.assertTrue(report["complete"])
        self.assertFalse(report["readability_assessed"])
        self.assertEqual(data["messages"], [original])
        self.assertNotIn("--max-items", runner.calls[0])

    def test_confidential_group_denial_is_explicit_and_resume_does_not_retry(self):
        denial = json.dumps({'error':{'server_error_code':'1001',
                            'message':'该群为保密群，无法获取消息记录'}})
        _, report, runner = self.run_fetch([(1, '', denial)])
        self.assertFalse(report['complete'])
        self.assertEqual(report['errors'][0]['reason'], fetch.CONFIDENTIAL_GROUP_DENIAL)
        _, resumed, runner = self.run_fetch([], resume=True)
        self.assertEqual(runner.calls, [])
        self.assertEqual(resumed['errors'][0]['reason'], fetch.CONFIDENTIAL_GROUP_DENIAL)

    def test_generic_business_error_is_not_mislabeled_as_policy(self):
        _, report, _ = self.run_fetch([(1, '', json.dumps({'error':{
            'server_error_code':'1001','message':'invalid argument'}}))])
        self.assertEqual(report['errors'][0]['reason'], 'command_failed')

    def test_strict_inclusive_time_filter(self):
        data, report, _ = self.run_fetch([page([message("a", LO), message("b", HI), message("before", "2026-10-12 23:59:59"), message("after", "2026-10-16 00:00:00")])])
        self.assertEqual([m["messageId"] for m in data["messages"]], ["a", "b"])
        self.assertEqual(report["out_of_window_records"], 2)
        raw = Path(report["conversations"][0]["raw_file"])
        self.assertEqual(len(json.loads(raw.read_text())["response"]["messages"]), 4)

    def test_no_progress_is_partial(self):
        _, report, _ = self.run_fetch([page([message()], True, LO)])
        self.assertFalse(report["complete"])
        self.assertEqual(report["conversations"][0]["stop_reason"], "pagination_no_progress")

    def test_opaque_cursor_not_sent_as_time(self):
        obj = page([message()], True)
        obj["nextPage"] = {"nextCursor": "opaque token"}
        _, report, runner = self.run_fetch([obj])
        self.assertFalse(report["complete"])
        self.assertEqual(len(runner.calls), 1)

    def test_missing_has_more_is_partial(self):
        _, report, _ = self.run_fetch([{"messages": [message()]}])
        self.assertFalse(report["complete"])

    def test_nested_pagination(self):
        data, report, runner = self.run_fetch([{"result": page([message()], True, "2026-10-14 12:00:00")}, {"result": page([message("m2")])}])
        self.assertTrue(report["complete"])
        self.assertEqual(len(data["messages"]), 2)
        self.assertEqual(runner.calls[1][runner.calls[1].index("--time") + 1], "2026-10-14 12:00:00")

    def test_resume_fixed_window_and_no_duplicate(self):
        _, report, _ = self.run_fetch([page([message()], True, "2026-10-14 12:00:00")], max_pages=1)
        self.assertFalse(report["complete"])
        data, report, runner = self.run_fetch([page([message(), message("m2")])], start=None, end=None, resume=True)
        self.assertTrue(report["complete"])
        self.assertEqual(len(data["messages"]), 2)
        self.assertEqual(report["duplicate_records"], 1)
        self.assertEqual(runner.calls[0][runner.calls[0].index("--time")+1], "2026-10-14 12:00:00")

    def test_resume_window_mismatch_no_command(self):
        self.run_fetch([page([message()])])
        runner = Runner([])
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            fetch.fetch_snapshot(self.root, "2026-10-01 00:00:00", HI, resume=True, runner=runner)
        self.assertEqual(runner.calls, [])

    def test_interrupted_checkpoint_recovered_from_raw(self):
        real_write = fetch._write
        def crash(path, value):
            if path.name.startswith("fetch-state-"):
                raise KeyboardInterrupt()
            real_write(path, value)
        with patch.object(fetch, "_write", crash):
            with self.assertRaises(KeyboardInterrupt):
                self.run_fetch([page([message()], True, "2026-10-14 12:00:00")])
        data, report, _ = self.run_fetch([page([message("m2")])], resume=True)
        self.assertTrue(report["complete"])
        self.assertEqual(len(data["messages"]), 2)

    def test_conflict_not_last_row_wins(self):
        other = message()
        other["content"] = "different cipher"
        data, report, _ = self.run_fetch([page([message(), other])])
        self.assertFalse(report["complete"])
        self.assertEqual(data["messages"], [])
        self.assertEqual(report["conflicting_message_count"], 1)

    def test_corrupt_raw_stops_no_append(self):
        _, report, _ = self.run_fetch([page([message()], True, "2026-10-14 12:00:00")], max_pages=1)
        raw = Path(report["conversations"][0]["raw_file"])
        with raw.open("a") as stream:
            stream.write('{"broken":')
        before = raw.read_bytes()
        _, report, runner = self.run_fetch([], resume=True)
        self.assertFalse(report["complete"])
        self.assertEqual(runner.calls, [])
        self.assertEqual(raw.read_bytes(), before)

    def test_command_error_report(self):
        _, report, _ = self.run_fetch([(1, "", "failure")])
        self.assertFalse(report["complete"])
        self.assertEqual(report["errors"][0]["reason"], "command_failed")

    def test_business_error_with_zero_exit_is_partial(self):
        obj = page([message()])
        obj["ok"] = False
        _, report, _ = self.run_fetch([obj])
        self.assertFalse(report["complete"])
        self.assertEqual(report["errors"][0]["reason"], "business_error")

    def test_truncated_flag_overrules_has_more_false(self):
        obj = page([message()])
        obj["truncatedByPageLimit"] = True
        _, report, _ = self.run_fetch([obj])
        self.assertFalse(report["complete"])

    def test_ambiguous_json_rejected(self):
        _, report, _ = self.run_fetch([(0, '{"messages":[],"hasMore":true,"hasMore":false}', "")])
        self.assertFalse(report["complete"])

    def test_nan_json_rejected(self):
        _, report, _ = self.run_fetch([(0, '{"messages":[],"hasMore":false,"x":NaN}', "")])
        self.assertFalse(report["complete"])

    def test_decrypt_partial_does_not_mean_fetch_partial(self):
        obj = page([message()])
        obj.update(partial=True, decryptFailedCount=1, failedCount=0)
        _, report, _ = self.run_fetch([obj])
        self.assertTrue(report["complete"])

    def test_discovery_zero_new_continues_cursor(self):
        def conv(items, token, done=False):
            return {"data": {"succeeded": [{"conversations": items}]}, "meta": {"pagination": {"next_token": token, "endpoint_exhausted": done}}}
        c = {"conversationId": "c1", "type": "group", "name": "钉钉文档自动化助手"}
        _, report, runner = self.run_fetch([conv([c], "a"), conv([c], "b"), conv([], None, True), page([message()])], conversation_ids=None)
        self.assertTrue(report["complete"])
        self.assertEqual(report["conversation_count"], 1)
        self.assertEqual(len(runner.calls), 4)
        self.assertEqual(runner.calls[2][-1], "b")

    def test_normal_success_envelope_discovers_messages_not_false_empty_complete(self):
        response = {"ok":True, "outcome":"success", "data":{"complete":True,
            "conversations":[{"conversationId":"c1","type":"group","name":"fixture group"}], "count":1},
            "meta":{"pagination":{"endpoint_exhausted":True}}}
        data, report, runner = self.run_fetch([response,page([message()])],conversation_ids=None)
        self.assertTrue(report['complete'])
        self.assertEqual(report['conversation_count'],1)
        self.assertEqual(len(data['messages']),1)
        self.assertEqual(data['messages'][0]['conversationTitle'],'fixture group')
        self.assertIs(data['messages'][0]['singleChat'],False)
        self.assertEqual(len(runner.calls),2)

    def test_unknown_success_shape_is_not_zero_complete(self):
        response = {"ok":True,"data":{"count":1},"meta":{"pagination":{"endpoint_exhausted":True}}}
        _, report, _ = self.run_fetch([response],conversation_ids=None)
        self.assertFalse(report['complete'])
        self.assertEqual(report['errors'][0]['reason'],'invalid_response_shape')

    def test_explicit_incomplete_discovery_overrules_exhausted_metadata(self):
        response = {"data":{"complete":False,"conversations":[]},
                    "meta":{"pagination":{"endpoint_exhausted":True}}}
        _, report, _ = self.run_fetch([response],conversation_ids=None)
        self.assertFalse(report['complete'])

    def test_normal_success_pages_continue_and_preserve_kind_filter(self):
        first = {"data":{"complete":False,"conversations":[{"conversationId":"direct1","type":"direct"}]},
                 "meta":{"pagination":{"endpoint_exhausted":False,"next_token":"next"}}}
        second = {"data":{"complete":True,"conversations":[{"conversationId":"c1","type":"group"}]},
                  "meta":{"pagination":{"endpoint_exhausted":True}}}
        data, report, runner = self.run_fetch([first,second,page([message()])],conversation_ids=None,kind='group')
        self.assertTrue(report['complete'])
        self.assertEqual(report['conversation_count'],1)
        self.assertEqual(len(data['messages']),1)
        self.assertEqual(len(runner.calls),3)

    def test_discovery_stall_partial(self):
        response = {"data": {"succeeded": []}, "meta": {"pagination": {"endpoint_exhausted": False}}}
        _, report, _ = self.run_fetch([response], conversation_ids=None)
        self.assertFalse(report["complete"])

    def test_stable_cid_filename_and_resume_skip(self):
        _, report, _ = self.run_fetch([page([message()])])
        name = Path(report["conversations"][0]["raw_file"]).name
        self.assertEqual(name, "fetch-" + fetch.hashlib.sha256(b"c1").hexdigest() + ".jsonl")
        _, report, runner = self.run_fetch([], resume=True)
        self.assertTrue(report["complete"])
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
