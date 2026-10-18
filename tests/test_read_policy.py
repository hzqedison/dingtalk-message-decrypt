import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]/'scripts'))
import batch_cli
import dws_fetch
from read_policy import ReadPolicyStore, CONFIDENTIAL_GROUP_DENIAL


class ReadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store_path = self.root/'account-policy.sqlite3'
        self.lo, self.hi = '2026-10-17 00:00:00', '2026-10-17 23:59:59'

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_batch_skips_prior_denial_and_preserves_allowed_messages(self):
        denial = json.dumps({'error':{'server_error_code':'1001','message':'该群为保密群，无法获取消息记录'}})
        calls = []
        def runner(command, **kwargs):
            cid = command[command.index('--conversation-id')+1]
            calls.append(cid)
            if cid == 'restricted':
                return 1, '', denial
            return 0, json.dumps({'messages':[{'conversationId':cid,'messageId':'m1',
                  'createTime':'2026-10-17 12:00:00','content':'fixture body'}],'hasMore':False}), ''
        with ReadPolicyStore(self.store_path,'account-a') as store:
            _, first = dws_fetch.fetch_snapshot(self.root/'first', self.lo, self.hi,
                conversation_ids=['restricted','allowed'], runner=runner, policy_store=store)
        self.assertCountEqual(calls,['restricted','allowed'])
        self.assertFalse(first['complete'])
        calls.clear()
        with ReadPolicyStore(self.store_path,'account-a') as store:
            snapshot, second = dws_fetch.fetch_snapshot(self.root/'second', self.lo, self.hi,
                conversation_ids=['restricted','allowed'], runner=runner, policy_store=store)
        self.assertEqual(calls,['allowed'])
        self.assertEqual(second['policy_cached_skips'],1)
        self.assertEqual(second['errors'][0]['reason'],CONFIDENTIAL_GROUP_DENIAL)
        self.assertEqual(json.loads(snapshot.read_text())['messages'][0]['content'],'fixture body')

    def test_account_scope_mismatch_does_not_reuse_or_modify_policy(self):
        with ReadPolicyStore(self.store_path,'account-a') as store:
            store.remember('restricted',CONFIDENTIAL_GROUP_DENIAL)
        with self.assertRaises(ValueError):
            ReadPolicyStore(self.store_path,'account-b')
        with ReadPolicyStore(self.store_path,'account-a') as store:
            self.assertEqual(store.get('restricted'),CONFIDENTIAL_GROUP_DENIAL)
        with ReadPolicyStore(self.root/'other-account.sqlite3','account-b') as store:
            self.assertIsNone(store.get('restricted'))

    def test_two_open_handles_preserve_both_denials(self):
        with ReadPolicyStore(self.store_path,'account-a') as first, ReadPolicyStore(self.store_path,'account-a') as second:
            first.remember('first',CONFIDENTIAL_GROUP_DENIAL)
            second.remember('second',CONFIDENTIAL_GROUP_DENIAL)
            self.assertEqual(first.get('second'),CONFIDENTIAL_GROUP_DENIAL)
            self.assertEqual(second.get('first'),CONFIDENTIAL_GROUP_DENIAL)

    def test_unknown_reason_and_unverified_default_scope_are_rejected(self):
        with self.assertRaises(ValueError):
            ReadPolicyStore(self.store_path,'output-local')
        with ReadPolicyStore(self.store_path,'account-a') as store:
            with self.assertRaises(ValueError):
                store.remember('fixture','command_failed')
            self.assertIsNone(store.get('fixture'))

    def test_cli_new_output_reuses_denial_without_any_runner_calls(self):
        with ReadPolicyStore(self.store_path,'account-a') as store:
            store.remember('restricted',CONFIDENTIAL_GROUP_DENIAL)
        args = batch_cli.parser().parse_args(['--out',str(self.root/'cli'), '--scope','account-a',
            '--read-policy-store',str(self.store_path),'--conversation-id','restricted',
            '--start',self.lo,'--end',self.hi,'--server','off','--client','off'])
        with patch('dws_fetch._runner',side_effect=AssertionError('unexpected read')) as runner:
            report = batch_cli.execute(args)
        runner.assert_not_called()
        self.assertEqual(report['status'],'partial')
        self.assertEqual(report['fetch']['policy_cached_skips'],1)
        self.assertEqual(report['counts']['readable_messages'],0)

    def test_corrupt_policy_store_stops_before_fetch(self):
        self.store_path.write_bytes(b'not a database')
        args = batch_cli.parser().parse_args(['--out',str(self.root/'cli'), '--scope','account-a',
            '--read-policy-store',str(self.store_path),'--conversation-id','restricted',
            '--start',self.lo,'--end',self.hi,'--server','off','--client','off'])
        with patch('batch_cli.fetch_snapshot',side_effect=AssertionError('unexpected fetch')) as fetch:
            with self.assertRaises(sqlite3.DatabaseError):
                batch_cli.execute(args)
        fetch.assert_not_called()

    def test_later_denial_does_not_reexport_old_successful_raw_pages(self):
        response={'messages':[{'conversationId':'restricted','messageId':'m1',
                  'createTime':'2026-10-17 12:00:00','content':'fixture old body'}],'hasMore':False}
        output = self.root/'old'
        dws_fetch.fetch_snapshot(output,self.lo,self.hi,conversation_ids=['restricted'],
                                 runner=lambda *a,**k:(0,json.dumps(response),''))
        with ReadPolicyStore(self.store_path,'account-a') as store:
            store.remember('restricted',CONFIDENTIAL_GROUP_DENIAL)
            snapshot, report = dws_fetch.fetch_snapshot(output,None,None,conversation_ids=['restricted'],
                resume=True,policy_store=store,runner=lambda *a,**k: self.fail('unexpected read'))
        self.assertEqual(json.loads(snapshot.read_text())['messages'],[])
        self.assertFalse(report['complete'])

    def test_denial_on_later_page_does_not_export_earlier_page(self):
        responses = iter([
            (0,json.dumps({'messages':[{'conversationId':'restricted','messageId':'m1',
              'createTime':'2026-10-17 12:00:00','content':'fixture body'}],
              'hasMore':True,'nextPage':{'time':'2026-10-17 12:00:00'}}),''),
            (1,'',json.dumps({'error':{'server_error_code':'1001','message':'该群为保密群，无法获取消息记录'}}))])
        with ReadPolicyStore(self.store_path,'account-a') as store:
            snapshot, report = dws_fetch.fetch_snapshot(self.root/'later',self.lo,self.hi,
                conversation_ids=['restricted'],policy_store=store,runner=lambda *a,**k:next(responses))
            self.assertEqual(store.get('restricted'),CONFIDENTIAL_GROUP_DENIAL)
        self.assertEqual(json.loads(snapshot.read_text())['messages'],[])
        self.assertEqual(report['errors'][0]['reason'],CONFIDENTIAL_GROUP_DENIAL)
