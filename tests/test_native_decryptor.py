import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from native_decryptor import NativeDecryptor
from message_pipeline import resolve_batch, Cache


class Provider:
    dll_sha256 = 'fixture-build'
    key = bytes(range(16))
    def __init__(self):
        self.selections = []
        self.closed = False
    def resolve_enterprise(self, org):
        if org != 7:
            raise ValueError('Unknown organization')
        return 'dingMessage'
    def get_key_for_enterprise(self, corp, version, kind):
        self.selections.append((corp,version,kind))
        if version != 1 or kind != 1:
            raise ValueError('Missing version')
        return self.key
    def close(self):
        self.closed = True


def inner(text='fixture decrypted body', version=1):
    from Crypto.Cipher import AES
    value=text.encode('utf-8'); padding=16-len(value)%16
    iv=bytes(range(16,32))
    encrypted=AES.new(Provider.key,AES.MODE_CBC,iv=iv).encrypt(value+bytes([padding])*padding)
    return f'1_{version}_'+(iv+encrypted).hex()


class Runner:
    def __init__(self, cid='cid1', single=False, envelope=None):
        self.cid,self.single=cid,single
        self.envelope=envelope if envelope is not None else inner()
        self.calls=[]
    def __call__(self, command, timeout=None, cwd=None):
        self.calls.append(command)
        if command == ['dws','version']:
            return 0,'dws v1.0.64',''
        if 'conversation-info' in command:
            return 0,json.dumps({'success':True,'result':{'conversationInfo':{
                'openConversationId':self.cid,'singleChat':self.single,'corpId':'dingGroup'}}}),''
        if 'decrypt' in command:
            assert command[command.index('--layer')+1]=='safechat'
            filename=command[command.index('--file')+1]
            assert not Path(filename).is_absolute() and Path(cwd,filename).is_file()
            return 0,json.dumps({'ok':True,'plaintext':self.envelope}),''
        raise AssertionError(command)


class ConversationProvider:
    def __init__(self, identities):
        self.identities=identities
        self.calls=[]
        self.summary={'scan_completed':True,'elapsed_seconds':0.01}
        self.closed=False
    def resolve(self,cid):
        self.calls.append(cid)
        return self.identities.get(cid)
    def close(self):
        self.closed=True


class NativeDecryptorTests(unittest.TestCase):
    cipher=base64.b64encode(b'cipher fixture').decode()+'||2||1||128'
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.provider=Provider();self.runner=Runner()
        self.resolver=NativeDecryptor(self.root/'tmpdec',self.runner,lambda:self.provider)
    def tearDown(self):
        self.resolver.close();self.tmp.cleanup()
    def call(self,row=None):
        return self.resolver.resolve(row or {},'cid1','msg1',self.cipher)
    def test_missing_dependencies_stop_before_client_or_network_and_identify_interpreter(self):
        for missing, package in (('Crypto.Cipher.AES','pycryptodome'),('pefile','pefile')):
            with self.subTest(missing=missing):
                resolver=NativeDecryptor(self.root/missing,self.runner,lambda:self.fail('Provider accessed'))
                def importer(name):
                    if name == missing:
                        raise ModuleNotFoundError('secret fixture must not be serialized')
                    return object()
                with patch('native_decryptor.importlib.import_module',side_effect=importer) as imports:
                    for _ in range(2):
                        result=resolver.resolve({},'cid1','m',self.cipher)
                        self.assertEqual(result['reason'],'local_dependency_unavailable')
                    self.assertEqual(imports.call_count,2)
                report=resolver.summary()
                self.assertEqual(report['python_executable'],sys.executable)
                self.assertEqual(report['dependencies'][missing]['install_command'],
                                 [sys.executable,'-m','pip','install',package])
                self.assertEqual(report['safechat_calls'],0)
                self.assertIsNone(report['key_provider'])
                self.assertNotIn('secret fixture',json.dumps(report))
                self.assertEqual(self.runner.calls,[])
    def test_key_failure_is_distinct_from_body_failure_without_exception_text(self):
        with patch.object(self.provider,'get_key_for_enterprise',side_effect=ValueError('secret fixture')):
            result=self.call({'oid':7})
        self.assertEqual(result['failure_stage'],'key_lookup_or_unwrap')
        self.assertEqual(self.resolver.calls,1)
        self.assertNotIn('secret fixture',json.dumps(result))
        with patch('native_decryptor.decrypt_envelope',side_effect=ValueError('secret fixture')):
            result=self.call({'oid':7})
        self.assertEqual(result['failure_stage'],'body_decryption_or_validation')
        self.assertNotIn('secret fixture',json.dumps(result))
    def test_invalid_envelope_never_selects_key_and_stage_survives_pipeline(self):
        self.runner.envelope='not an envelope'
        source=self.root/'invalid-envelope.json'
        source.write_text(json.dumps([{'conversationId':'cid1','messageId':'m',
                                      'content':self.cipher,'oid':7}]),encoding='utf-8')
        out=self.root/'invalid-output'
        resolve_batch([source],out,server='off',local_decryptor=self.resolver)
        row=json.loads((out/'unresolved.jsonl').read_text(encoding='utf-8').strip())
        self.assertEqual(row['local_failure_stage'],'envelope_validation')
        self.assertEqual(self.provider.selections,[])
    def test_group_metadata_and_decrypt_are_cached_at_correct_scopes(self):
        for _ in range(2):
            result=self.call()
            self.assertEqual(result['text'],'fixture decrypted body')
            self.assertEqual(result['identity_source'],'group_conversation_info_corp_id')
        self.assertEqual(self.resolver.metadata_calls,1)
        self.assertEqual(self.resolver.calls,2)
        self.assertEqual(self.provider.selections,[('dingGroup',1,1)]*2)
    def test_message_oid_precedes_conversation_and_never_uses_current_account(self):
        result=self.call({'extension':{'oid':'7','safety_priority':'0'}})
        self.assertEqual(result['enterprise'],'dingMessage')
        self.assertEqual(self.resolver.metadata_calls,0)
    def test_top_level_oid_supported_and_conflict_rejected(self):
        self.assertEqual(self.call({'oid':7})['enterprise'],'dingMessage')
        self.assertEqual(self.call({'oid':8,'extension':{'oid':'7'}})['reason'],'conflicting_message_org_ids')
    def test_explicit_corp_selects_enterprise_without_conversation_lookup(self):
        for row in ({'corpId':'dingExplicit'}, {'extension':{'corpId':'dingExplicit'}}):
            result=self.call(row)
            self.assertEqual(result['text'],'fixture decrypted body')
            self.assertEqual(result['enterprise'],'dingExplicit')
            self.assertEqual(result['identity_source'],'message_explicit_corp_id')
        self.assertEqual(self.resolver.metadata_calls,0)
        self.assertEqual(self.provider.selections,[('dingExplicit',1,1)]*2)
    def test_oid_and_explicit_corp_conflict_never_selects_key(self):
        for row in ({'oid':7,'corpId':'dingOther'},
                    {'extension':{'oid':'7','corpId':'dingOther'}},
                    {'oid':7,'extension':{'corpId':'dingOther'}}):
            self.assertEqual(self.call(row)['reason'],'message_org_enterprise_conflict')
        self.assertEqual(self.resolver.metadata_calls,0)
        self.assertEqual(self.resolver.calls,0)
        self.assertEqual(self.provider.selections,[])
    def test_matching_oid_and_corp_retains_oid_identity_source(self):
        result=self.call({'oid':7,'corpId':'dingMessage'})
        self.assertEqual(result['enterprise'],'dingMessage')
        self.assertEqual(result['identity_source'],'message_oid_to_client_enterprise')
        self.assertEqual(self.resolver.metadata_calls,0)
    def test_conflicting_or_invalid_explicit_corp_never_selects_key(self):
        for row in ({'corpId':'dingOne','extension':{'corpId':'dingTwo'}},
                    {'corpId':None},{'corpId':''},{'corpId':True}):
            self.assertEqual(self.call(row)['reason'],'invalid_or_conflicting_message_enterprises')
        self.assertEqual(self.provider.selections,[])
    def test_invalid_or_unknown_message_oid_does_not_downgrade_to_group(self):
        for oid in ('0','-1','not-number','8',True):
            self.assertEqual(self.call({'extension':{'oid':oid}})['status'],'unresolved')
        self.assertEqual(self.resolver.calls,0)
        self.assertEqual(self.resolver.metadata_calls,0)
    def test_mismatched_cid_or_direct_without_oid_never_reads_key(self):
        for runner in (Runner(cid='another-cid'),Runner(single=True)):
            resolver=NativeDecryptor(self.root/'other',runner,lambda:self.provider)
            self.assertEqual(resolver.resolve({},'cid1','m',self.cipher)['status'],'unresolved')
            self.assertEqual(resolver.calls,0)
        self.assertEqual(self.provider.selections,[])
    def test_wrong_layer_intermediate_and_missing_version_are_not_plaintext(self):
        self.assertEqual(self.call({'extension':{'safety_priority':'1'}})['status'],'unresolved')
        self.runner.envelope='1_1_abcdef'
        self.assertEqual(self.call()['status'],'unresolved')
        self.runner.envelope=inner(version=9)
        self.assertEqual(self.call()['status'],'unresolved')
    def test_limit_and_close(self):
        self.resolver.limit=1;self.call()
        self.assertEqual(self.call()['reason'],'local_decrypt_limit')
        self.resolver.close();self.assertTrue(self.provider.closed)
    def test_policy_disabled_pipeline_uses_local_and_persists_only_plaintext(self):
        source=self.root/'source.json';out=self.root/'output';out.mkdir()
        rows=[{'conversationId':'cid1','messageId':'m1','content':self.cipher},
              {'conversationId':'cid1','messageId':'m2','content':self.cipher}]
        source.write_text(json.dumps(rows),encoding='utf-8')
        cache=Cache(out/'resolution_cache.sqlite3','fixture');cache.set_disabled('CRYPTO_DISABLED');cache.close()
        report=resolve_batch([source],out,scope='fixture',runner=self.runner,local_decryptor=self.resolver)
        self.assertEqual(report['counts']['body_decrypted_local'],2)
        self.assertEqual(report['local_crypto']['safechat_calls'],1)
        self.assertEqual(report['decrypt_calls'],0)
        self.assertEqual(report['server_stop_reason'],'CRYPTO_DISABLED')
        second=resolve_batch([source],out,scope='fixture',server='off')
        self.assertEqual(second['counts']['body_decrypted_local_cache'],2)
        self.assertEqual(second['decrypt_calls'],0)
        replay=[json.loads(line) for line in (out/'messages.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertTrue(all(row['source_resolution_status']=='decrypted_local' and row['enterprise']=='dingGroup'
                            and row['key_version']==1 and row['identity_source']=='group_conversation_info_corp_id'
                            for row in replay))
    def test_conflicting_message_oid_variants_do_not_resolve(self):
        source=self.root/'conflict.json'
        source.write_text(json.dumps([{'messageId':'m','conversationId':'cid1','content':self.cipher,
            'extension':{'oid':oid}} for oid in ('7','8')]),encoding='utf-8')
        report=resolve_batch([source],self.root/'conflict',server='off',local_decryptor=self.resolver)
        self.assertEqual(report['counts']['conflicting_messages'],1)
        self.assertEqual(self.resolver.calls,0)
    def test_identity_evidence_survives_contextual_cache(self):
        result=self.call({'oid':7})
        evidence={'conversation_id':'cid1','org_id':7,'source':'fixture_typed_metadata',
                  'observed_at':'2026-10-18T00:00:00Z','history_enterprise_stability_verified':False}
        result['identity_evidence']=evidence
        cache=Cache(self.root/'evidence.sqlite3','fixture')
        try:
            cache.put_result('cid1',self.cipher,{'oid':'7'},result)
            replay=cache.get_result('cid1',self.cipher,{'oid':'7'})
            self.assertEqual(replay['identity_evidence'],evidence)
        finally:
            cache.close()
    def test_native_conversation_consensus_selects_exact_org_and_preserves_evidence(self):
        self.runner.single=True
        identity={'api_conversation_id':'cid1','org_id':7,'identity_source':'native_conversation_candidate_consensus',
                  'historical_identity_proven':False,'evidence':{'same_object_double_read':True,'scan_completed':True}}
        native=ConversationProvider({'cid1':identity})
        self.resolver.conversation_provider_factory=lambda:native
        for _ in range(2):
            result=self.call()
            self.assertEqual(result['enterprise'],'dingMessage')
            self.assertEqual(result['identity_source'],'native_conversation_candidate_consensus')
            self.assertEqual(result['identity_evidence']['native_evidence'],identity)
            self.assertFalse(result['identity_evidence']['history_enterprise_stability_verified'])
            self.assertFalse(result['identity_evidence']['native_service_cache_selection_verified'])
        self.assertEqual(self.resolver.metadata_calls,1)
        self.assertEqual(native.calls,['cid1'])
        self.assertEqual(self.provider.selections,[('dingMessage',1,1)]*2)
        self.assertEqual(self.resolver.summary()['native_conversation_provider'],native.summary)
        self.resolver.close()
        self.assertTrue(native.closed)
    def test_native_missing_candidate_does_not_select_key_or_repeat_lookup(self):
        self.runner.single=True
        native=ConversationProvider({})
        self.resolver.conversation_provider_factory=lambda:native
        for _ in range(3):
            self.assertEqual(self.call()['status'],'unresolved')
        self.assertEqual(native.calls,['cid1'])
        self.assertEqual(self.resolver.metadata_calls,1)
        self.assertEqual(self.resolver.calls,0)
        self.assertEqual(self.provider.selections,[])
    def test_native_provider_initialization_failure_does_not_repeat_for_each_body_or_cid(self):
        for failure in (OSError,RuntimeError):
            with self.subTest(failure=failure):
                attempts=[]
                def factory():
                    attempts.append(1)
                    raise failure('fixture failed initialization')
                runner=Runner(single=True)
                resolver=NativeDecryptor(self.root/failure.__name__,runner,lambda:self.provider,
                                         conversation_provider_factory=factory)
                try:
                    for cid in ('cid1','cid1','cid2'):
                        runner.cid=cid
                        self.assertEqual(resolver.resolve({},cid,'m',self.cipher)['status'],'unresolved')
                    self.assertEqual(len(attempts),1)
                    self.assertEqual(resolver.metadata_calls,2)
                    self.assertEqual(resolver.calls,0)
                    self.assertEqual(resolver.conversation_provider_error,'native_conversation_provider_unavailable')
                finally:
                    resolver.close()
        self.assertEqual(self.provider.selections,[])
    def test_metadata_transport_failure_is_negative_cached_for_cid(self):
        calls=[]
        def runner(command,**kwargs):
            if 'conversation-info' in command:
                calls.append(command)
                raise OSError('fixture metadata failure')
            return self.runner(command,**kwargs)
        self.resolver.runner=runner
        for _ in range(3):
            self.assertEqual(self.call()['status'],'unresolved')
        self.assertEqual(len(calls),1)
        self.assertEqual(self.resolver.conversation_errors['cid1'],'conversation_metadata_unavailable')
        self.assertEqual(self.provider.selections,[])
    def test_one_missing_org_mapping_does_not_disable_other_conversation(self):
        self.runner.single=True
        native=ConversationProvider({'cid1':{'api_conversation_id':'cid1','org_id':8},
                                     'cid2':{'api_conversation_id':'cid2','org_id':7}})
        self.resolver.conversation_provider_factory=lambda:native
        self.assertEqual(self.call()['status'],'unresolved')
        self.assertIsNone(self.resolver.conversation_provider_error)
        self.runner.cid='cid2'
        result=self.resolver.resolve({},'cid2','m',self.cipher)
        self.assertEqual(result['status'],'decrypted_local')
        self.assertEqual(result['enterprise'],'dingMessage')
        self.assertEqual(self.provider.selections,[('dingMessage',1,1)])
        self.assertEqual(native.calls,['cid1','cid2'])


if __name__=='__main__':
    unittest.main()
