"""Batch DING fallback: dws SafeChat intermediate + version-locked local keys.

No model calls. Conversation metadata is fetched once per CID; one exact
enterprise/version key is used, never trial-decrypting across enterprises.
"""
from pathlib import Path
from datetime import datetime, timezone
import re
import importlib
import sys

from ding_codec import parse_envelope, decrypt_envelope
from message_pipeline import plaintext, strict_json, unpack, sha


class NativeDecryptor:
    def __init__(self, out, runner, provider_factory=None, limit=0,
                 target_cids=None, conversation_provider_factory=None):
        self.out, self.runner, self.limit = Path(out), runner, limit
        self.provider_factory = provider_factory
        self.provider = None
        self.target_cids = set(target_cids or ())
        self.conversation_provider_factory = conversation_provider_factory
        self.conversation_provider = None
        self.conversation_provider_error = None
        self.conversation_errors = {}
        self.conversations = {}
        self.conversation_evidence = {}
        self.calls = 0
        self.metadata_calls = 0
        self.halted = None
        self.version_checked = False
        self.dependencies = None

    def check_dependencies(self):
        if self.dependencies is None:
            self.dependencies = {}
            for module, package in (('Crypto.Cipher.AES', 'pycryptodome'), ('pefile', 'pefile')):
                try:
                    importlib.import_module(module)
                    self.dependencies[module] = {'status':'available','package':package}
                except (ImportError, OSError, RuntimeError, ValueError):
                    # Import errors can contain local paths or arbitrary library text.
                    self.dependencies[module] = {'status':'unavailable','package':package,
                        'install_command':[sys.executable,'-m','pip','install',package]}
        if any(item['status'] != 'available' for item in self.dependencies.values()):
            self.halted = 'local_dependency_unavailable'
            return False
        return True

    def initialize(self):
        if self.halted:
            return False
        if not self.check_dependencies():
            return False
        try:
            if self.provider is None:
                if self.provider_factory:
                    self.provider = self.provider_factory()
                else:
                    from client_bridge import discover_client
                    from client_runtime.ding_key_provider import WindowsDingKeyProvider
                    target, error = discover_client()
                    if error:
                        self.halted = error
                        return False
                    self.provider = WindowsDingKeyProvider(target)
            if not self.version_checked:
                rc, output, _ = self.runner(['dws','version'],timeout=30)
                match = re.search(r'\bv?(\d+)\.(\d+)\.(\d+)\b', output)
                if rc or not match or tuple(map(int,match.groups())) < (1,0,63):
                    self.halted = 'unsupported_or_unknown_dws_version'
                    return False
                self.version_checked = True
            return True
        except (OSError, ValueError, RuntimeError, ImportError):
            self.halted = 'local_key_provider_unavailable'
            return False

    def conversation_enterprise(self, cid):
        if cid not in self.conversations:
            # Negative-cache this CID before I/O: a failed request must not be
            # retried for every encrypted body in the same conversation.
            self.conversations[cid] = None
            self.metadata_calls += 1
            try:
                rc, stdout, _ = self.runner(['dws','chat','conversation-info','--conversation-id',cid,'--format','json'],timeout=30)
                response = strict_json(stdout)
                info = response['result']['conversationInfo']
                if rc or response.get('success') is not True or info.get('openConversationId') != cid:
                    raise ValueError('Conversation identity mismatch')
                corp = info.get('corpId')
                if info.get('singleChat') is False and isinstance(corp,str) and re.fullmatch(r'ding[0-9a-zA-Z]+',corp):
                    self.conversations[cid] = corp
                    self.conversation_evidence[cid] = {'conversation_id':cid,'enterprise':corp,
                        'fetched_utc':datetime.now(timezone.utc).isoformat(),'response_sha256':sha(stdout),
                        'identity_basis':'official_group_conversation_info','history_enterprise_stability_verified':False}
                else:
                    self.conversations[cid] = self.native_conversation_enterprise(cid)
            except (KeyError,TypeError,ValueError,OSError,RuntimeError):
                self.conversation_errors[cid] = 'conversation_metadata_unavailable'
        return self.conversations[cid]

    def native_conversation_enterprise(self, cid):
        if self.conversation_provider_error:
            return None
        try:
            identity = self._native_conversation_identity(cid)
        except (KeyError,TypeError,ValueError,OSError,RuntimeError,ImportError):
            self.conversation_provider_error = 'native_conversation_provider_unavailable'
            return None
        if not identity:
            return None
        org = identity.get('org_id')
        if type(org) is not int or not 0 < org <= 0x7fffffffffffffff:
            return None
        # A missing org mapping concerns this CID, not the scan/provider itself.
        corp = self.provider.resolve_enterprise(org)
        self.conversation_evidence[cid] = {'conversation_id':cid,'enterprise':corp,
            'org_id':org,'identity_basis':'native_conversation_candidate_consensus',
            'fetched_utc':datetime.now(timezone.utc).isoformat(),
            'history_enterprise_stability_verified':False,
            'native_service_cache_selection_verified':False,'native_evidence':identity}
        return corp

    def _native_conversation_identity(self, cid):
        if self.conversation_provider is None:
            if self.conversation_provider_factory:
                self.conversation_provider = self.conversation_provider_factory()
            elif getattr(self.provider,'target',None):
                from client_runtime.conversation_identity import ConversationIdentityProvider
                target = dict(self.provider.target)
                target['process_created_filetime'] = self.provider.metadata['process_created_filetime']
                self.conversation_provider = ConversationIdentityProvider(target,self.target_cids | {cid})
            else:
                return None
        return self.conversation_provider.resolve(cid)

    def resolve(self, row, cid, mid, cipher):
        if not self.initialize():
            return {'status':'unresolved','reason':self.halted}
        if self.limit and self.calls >= self.limit:
            return {'status':'unresolved','reason':'local_decrypt_limit'}
        extension = unpack(row.get('extension',{}))
        if not isinstance(extension,dict):
            return {'status':'unresolved','reason':'invalid_message_crypto_metadata'}
        if any('safety_priority' in obj and str(obj['safety_priority']) != '0' for obj in (row,extension)):
            return {'status':'unresolved','reason':'unsupported_local_layer_order'}
        stage = 'enterprise_identity'
        try:
            explicit_corps = {str(obj[key]) for obj in (row,extension) for key in ('corpId','corp_id','enterprise') if key in obj}
            if len(explicit_corps)>1 or any(not re.fullmatch(r'ding[0-9a-zA-Z]+',corp) for corp in explicit_corps):
                return {'status':'unresolved','reason':'invalid_or_conflicting_message_enterprises'}
            explicit_corp = next(iter(explicit_corps),None)
            if 'oid' in extension or 'oid' in row:
                raw_org = extension.get('oid',row.get('oid'))
                if 'oid' in extension and 'oid' in row and str(extension['oid']) != str(row['oid']):
                    return {'status':'unresolved','reason':'conflicting_message_org_ids'}
                if isinstance(raw_org,bool) or not re.fullmatch(r'[1-9][0-9]{0,18}',str(raw_org)) or int(raw_org)>0x7fffffffffffffff:
                    return {'status':'unresolved','reason':'invalid_message_org_id'}
                corp = self.provider.resolve_enterprise(int(raw_org))
                if explicit_corp and corp != explicit_corp:
                    return {'status':'unresolved','reason':'message_org_enterprise_conflict'}
                identity_source = 'message_oid_to_client_enterprise'
            elif explicit_corp:
                corp = explicit_corp
                identity_source = 'message_explicit_corp_id'
            else:
                corp = self.conversation_enterprise(cid)
                identity_source = ('native_conversation_candidate_consensus'
                    if self.conversation_evidence.get(cid,{}).get('identity_basis') == 'native_conversation_candidate_consensus'
                    else 'group_conversation_info_corp_id')
            if not corp:
                return {'status':'unresolved','reason':'local_enterprise_identity_unavailable'}
            stage = 'safechat_input'
            self.out.mkdir(parents=True,exist_ok=True)
            file = self.out/'cipher.txt'
            file.write_text(cipher,encoding='utf-8')
            self.calls += 1
            stage = 'safechat_call'
            rc, output, _ = self.runner(['dws','chat','crypto','decrypt','--layer','safechat','--file',file.name,'--format','json'],timeout=45,cwd=str(self.out.resolve()))
            payload = strict_json(output)
            if rc or not isinstance(payload,dict) or payload.get('ok') is not True:
                self.halted = 'safechat_intermediate_failed'
                return {'status':'unresolved','reason':self.halted}
            inner = payload.get('plaintext')
            stage = 'envelope_validation'
            envelope = parse_envelope(inner)
            stage = 'key_lookup_or_unwrap'
            key = self.provider.get_key_for_enterprise(corp,envelope.key_version,envelope.crypto_type)
            stage = 'body_decryption_or_validation'
            decoded = decrypt_envelope(inner,key,expected_version=envelope.key_version).decode('utf-8',errors='strict')
            if not plaintext(decoded):
                return {'status':'unresolved','reason':'invalid_local_plaintext'}
            return {'status':'decrypted_local','text':decoded,'crypto_decryption_proven':True,
                    'enterprise':corp,'key_version':envelope.key_version,'crypto_type':envelope.crypto_type,
                    'identity_source':identity_source,'client_dll_sha256':self.provider.dll_sha256,
                    'identity_evidence':self.conversation_evidence.get(cid,{}) if identity_source in
                        ('native_conversation_candidate_consensus','group_conversation_info_corp_id') else {},
                    'plaintext_validation':'strict_pkcs7_and_utf8','independent_body_comparison':False}
        except (ValueError, OSError, RuntimeError, ImportError, KeyError, TypeError):
            # Never serialize library errors or decoded key buffers to output.
            return {'status':'unresolved','reason':'local_identity_key_or_payload_validation_failed',
                    'failure_stage':stage}

    def summary(self):
        return {'safechat_calls':self.calls,'conversation_metadata_calls':self.metadata_calls,
                'stop_reason':self.halted,'keys_written_to_disk':False,
                'python_executable':sys.executable,'dependencies':self.dependencies,
                'conversation_identity_evidence':list(self.conversation_evidence.values()),
                'key_provider':getattr(self.provider,'metadata',None),
                'native_conversation_provider':getattr(self.conversation_provider,'summary',None),
                'native_conversation_stop_reason':self.conversation_provider_error,
                'conversation_metadata_errors':dict(self.conversation_errors),
                'limitations':['Requires the verified logged-in Windows client and a cached matching enterprise/version.',
                               'Group fallback uses official conversation corpId; explicit message oid takes precedence.',
                               'Conversation metadata does not independently verify historical enterprise stability or each plaintext.',
                               'Native fallback requires exact CID and unanimous typed conversation organization candidates.',
                               'Native object consensus does not prove service cache selection or historical enterprise stability.']}

    def close(self):
        if self.conversation_provider is not None:
            self.conversation_provider.close()
            self.conversation_provider = None
        if self.provider is not None:
            self.provider.close()
            self.provider = None
