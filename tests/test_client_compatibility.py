"""Fingerprint gates and diagnostics, with no live process or account access."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import client_bridge
import client_compatibility as compatibility
from client_doctor import inspect_dll
from native_decryptor import NativeDecryptor
from client_runtime import ding_key_provider, conversation_identity
from client_layouts import select_binary_layout, LEGACY_LAYOUT, LAYOUT_261018001


class CompatibilityTests(unittest.TestCase):
    def test_known_fingerprint_is_not_runtime_or_key_proof(self):
        result = compatibility.assess_fingerprint(compatibility.LEGACY_PROFILE.dll_sha256)
        self.assertEqual(result['status'], 'recognized')
        self.assertEqual(len(result['capabilities']), 3)
        self.assertFalse(result['runtime_validation_performed'])
        self.assertFalse(result['key_lookup_attempted'])
        self.assertEqual(result['key_availability'], 'not_assessed')

    def test_unknown_binary_preserves_fingerprint_not_contents(self):
        raw = b'private fixture bytes'
        with self.assertRaises(compatibility.ClientCompatibilityError) as caught:
            compatibility.require_binary(raw, 'ding_key_provider')
        result = caught.exception.diagnostic
        self.assertEqual(result['dll_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['reason'], 'unsupported_client_fingerprint')
        self.assertNotIn('private fixture', json.dumps(result))

    def test_new_profile_cannot_reuse_old_adapter_implicitly(self):
        raw = b'new reviewed fixture'
        profile = compatibility.ClientProfile('new-adapter', 'new-version',
            hashlib.sha256(raw).hexdigest(), ('ding_key_provider',))
        with patch.object(compatibility, 'PROFILES', (profile,)):
            with self.assertRaises(compatibility.ClientCompatibilityError) as caught:
                compatibility.require_binary(raw, 'ding_key_provider')
            self.assertEqual(caught.exception.reason, 'client_adapter_not_implemented')
            result = compatibility.require_binary(raw, 'ding_key_provider',
                                                  adapter_profile='new-adapter')
            self.assertEqual(result['profile_id'], 'new-adapter')
            with self.assertRaises(compatibility.ClientCompatibilityError) as caught:
                compatibility.require_binary(raw, 'typed_messages',
                                             adapter_profile='new-adapter')
            self.assertEqual(caught.exception.reason, 'client_capability_not_supported')

    def test_duplicate_fingerprint_fails_closed(self):
        profile = compatibility.LEGACY_PROFILE
        with patch.object(compatibility, 'PROFILES', (profile, profile)):
            result = compatibility.assess_fingerprint(profile.dll_sha256)
        self.assertEqual(result['reason'], 'ambiguous_client_profile')
        self.assertEqual(result['capabilities'], [])

    def test_layout_dispatch_and_validation_stage_are_profile_specific(self):
        raw_old, raw_new = b'synthetic old file', b'synthetic new file'
        old = compatibility.ClientProfile(compatibility.LEGACY_PROFILE.id, 'old',
            hashlib.sha256(raw_old).hexdigest(), ('ding_key_provider',), 'runtime_sample_verified')
        new = compatibility.ClientProfile(compatibility.CLIENT_261018001.id, 'new',
            hashlib.sha256(raw_new).hexdigest(), ('ding_key_provider',), 'static_verified_runtime_pending')
        with patch.object(compatibility, 'PROFILES', (old, new)):
            for raw, profile, layout in ((raw_new, new, LAYOUT_261018001),
                                          (raw_old, old, LEGACY_LAYOUT),
                                          (raw_new, new, LAYOUT_261018001)):
                selected, actual = select_binary_layout(raw, 'ding_key_provider')
                self.assertIs(selected, profile)
                self.assertIs(actual, layout)
                info = compatibility.assess_fingerprint(profile.dll_sha256)
                self.assertEqual(info['adapter_validation'], profile.validation)
                self.assertFalse(info['runtime_validation_performed'])
            self.assertNotEqual(LEGACY_LAYOUT.key_slot_rva, LAYOUT_261018001.key_slot_rva)

    def test_registered_fingerprint_without_implemented_layout_still_rejected(self):
        raw = b'future layout'
        profile = compatibility.ClientProfile('future-adapter', 'future',
            hashlib.sha256(raw).hexdigest(), ('ding_key_provider',))
        with patch.object(compatibility, 'PROFILES', (profile,)):
            with self.assertRaises(compatibility.ClientCompatibilityError) as caught:
                select_binary_layout(raw, 'ding_key_provider')
        self.assertEqual(caught.exception.reason, 'client_adapter_not_implemented')

    def test_offline_doctor_unknown_and_missing_files_do_not_leak_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-user-MainFrame.dll'
            path.write_bytes(b'unknown binary')
            result = inspect_dll(path)
            self.assertEqual(result['reason'], 'unsupported_client_fingerprint')
            self.assertNotIn(directory, json.dumps(result))
            result = inspect_dll(path.with_suffix('.absent'))
            self.assertEqual(result['reason'], 'dll_file_unreadable')
            self.assertNotIn(directory, json.dumps(result))

    def test_doctor_cli_has_partial_exit_and_json_without_dependencies(self):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'client_doctor.py'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'MainFrame.dll'
            path.write_bytes(b'unknown binary')
            completed = subprocess.run([sys.executable, '-B', '-S', str(script),
                                        '--dll', str(path)], capture_output=True)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)['reason'],
                         'unsupported_client_fingerprint')

    def test_unknown_dll_rejects_both_native_adapters_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'MainFrame.dll'
            path.write_bytes(b'unknown binary')
            target = {'pid': 7, 'module_base': 0x180000000,
                      'exe': 'synthetic/DingTalk.exe', 'dll': str(path)}
            with patch.object(ding_key_provider, '_open_process') as open_process:
                with self.assertRaises(compatibility.ClientCompatibilityError):
                    ding_key_provider.WindowsDingKeyProvider(target)
                open_process.assert_not_called()
            with patch.object(conversation_identity, '_open_process') as open_process:
                with self.assertRaises(compatibility.ClientCompatibilityError):
                    conversation_identity.ConversationIdentityProvider(target, {'cid-synthetic'})
                open_process.assert_not_called()

    def test_capture_unknown_dll_stops_before_inputs_output_or_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'MainFrame.dll'
            path.write_bytes(b'unknown binary')
            output = Path(directory) / 'must-not-exist'
            with patch.object(client_bridge, 'discover_client',
                              return_value=({'dll': str(path)}, None)), \
                    patch.object(client_bridge, 'load_inputs') as load, \
                    patch.object(client_bridge.subprocess, 'run') as run:
                result = client_bridge.capture_loaded(['missing-input'], output)
            self.assertEqual(result['reason'], 'unsupported_client_fingerprint')
            load.assert_not_called()
            run.assert_not_called()
            self.assertFalse(output.exists())

    def test_batch_reports_compatibility_without_guessing_missing_keys(self):
        def unknown_provider():
            compatibility.require_binary(b'unknown binary', 'ding_key_provider')
        with tempfile.TemporaryDirectory() as directory:
            runner = unittest.mock.Mock()
            reader = NativeDecryptor(directory, runner, provider_factory=unknown_provider)
            with patch.object(reader, 'check_dependencies', return_value=True):
                self.assertFalse(reader.initialize())
                self.assertFalse(reader.initialize())
            result = reader.summary()
            self.assertEqual(result['stop_reason'], 'unsupported_client_fingerprint')
            self.assertEqual(result['safechat_calls'], 0)
            self.assertIsNone(result['key_provider'])
            self.assertEqual(result['client_compatibility']['key_availability'], 'not_assessed')
            runner.assert_not_called()


if __name__ == '__main__':
    unittest.main()
