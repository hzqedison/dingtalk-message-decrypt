"""Offline client fingerprint registry. Never opens a process or contacts DWS.

New fingerprints require a reviewed adapter and separate runtime acceptance.
Version labels are diagnostic only: they never authorize a native memory read.
"""
from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class ClientProfile:
    id: str
    tested_version: str
    dll_sha256: str
    capabilities: tuple[str, ...]


LEGACY_PROFILE = ClientProfile(
    'windows-x64-261015001',
    '9.0.2.261015001',
    '23bf21eec6a50c69388089e7ddeb22b573439c36f4c9be4c396d719a3f375d77',
    ('ding_key_provider', 'conversation_identity', 'typed_messages'),
)
PROFILES = (LEGACY_PROFILE,)


class ClientCompatibilityError(ValueError):
    def __init__(self, reason, diagnostic):
        super().__init__(reason)
        self.reason = reason
        self.diagnostic = diagnostic


def assess_fingerprint(dll_sha256):
    """Only allowlisted fields; caller paths, process/account IDs are excluded."""
    matches = [p for p in PROFILES if p.dll_sha256 == dll_sha256]
    profile = matches[0] if len(matches) == 1 else None
    return {
        'status': 'recognized' if profile else 'unsupported',
        'reason': None if profile else (
            'ambiguous_client_profile' if matches else 'unsupported_client_fingerprint'),
        'dll_sha256': dll_sha256,
        'profile_id': profile.id if profile else None,
        'tested_client_version': profile.tested_version if profile else None,
        'capabilities': list(profile.capabilities) if profile else [],
        'supported_profiles': [
            {'id': p.id, 'tested_client_version': p.tested_version,
             'dll_sha256': p.dll_sha256, 'capabilities': list(p.capabilities)}
            for p in PROFILES
        ],
        'validation_stage': 'disk_fingerprint',
        'runtime_validation_performed': False,
        'key_lookup_attempted': False,
        'key_availability': 'not_assessed',
    }


def require_binary(raw, capability, *, adapter_profile=LEGACY_PROFILE.id):
    """Guard a concrete adapter, not just membership in a future allowlist."""
    result = assess_fingerprint(hashlib.sha256(raw).hexdigest())
    reason = result['reason']
    if not reason and result['profile_id'] != adapter_profile:
        reason = 'client_adapter_not_implemented'
    if not reason and capability not in result['capabilities']:
        reason = 'client_capability_not_supported'
    if reason:
        result.update(status='unsupported', reason=reason,
                      requested_capability=capability)
        raise ClientCompatibilityError(reason, result)
    return result
