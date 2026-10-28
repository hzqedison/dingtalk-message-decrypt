"""Explicit layouts for audited x64 native adapters; no live signature guessing."""
from dataclasses import dataclass
import hashlib
from types import MappingProxyType

import client_compatibility as compatibility


@dataclass(frozen=True)
class NativeLayout:
    getter_rva: int
    key_slot_rva: int
    org_slot_rva: int
    org_vtable_rva: int
    material_table_rva: int
    conversation_vtable_rva: int
    conversation_first_rva: int
    mj_model_vtable: int
    mj_text_vtable: int
    im_model_vtable: int
    im_text_vtable: int

    def message(self, kind):
        if kind == 'mj':
            return {'model_vtable': self.mj_model_vtable, 'text_vtable': self.mj_text_vtable,
                    'text_offset': 0x38, 'require_status_one': True}
        if kind == 'im_chat':
            return {'model_vtable': self.im_model_vtable, 'text_vtable': self.im_text_vtable,
                    'text_offset': 0x28, 'require_status_one': False}
        raise ValueError('Unsupported message model')


LEGACY_LAYOUT = NativeLayout(
    0x59AAF40, 0x9D70CD8, 0x9D5F148, 0x82C0E30, 0x84EF581,
    0x6DF44C8, 0xF84400, 0x6E03DF0, 0x6E36328, 0x81AFF00, 0x81AFD98,
)
LAYOUT_261018001 = NativeLayout(
    0x59AD3B0, 0x9D7D6E8, 0x9D6BB58, 0x82CB320, 0x84F9A91,
    0x6DFE528, 0xF844B0, 0x6E0DE50, 0x6E403E8, 0x81BA330, 0x81BA1C8,
)
LAYOUT_261021001 = NativeLayout(
    0x59D4BA0, 0x9D90DB8, 0x9D7F228, 0x82DA3E0, 0x85083D1,
    0x6E0C648, 0xF85DC0, 0x6E1BF70, 0x6E4E4A8, 0x81C9430, 0x81C92C8,
)
LAYOUTS = MappingProxyType({
    compatibility.LEGACY_PROFILE.id: LEGACY_LAYOUT,
    compatibility.CLIENT_261018001.id: LAYOUT_261018001,
    compatibility.CLIENT_261021001.id: LAYOUT_261021001,
})


def select_binary_layout(raw, capability):
    diagnostic = compatibility.assess_fingerprint(hashlib.sha256(raw).hexdigest())
    profile_id = diagnostic['profile_id']
    compatibility.require_binary(raw, capability, adapter_profile=profile_id)
    if profile_id not in LAYOUTS:
        diagnostic.update(status='unsupported', reason='client_adapter_not_implemented',
                          requested_capability=capability)
        raise compatibility.ClientCompatibilityError(diagnostic['reason'], diagnostic)
    profile = next(p for p in compatibility.PROFILES if p.id == profile_id
                   and p.dll_sha256 == diagnostic['dll_sha256'])
    return profile, LAYOUTS[profile_id]
