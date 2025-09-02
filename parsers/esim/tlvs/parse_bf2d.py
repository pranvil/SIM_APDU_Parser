
from core.models import MsgType, ParseNode
from core.registry import register
from core.tlv import parse_ber_tlvs
from core.utils import parse_iccid, hex_to_utf8

def _build_profile_block(e3_hex: str) -> ParseNode:
    prof = ParseNode(name="Profile")
    for st in parse_ber_tlvs(e3_hex):
        name = st.tag
        val = st.value_hex
        if st.tag == "5A":
            name = "ICCID"; val = parse_iccid(val)
        elif st.tag == "4F":
            name = "ISD-P AID"
        elif st.tag == "9F70":
            name = "Profile state"; val = {"00":"Disabled","01":"Enabled"}.get(val, f"Unknown({val})")
        elif st.tag == "90":
            name = "Profile Nickname"; val = hex_to_utf8(val) or st.value_hex
        elif st.tag == "91":
            name = "Service provider name"; val = hex_to_utf8(val) or st.value_hex
        elif st.tag == "92":
            name = "Profile name"; val = hex_to_utf8(val) or st.value_hex
        elif st.tag == "95":
            name = "Profile Class"; val = {"00":"test","01":"provisioning","02":"operational"}.get(val, f"Unknown({val})")
        prof.children.append(ParseNode(name=name, value=val))
    return prof

def _try_response_profiles(hexv: str) -> ParseNode|None:
    # Look for profiles under E3, possibly wrapped by A0/A1 etc.
    # Depth 0
    tlvs = parse_ber_tlvs(hexv)
    e3_blocks = [t for t in tlvs if t.tag == "E3"]
    if e3_blocks:
        root = ParseNode(name="BF2D: Profile Info List")
        for i, t in enumerate(e3_blocks, 1):
            prof = _build_profile_block(t.value_hex)
            prof.name = f"Profile {i}"
            root.children.append(prof)
        return root
    # Depth 1 containers
    for t in tlvs:
        if t.tag in ("A0","A1","E0","E1","61","30"):
            inner = parse_ber_tlvs(t.value_hex)
            e3_blocks = [x for x in inner if x.tag == "E3"]
            if e3_blocks:
                root = ParseNode(name="BF2D: Profile Info List")
                for i, x in enumerate(e3_blocks, 1):
                    prof = _build_profile_block(x.value_hex)
                    prof.name = f"Profile {i}"
                    root.children.append(prof)
                return root
    return None

def _decode_taglist_hex(taglist_hex: str):
    s = taglist_hex.upper().replace(" ", "")
    idx = 0; n = len(s); out = []
    
    # Tag meaning mapping
    tag_meaning_map = {
        "5A": "ICCID",
        "90": "profileNickname", 
        "91": "serviceProviderName",
        "92": "profileName",
        "93": "iconType",
        "94": "icon",
        "95": "profileClass",
        "B6": "notificationConfigurationInfo",
        "B7": "profileOwner",
        "B8": "dpProprietaryData",
        "99": "profilePolicyRules",
        "9F70": "profileState",
        "BF76": "BF76 (unknown/vendor-specific)",
    }
    
    while idx < n:
        if idx+2>n: break
        t1 = s[idx:idx+2]; idx += 2
        if t1 in ("9F","BF","5F","7F") and idx+2<=n:
            t2 = s[idx:idx+2]; idx += 2
            tag = t1+t2
        else:
            tag = t1
        meaning = tag_meaning_map.get(tag, "Unknown")
        out.append((tag, meaning))
    return out

@register(MsgType.ESIM, "BF2D")
class BF2DParser:
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        # Try response style first (E3 profile blocks)
        resp = _try_response_profiles(payload_hex)
        if resp is not None:
            return resp

        # Request style: Tag List / searchCriteria
        root = ParseNode(name="BF2D: ProfileInfoListRequest")
        tlvs = parse_ber_tlvs(payload_hex)
        for t in tlvs:
            if t.tag == "5C":
                tag_pairs = _decode_taglist_hex(t.value_hex)
                tag_list = [f"{tag}({meaning})" for tag, meaning in tag_pairs]
                sub = ParseNode(name="Requested Tags (5C)", value=", ".join(tag_list))
                for tag, meaning in tag_pairs:
                    sub.children.append(ParseNode(name=f"Tag {tag}", value=meaning))
                root.children.append(sub)
            elif t.tag == "4F":
                root.children.append(ParseNode(name="searchCriteria.isdpAid (4F)", value=t.value_hex))
            elif t.tag == "5A":
                root.children.append(ParseNode(name="searchCriteria.iccid (5A)", value=parse_iccid(t.value_hex)))
            elif t.tag == "95":
                root.children.append(ParseNode(name="searchCriteria.profileClass (95)",
                                               value={"00":"test","01":"provisioning","02":"operational"}.get(t.value_hex, f"Unknown({t.value_hex})")))
            else:
                root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))
        if not tlvs and payload_hex == "00":
            root.hint = "Default request (BF2D 00)"
        return root
