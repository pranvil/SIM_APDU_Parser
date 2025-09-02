
from core.models import MsgType, ParseNode
from core.registry import register
from core.tlv import parse_ber_tlvs
from core.utils import parse_iccid

def _parse_euicc_response(ppi_hex: str) -> ParseNode:
    node = ParseNode(name="peStatus")
    # ppi structure: 30 [len] { 80 status, 81 identification number, ...}
    tlvs = parse_ber_tlvs(ppi_hex)
    for t in tlvs:
        if t.tag == "30":
            for st in parse_ber_tlvs(t.value_hex):
                if st.tag == "80":
                    status_map = {0:"ok",1:"pe-not-supported",2:"memory-failure",3:"bad-values",4:"not-enough-memory",
                                  5:"invalid-request-format",6:"invalid-parameter",7:"runtime-not-supported",
                                  8:"lib-not-supported",9:"template-not-supported",10:"feature-not-supported",
                                  11:"pin-code-missing",31:"unsupported-profile-version"}
                    v = int(st.value_hex or "00", 16)
                    node.children.append(ParseNode(name="status", value=f"{status_map.get(v,'Unknown Status')}({v})"))
                elif st.tag == "81":
                    v = int(st.value_hex or "00", 16)
                    node.children.append(ParseNode(name="identification number", value=str(v)))
                else:
                    node.children.append(ParseNode(name=f"Unknown {st.tag}", value=st.value_hex))
    return node

@register(MsgType.ESIM, "BF37")
class BF37Parser:
    """ProfileInstallationResult / EID"""
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        root = ParseNode(name="BF37: ProfileInstallationResult/EID")
        tlvs = parse_ber_tlvs(payload_hex)
        # transactionId under BF27
        for t in tlvs:
            if t.tag == "BF27":
                for st in parse_ber_tlvs(t.value_hex):
                    root.children.append(ParseNode(name="transactionId", value=st.value_hex))
        # NotificationMetadata under BF2F
        for t in tlvs:
            if t.tag == "BF2F":
                meta = ParseNode(name="NotificationMetadata")
                for st in parse_ber_tlvs(t.value_hex):
                    if st.tag == "80":
                        meta.children.append(ParseNode(name="seqNumber", value=st.value_hex))
                    elif st.tag == "81":
                        meta.children.append(ParseNode(name="profileManagementOperation", value=st.value_hex))
                    elif st.tag == "0C":
                        try:
                            meta.children.append(ParseNode(name="notificationAddress", value=bytes.fromhex(st.value_hex).decode('ascii')))
                        except Exception:
                            meta.children.append(ParseNode(name="notificationAddress", value=st.value_hex))
                    elif st.tag == "5A":
                        meta.children.append(ParseNode(name="iccid", value=parse_iccid(st.value_hex)))
                root.children.append(meta)
        # smdpOid (tag sequence 06 len ...)
        for i,t in enumerate(tlvs):
            if t.tag == "06":  # OBJECT IDENTIFIER
                root.children.append(ParseNode(name="smdpOid", value=t.value_hex))
        # finalResult A0/A1 etc
        for t in tlvs:
            if t.tag in ("A0","A1"):
                result = ParseNode(name="finalResult", value=("Installation success" if t.tag=="A0" else "InstallationFail"))
                sub = parse_ber_tlvs(t.value_hex)
                # attempt to read AID and peStatus inside
                for st in sub:
                    if st.tag == "4F":
                        result.children.append(ParseNode(name="AID", value=st.value_hex))
                    elif st.tag == "30" or st.tag=="A3":
                        result.children.append(_parse_euicc_response(st.value_hex))
                root.children.append(result)
        # Fallback: If none, just show raw TLVs
        if not root.children:
            for t in tlvs:
                root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))
        return root
