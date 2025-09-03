from core.models import MsgType, ParseNode
from core.registry import register
from core.tlv import parse_ber_tlvs

def _parse_bitstring(hexv: str, names):
    if len(hexv) < 2:
        return []
    unused = int(hexv[0:2], 16)
    bits = bin(int(hexv[2:] or "0", 16))[2:].zfill(max(0, (len(hexv) - 2) // 2 * 8))
    if unused > 0:
        bits = bits[:-unused] if unused <= len(bits) else ""
    bits = bits[::-1]  # LSB first
    out = []
    for i, nm in enumerate(names):
        val = "Support" if i < len(bits) and bits[i] == "1" else "Not Support"
        out.append((nm, val))
    return out

def _decode_utf8(hexv: str) -> str:
    try:
        return bytes.fromhex(hexv).decode("utf-8")
    except Exception:
        return hexv

def _decode_bool(hexv: str) -> str:
    # DER BOOLEAN: '00' = FALSE, any non-zero = TRUE
    try:
        return "True" if int(hexv or "00", 16) != 0 else "False"
    except Exception:
        return hexv

def _parse_session_context(hexv: str) -> ParseNode:
    grp = ParseNode(name="SessionContext")
    for t in parse_ber_tlvs(hexv):
        if t.tag == "80":       # serverSvn [0] VersionType
            grp.children.append(ParseNode(name="serverSvn", value=t.value_hex))
        elif t.tag == "81":     # crlStaplingV3Used [1] BOOLEAN
            grp.children.append(ParseNode(name="crlStaplingV3Used", value=_decode_bool(t.value_hex)))
        elif t.tag == "82":     # euiccCiPKIdToBeUsedV3 [2] SubjectKeyIdentifier
            grp.children.append(ParseNode(name="euiccCiPKIdToBeUsedV3", value=t.value_hex))
        elif t.tag == "A3":     # supportedPushServices [3] SEQUENCE OF OBJECT IDENTIFIER
            oids = ParseNode(name="supportedPushServices")
            for st in parse_ber_tlvs(t.value_hex):
                if st.tag == "06":  # OBJECT IDENTIFIER (raw)
                    oids.children.append(ParseNode(name="OID", value=st.value_hex))
                else:
                    oids.children.append(ParseNode(name=f"Unknown {st.tag}", value=st.value_hex))
            grp.children.append(oids)
        else:
            grp.children.append(ParseNode(name=f"Unknown {t.tag}", value=t.value_hex))
    return grp

def _parse_server_signed1(hexv: str) -> ParseNode:
    grp = ParseNode(name="serverSigned1")
    for t in parse_ber_tlvs(hexv):
        if t.tag == "80":       # transactionId [0] TransactionId
            grp.children.append(ParseNode(name="transactionId", value=t.value_hex))
        elif t.tag == "81":     # euiccChallenge [1] Octet16
            grp.children.append(ParseNode(name="euiccChallenge", value=t.value_hex))
        elif t.tag == "83":     # serverAddress [3] UTF8String
            grp.children.append(ParseNode(name="serverAddress", value=_decode_utf8(t.value_hex)))
        elif t.tag == "84":     # serverChallenge [4] Octet16
            grp.children.append(ParseNode(name="serverChallenge", value=t.value_hex))
        elif t.tag == "A5":     # sessionContext [5] SessionContext
            grp.children.append(_parse_session_context(t.value_hex))
        elif t.tag == "86":     # serverRspCapability [6] BIT STRING
            names = ["crlStaplingV3Support", "eventListSigningV3Support",
                     "pushServiceV3Support", "cancelForEmptySpnPnSupport"]
            cap = ParseNode(name="serverRspCapability")
            for nm, val in _parse_bitstring(t.value_hex, names):
                cap.children.append(ParseNode(name=nm, value=val))
            grp.children.append(cap)
        else:
            grp.children.append(ParseNode(name=f"Unknown {t.tag}", value=t.value_hex))
    return grp

def _parse_ctx_params_common_auth(hexv: str) -> ParseNode:
    grp = ParseNode(name="CtxParamsForCommonAuthentication")
    for t in parse_ber_tlvs(hexv):
        if t.tag == "80":  # matchingId [0] UTF8String OPTIONAL
            grp.children.append(ParseNode(name="matchingId", value=_decode_utf8(t.value_hex)))
        elif t.tag == "A1":  # deviceInfo [1] DeviceInfo
            grp.children.append(ParseNode(name="deviceInfo", value=t.value_hex))
        elif t.tag == "82":  # operationType [2] BIT STRING (DEFAULT {profileDownload})
            names = ["profileDownload", "rpm"]
            op = ParseNode(name="operationType")
            for nm, val in _parse_bitstring(t.value_hex, names):
                op.children.append(ParseNode(name=nm, value=val))
            grp.children.append(op)
        elif t.tag == "5A":  # iccid (APPLICATION 26) OPTIONAL
            grp.children.append(ParseNode(name="iccid", value=t.value_hex))
        elif t.tag == "83":  # matchingIdSource [3] CHOICE OPTIONAL (wrapped)
            # 尝试解析内部 CHOICE（none[0] NULL / activationCode[1] NULL / smdsOid[2] OID）
            inner = parse_ber_tlvs(t.value_hex)
            if inner:
                c = inner[0]
                if c.tag == "80":
                    grp.children.append(ParseNode(name="matchingIdSource", value="none"))
                elif c.tag == "81":
                    grp.children.append(ParseNode(name="matchingIdSource", value="activationCode"))
                elif c.tag == "06" or c.tag == "82":
                    # 有的实现可能将 OID 直接作为 UNIVERSAL 06 放入
                    grp.children.append(ParseNode(name="matchingIdSource", value=f"smdsOid:{c.value_hex}"))
                else:
                    grp.children.append(ParseNode(name="matchingIdSource", value=t.value_hex))
            else:
                grp.children.append(ParseNode(name="matchingIdSource", value=t.value_hex))
        elif t.tag == "A4":  # vendorSpecificExtension [4] OPTIONAL
            grp.children.append(ParseNode(name="vendorSpecificExtension", value=t.value_hex))
        else:
            grp.children.append(ParseNode(name=f"Unknown {t.tag}", value=t.value_hex))
    return grp

def _parse_ctx_params_device_change(hexv: str) -> ParseNode:
    grp = ParseNode(name="CtxParamsForDeviceChange")
    iccid_seen = False
    for t in parse_ber_tlvs(hexv):
        if t.tag == "5A" and not iccid_seen:  # iccid Iccid
            grp.children.append(ParseNode(name="iccid", value=t.value_hex))
            iccid_seen = True
        elif t.tag == "A1":  # deviceInfo [1]
            grp.children.append(ParseNode(name="deviceInfo", value=t.value_hex))
        elif t.tag == "5A" and iccid_seen:  # targetEidValue [APPLICATION 26] Octet16 OPTIONAL（部分实现复用 5A）
            grp.children.append(ParseNode(name="targetEidValue", value=t.value_hex))
        elif t.tag == "82":  # targetTacValue [2] Octet4 OPTIONAL
            grp.children.append(ParseNode(name="targetTacValue", value=t.value_hex))
        elif t.tag == "A3":  # vendorSpecificExtension [3] OPTIONAL
            grp.children.append(ParseNode(name="vendorSpecificExtension", value=t.value_hex))
        else:
            grp.children.append(ParseNode(name=f"Unknown {t.tag}", value=t.value_hex))
    return grp

def _parse_ctx_params_profile_recovery(hexv: str) -> ParseNode:
    grp = ParseNode(name="CtxParamsForProfileRecovery")
    for t in parse_ber_tlvs(hexv):
        if t.tag == "5A":      # iccid Iccid
            grp.children.append(ParseNode(name="iccid", value=t.value_hex))
        elif t.tag == "A1":    # deviceInfo [1]
            grp.children.append(ParseNode(name="deviceInfo", value=t.value_hex))
        elif t.tag == "A2":    # vendorSpecificExtension [2] OPTIONAL
            grp.children.append(ParseNode(name="vendorSpecificExtension", value=t.value_hex))
        else:
            grp.children.append(ParseNode(name=f"Unknown {t.tag}", value=t.value_hex))
    return grp

def _parse_ctx_params_push_service(hexv: str) -> ParseNode:
    grp = ParseNode(name="CtxParamsForPushServiceRegistration")
    for t in parse_ber_tlvs(hexv):
        if t.tag == "80":      # selectedPushService [0] OBJECT IDENTIFIER
            grp.children.append(ParseNode(name="selectedPushServiceOID", value=t.value_hex))
        elif t.tag == "81":    # pushToken [1] UTF8String
            grp.children.append(ParseNode(name="pushToken", value=_decode_utf8(t.value_hex)))
        else:
            grp.children.append(ParseNode(name=f"Unknown {t.tag}", value=t.value_hex))
    return grp

def _parse_ctx_params1(hexv: str) -> ParseNode:
    # ctxParams1 外层（自动标签 [5] -> A5），内部为 CHOICE 的一个备选
    grp = ParseNode(name="ctxParams1")
    inner = parse_ber_tlvs(hexv)
    # 常见编码：A0/A1/A2/A3 包一层
    if len(inner) == 1 and inner[0].tag in ("A0", "A1", "A2", "A3"):
        ch = inner[0]
        if ch.tag == "A0":
            grp.children.append(_parse_ctx_params_common_auth(ch.value_hex))
        elif ch.tag == "A1":
            grp.children.append(_parse_ctx_params_device_change(ch.value_hex))
        elif ch.tag == "A2":
            grp.children.append(_parse_ctx_params_profile_recovery(ch.value_hex))
        elif ch.tag == "A3":
            grp.children.append(_parse_ctx_params_push_service(ch.value_hex))
        return grp
    # 兼容：直接展开为 CommonAuthentication 的字段（少数实现）
    # 若未包裹，则按 common-auth 尝试解析
    grp.children.append(_parse_ctx_params_common_auth(hexv))
    return grp

@register(MsgType.ESIM, "BF38")
class BF38Parser:
    """AuthenticateServerRequest"""
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        root = ParseNode(name="BF38: AuthenticateServerRequest")
        for t in parse_ber_tlvs(payload_hex):
            if t.tag == "A0":             # serverSigned1  (AUTOMATIC TAGS -> [0])
                root.children.append(_parse_server_signed1(t.value_hex))
            elif t.tag == "5F37":         # serverSignature1 [APPLICATION 55] OCTET STRING
                root.children.append(ParseNode(name="serverSignature1", value=t.value_hex))
            elif t.tag == "83":           # euiccCiPKIdToBeUsed  (AUTOMATIC TAGS -> [3])
                root.children.append(ParseNode(name="euiccCiPKIdToBeUsed", value=t.value_hex))
            elif t.tag == "A4":           # serverCertificate  (AUTOMATIC TAGS -> [4]) X.509
                root.children.append(ParseNode(name="serverCertificate", value=t.value_hex))
            elif t.tag == "A5":           # ctxParams1  (AUTOMATIC TAGS -> [5]) CHOICE
                root.children.append(_parse_ctx_params1(t.value_hex))
            elif t.tag == "A1":           # otherCertsInChain [1] CertificateChain OPTIONAL
                chain = ParseNode(name="otherCertsInChain")
                # 通常内部是一系列 X.509 Certificate (UNIVERSAL 30)
                for st in parse_ber_tlvs(t.value_hex):
                    chain.children.append(ParseNode(name=f"Certificate {len(chain.children)+1}", value=st.value_hex, hint=st.tag))
                root.children.append(chain)
            elif t.tag == "A2":           # crlList [2] SEQUENCE OF CertificateList OPTIONAL
                crls = ParseNode(name="crlList")
                for st in parse_ber_tlvs(t.value_hex):
                    crls.children.append(ParseNode(name=f"CRL {len(crls.children)+1}", value=st.value_hex, hint=st.tag))
                root.children.append(crls)
            else:
                root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))
        return root
