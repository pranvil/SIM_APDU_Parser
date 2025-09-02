
from core.models import MsgType, ParseNode
from core.registry import register
from core.tlv import parse_ber_tlvs

def _parse_bitstring(hexv: str, names):
    # First octet = number of unused bits
    if len(hexv) < 2:
        return []
    unused = int(hexv[0:2], 16)
    bits = bin(int(hexv[2:] or "0", 16))[2:].zfill(max(0,(len(hexv)-2)//2*8))
    if unused > 0:
        bits = bits[:-unused] if unused <= len(bits) else ""
    bits = bits[::-1]  # LSB -> index 0
    out = []
    for i, nm in enumerate(names):
        val = "Support" if i < len(bits) and bits[i] == "1" else "Not Support"
        out.append((nm, val))
    return out

@register(MsgType.ESIM, "BF22")
class BF22Parser:
    """GetEuiccInfo2"""
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        root = ParseNode(name="BF22: GetEuiccInfo2")
        tlvs = parse_ber_tlvs(payload_hex)
        for t in tlvs:
            if t.tag == "81":
                root.children.append(ParseNode(name="baseProfilePackageVersion", value=t.value_hex))
            elif t.tag == "82":
                root.children.append(ParseNode(name="lowestSvn", value=t.value_hex))
            elif t.tag == "83":
                root.children.append(ParseNode(name="euiccFirmwareVersion", value=t.value_hex))
            elif t.tag == "84":
                grp = ParseNode(name="extCardResource")
                for st in parse_ber_tlvs(t.value_hex):
                    if st.tag == "81":
                        grp.children.append(ParseNode(name="Number of installed application", value=st.value_hex))
                    elif st.tag == "82":
                        grp.children.append(ParseNode(name="Available ROM (bytes)", value=str(int(st.value_hex,16))))
                    elif st.tag == "83":
                        grp.children.append(ParseNode(name="Available RAM (bytes)", value=str(int(st.value_hex,16))))
                    else:
                        grp.children.append(ParseNode(name=f"Unknown {st.tag}", value=st.value_hex))
                root.children.append(grp)
            elif t.tag == "85":
                names = ["contactlessSupport","usimSupport","isimSupport","csimSupport",
                         "akaMilenage","akaCave","akaTuak128","akaTuak256",
                         "usimTestAlgorithm","rfu2","gbaAuthenUsim","gbaAuthenISim",
                         "mbmsAuthenUsim","eapClient","javacard","multos",
                         "multipleUsimSupport","multipleIsimSupport","multipleCsimSupport",
                         "berTlvFileSupport","dfLinkSupport","catTp","getIdentity",
                         "profile-a-x25519","profile-b-p256","suciCalculatorApi",
                         "dns-resolution","scp11ac","scp11c-authorization-mechanism",
                         "s16mode","eaka","iotminimal"]
                grp = ParseNode(name="UICCCapability")
                for nm, val in _parse_bitstring(t.value_hex, names):
                    grp.children.append(ParseNode(name=nm, value=val))
                root.children.append(grp)
            elif t.tag == "86":
                root.children.append(ParseNode(name="ts102241Version", value=t.value_hex))
            elif t.tag == "87":
                root.children.append(ParseNode(name="globalplatformVersion", value=t.value_hex))
            elif t.tag == "88":
                names = ["additionalProfile","loadCrlSupport","rpmSupport","testProfileSupport",
                         "deviceInfoExtensibilitySupport","serviceSpecificDataSupport","hriServerAddressSupport",
                         "serviceProviderMessageSupport","lpaProxySupport","enterpriseProfilesSupport",
                         "serviceDescriptionSupport","deviceChangeSupport","encryptedDeviceChangeDataSupport",
                         "estimatedProfileSizeIndicationSupport","profileSizeInProfilesInfoSupport",
                         "crlStaplingV3Support","certChainV3VerificationSupport","signedSmdsResponseV3Support",
                         "euiccRspCapInInfo1","osUpdateSupport","cancelForEmptySpnPnSupport",
                         "updateNotifConfigInfoSupport","updateMetadataV3Support"]
                grp = ParseNode(name="euiccRspCapability")
                for nm, val in _parse_bitstring(t.value_hex, names):
                    grp.children.append(ParseNode(name=nm, value=val))
                root.children.append(grp)
            elif t.tag == "A9":
                root.children.append(ParseNode(name="euiccCiPKIdListForVerification", value=t.value_hex))
            elif t.tag == "AA":
                root.children.append(ParseNode(name="euiccCiPKIdListForSigning", value=t.value_hex))
            elif t.tag == "0C":
                try:
                    root.children.append(ParseNode(name="sasAcreditationNumber", value=bytes.fromhex(t.value_hex).decode('utf-8')))
                except Exception:
                    root.children.append(ParseNode(name="sasAcreditationNumber", value=t.value_hex))
            elif t.tag == "AC":
                grp = ParseNode(name="certificationDataObject")
                for st in parse_ber_tlvs(t.value_hex):
                    if st.tag == "80":
                        try:
                            grp.children.append(ParseNode(name="platformLabel", value=bytes.fromhex(st.value_hex).decode('utf-8')))
                        except Exception:
                            grp.children.append(ParseNode(name="platformLabel", value=st.value_hex))
                    elif st.tag == "81":
                        try:
                            grp.children.append(ParseNode(name="discoveryBaseURL", value=bytes.fromhex(st.value_hex).decode('utf-8')))
                        except Exception:
                            grp.children.append(ParseNode(name="discoveryBaseURL", value=st.value_hex))
                    else:
                        grp.children.append(ParseNode(name=f"Unknown {st.tag}", value=st.value_hex))
                root.children.append(grp)
            elif t.tag == "99":
                root.children.append(ParseNode(name="forbiddenProfilePolicyRules", value=t.value_hex))
            elif t.tag == "04":
                root.children.append(ParseNode(name="ppVersion", value=t.value_hex))
            else:
                root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))
        return root
