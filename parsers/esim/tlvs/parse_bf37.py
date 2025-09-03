from core.models import MsgType, ParseNode
from core.registry import register
from core.tlv import parse_ber_tlvs
from core.utils import parse_iccid


def _parse_notification_event_bits(bitstring_hex: str):
    # 返回 ([(event_name, "Requested"/"Not Requested")], requested_count)
    if not bitstring_hex or len(bitstring_hex) < 2 or len(bitstring_hex) % 2 != 0:
        return [], 0
    unused = int(bitstring_hex[:2], 16)
    value_hex = bitstring_hex[2:]
    if not (0 <= unused <= 7) or not value_hex:
        return [], 0
    n_bits_total = len(value_hex) * 4
    bit_len = n_bits_total - unused
    if bit_len < 0:
        return [], 0
    last_byte = int(value_hex[-2:], 16)
    if unused and (last_byte & ((1 << unused) - 1)) != 0:
        # 非法编码：未用位非 0
        return [], 0

    bit_value = int(value_hex, 16)
    bits = bin(bit_value)[2:].zfill(n_bits_total)
    bits = bits[:bit_len]  # 去掉未用位
    event_types = [
        "notificationInstall",       # bit 0
        "notificationLocalEnable",   # bit 1
        "notificationLocalDisable",  # bit 2
        "notificationLocalDelete",   # bit 3
        "notificationRpmEnable",     # bit 4
        "notificationRpmDisable",    # bit 5
        "notificationRpmDelete",     # bit 6
        "loadRpmPackageResult",      # bit 7
    ]
    rows, cnt = [], 0
    for i, name in enumerate(event_types):
        b = bits[i] if i < len(bits) else '0'
        if b == '1':
            cnt += 1
        rows.append((name, "Requested" if b == '1' else "Not Requested"))
    return rows, cnt


def _parse_euicc_response(ppi_hex: str) -> ParseNode:
    """解析EUICCResponse：
    - 先用 BER 解析，支持 A0..AF 容器以及其中再套 SEQUENCE(30)；
    - 任意层级递归提取 80(status) 与 81(identification number)；
    - 失败再回退到旧的逐字节解析。
    """
    node = ParseNode(name="peStatus")
    s = "".join(ppi_hex.split())

    status_map = {
        0: "ok", 1: "pe-not-supported", 2: "memory-failure", 3: "bad-values",
        4: "not-enough-memory", 5: "invalid-request-format", 6: "invalid-parameter",
        7: "runtime-not-supported", 8: "lib-not-supported", 9: "template-not-supported",
        10: "feature-not-supported", 11: "pin-code-missing", 31: "unsupported-profile-version"
    }

    def _emit_status(val_hex: str):
        try:
            v = int(val_hex, 16)
            node.children.append(ParseNode(name="status", value=f"{status_map.get(v, 'Unknown Status')}({v})"))
        except ValueError:
            node.children.append(ParseNode(name="status", value=f"parse_error({val_hex})"))

    def _emit_ident(val_hex: str):
        try:
            v = int(val_hex, 16)
            node.children.append(ParseNode(name="identification number", value=str(v)))
        except ValueError:
            node.children.append(ParseNode(name="identification number", value=val_hex))

    def _walk_ppi_tlvs(tlvs_list):
        """递归下钻任何层级的 30/A0..AF，抽取 80/81；其它保留为 Unknown。"""
        for x in tlvs_list:
            tag = x.tag
            if tag == "80":
                _emit_status(x.value_hex)
            elif tag == "81":
                _emit_ident(x.value_hex)
            elif tag == "30":
                _walk_ppi_tlvs(parse_ber_tlvs(x.value_hex))
            elif tag and tag[0] in "Aa":  # A0..AF：ctx-specific constructed 容器
                _walk_ppi_tlvs(parse_ber_tlvs(x.value_hex))
            else:
                node.children.append(ParseNode(name=f"Unknown {tag}", value=x.value_hex[:120]))

    # ---------- 首选：BER 解析 ----------
    try:
        tlvs = parse_ber_tlvs(s)
        if tlvs:
            _walk_ppi_tlvs(tlvs)
            # 如果确实解出了 status/ident，就返回
            if any(c.name in ("status", "identification number") for c in node.children):
                return node
    except Exception:
        # 继续走回退
        pass

    # ---------- 回退：旧的逐字节解析（兼容少见厂商格式） ----------
    length = len(s)
    index = 0
    if length > 8:
        index = 8  # 兼容某些实现的头部
    while index < length:
        if index + 2 > length:
            break
        tag = s[index:index+2]; index += 2
        if index + 2 > length:
            break
        length_byte = int(s[index:index+2], 16); index += 2
        if length_byte == 0:
            node.children.append(ParseNode(name="profileInstallationAborted", value="true"))
            continue
        if index + length_byte * 2 > length:
            break
        value = s[index:index + (length_byte * 2)]
        index += length_byte * 2

        if tag == "30":  # SEQUENCE
            inner_index = 0
            inner_length = length_byte * 2
            while inner_index < inner_length:
                if inner_index + 2 > inner_length:
                    break
                inner_tag = value[inner_index:inner_index+2]; inner_index += 2
                if inner_index + 2 > inner_length:
                    break
                inner_len = int(value[inner_index:inner_index+2], 16); inner_index += 2
                if inner_index + inner_len * 2 > inner_length:
                    break
                inner_val = value[inner_index:inner_index + (inner_len * 2)]
                inner_index += inner_len * 2

                if inner_tag == "80":
                    _emit_status(inner_val)
                elif inner_tag == "81":
                    _emit_ident(inner_val)
                else:
                    node.children.append(ParseNode(name=f"Unknown {inner_tag}", value=inner_val))
        else:
            node.children.append(ParseNode(name=f"Unknown {tag}", value=value))

    return node


def _parse_notification_metadata(metadata_hex: str) -> ParseNode:
    """解析NotificationMetadata"""
    meta = ParseNode(name="NotificationMetadata")
    tlvs = parse_ber_tlvs(metadata_hex)

    for t in tlvs:
        if t.tag == "80":  # seqNumber [0] INTEGER
            try:
                seq_num = int(t.value_hex, 16)
                meta.children.append(ParseNode(name="seqNumber", value=str(seq_num)))
            except ValueError:
                meta.children.append(ParseNode(name="seqNumber", value=t.value_hex))

        elif t.tag == "81":  # profileManagementOperation [1] NotificationEvent (BIT STRING)
            op_node = ParseNode(name="profileManagementOperation")
            rows, cnt = _parse_notification_event_bits(t.value_hex)
            if rows:
                for name, status in rows:
                    op_node.children.append(ParseNode(name=name, value=status))
                if cnt != 1:
                    op_node.hint = f"Spec: Only one bit SHALL be set to 1, observed={cnt}"
            else:
                op_node.children.append(ParseNode(name="parse-error", value=t.value_hex))
            meta.children.append(op_node)

        elif t.tag == "0C":  # notificationAddress UTF8String
            try:
                address = bytes.fromhex(t.value_hex).decode('utf-8')
                meta.children.append(ParseNode(name="notificationAddress", value=address))
            except Exception:
                meta.children.append(ParseNode(name="notificationAddress", value=t.value_hex))

        elif t.tag == "5A":  # iccid Iccid
            iccid = parse_iccid(t.value_hex)
            meta.children.append(ParseNode(name="iccid", value=iccid))

        else:
            meta.children.append(ParseNode(name=f"Field {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))

    return meta


def _parse_success_result(success_hex: str) -> ParseNode:
    """解析SuccessResult"""
    result = ParseNode(name="SuccessResult")
    tlvs = parse_ber_tlvs(success_hex)

    for t in tlvs:
        if t.tag == "4F":  # aid [APPLICATION 15] OCTET STRING
            result.children.append(ParseNode(name="aid", value=t.value_hex))
        elif t.tag == "04":  # ppiResponse OCTET STRING
            # 解析EUICCResponse（支持 A0..AF 容器 + 多个 SEQUENCE）
            ppi_node = _parse_euicc_response(t.value_hex)
            result.children.append(ppi_node)
        else:
            result.children.append(ParseNode(name=f"Unknown {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))

    return result


def _parse_error_result(error_hex: str) -> ParseNode:
    """解析ErrorResult"""
    result = ParseNode(name="ErrorResult")
    tlvs = parse_ber_tlvs(error_hex)

    bpp_command_map = {
        0: "initialiseSecureChannel", 1: "configureISDP", 2: "storeMetadata",
        3: "storeMetadata2", 4: "replaceSessionKeys", 5: "loadProfileElements"
    }
    error_reason_map = {
        1: "incorrectInputValues", 2: "invalidSignature", 3: "invalidTransactionId",
        4: "unsupportedCrtValues", 5: "unsupportedRemoteOperationType", 6: "unsupportedProfileClass",
        7: "bspStructureError", 8: "bspSecurityError", 9: "installFailedDueToIccidAlreadyExistsOnEuicc",
        10: "installFailedDueToInsufficientMemoryForProfile", 11: "installFailedDueToInterruption",
        12: "installFailedDueToPEProcessingError", 13: "installFailedDueToDataMismatch",
        14: "testProfileInstallFailedDueToInvalidNaaKey", 15: "pprNotAllowed",
        17: "enterpriseProfilesNotSupported", 18: "enterpriseRulesNotAllowed",
        19: "enterpriseProfileNotAllowed", 20: "enterpriseOidMismatch",
        21: "enterpriseRulesError", 22: "enterpriseProfilesOnly", 23: "lprNotSupported",
        26: "unknownTlvInMetadata", 127: "installFailedDueToUnknownError"
    }

    saw_cmd = False
    for t in tlvs:
        if t.tag == "02":  # INTEGER：先 bppCommandId，后 errorReason
            try:
                val = int(t.value_hex, 16)
                if not saw_cmd:
                    saw_cmd = True
                    cmd_name = bpp_command_map.get(val, f"Unknown({val})")
                    result.children.append(ParseNode(name="bppCommandId", value=f"{cmd_name}({val})"))
                else:
                    reason_name = error_reason_map.get(val, f"Unknown({val})")
                    result.children.append(ParseNode(name="errorReason", value=f"{reason_name}({val})"))
            except ValueError:
                result.children.append(ParseNode(name="INTEGER", value=t.value_hex))

        elif t.tag == "04":  # ppiResponse OCTET STRING OPTIONAL
            ppi_node = _parse_euicc_response(t.value_hex)
            result.children.append(ppi_node)

        else:
            result.children.append(ParseNode(name=f"Unknown {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))

    return result


@register(MsgType.ESIM, "BF37")
class BF37Parser:
    """ProfileInstallationResult - 根据ASN定义重写"""
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        root = ParseNode(name="BF37: ProfileInstallationResult")
        tlvs = parse_ber_tlvs(payload_hex)

        # ProfileInstallationResult ::= [55] SEQUENCE
        for t in tlvs:
            if t.tag == "BF27":  # profileInstallationResultData [39]
                data_node = ParseNode(name="profileInstallationResultData")
                inner_tlvs = parse_ber_tlvs(t.value_hex)

                for st in inner_tlvs:
                    if st.tag == "80":  # transactionId [0] TransactionId
                        data_node.children.append(ParseNode(name="transactionId", value=st.value_hex))
                    elif st.tag == "BF2F":  # notificationMetadata [47] NotificationMetadata
                        meta = _parse_notification_metadata(st.value_hex)
                        data_node.children.append(meta)
                    elif st.tag == "06":  # smdpOid OBJECT IDENTIFIER
                        data_node.children.append(ParseNode(name="smdpOid", value=st.value_hex))
                    elif st.tag == "A2":  # finalResult [2] CHOICE
                        final_result = ParseNode(name="finalResult")
                        choice_tlvs = parse_ber_tlvs(st.value_hex)

                        for ct in choice_tlvs:
                            if ct.tag == "A0":  # successResult
                                success = _parse_success_result(ct.value_hex)
                                final_result.children.append(success)
                            elif ct.tag == "A1":  # errorResult
                                error = _parse_error_result(ct.value_hex)
                                final_result.children.append(error)
                            else:
                                final_result.children.append(ParseNode(
                                    name=f"Unknown choice {ct.tag}",
                                    value=f"len={ct.length}",
                                    hint=ct.value_hex[:120]
                                ))
                        data_node.children.append(final_result)
                    else:
                        data_node.children.append(ParseNode(
                            name=f"Unknown {st.tag}",
                            value=f"len={st.length}",
                            hint=st.value_hex[:120]
                        ))

                root.children.append(data_node)

            elif t.tag == "5F37":  # euiccSignPIR [APPLICATION 55] OCTET STRING
                root.children.append(ParseNode(name="euiccSignPIR", value=t.value_hex, hint="eUICC signature"))
            else:
                # 兜底：显示未知TLV
                root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))

        # 如果没有解析到任何内容，显示原始TLV
        if not root.children:
            for t in tlvs:
                root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))

        return root
