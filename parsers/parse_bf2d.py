from utils import parse_iccid, hex_to_utf8

def parse_bf2d(apdu_data: str) -> str:
    """
    ProfileInfo（BF2D）统一解析：
      - 若包含 E3（响应侧，ESIM=>LPA），逐个 profile 块解析（旧逻辑保留）。
      - 若不包含 E3（请求侧，LPA=>ESIM），调用 ProfileInfoListRequest 解析：
            支持 searchCriteria(4F/5A/95) 与可选 tagList(5C)。
    说明：传入的 apdu_data 应该从 BF2D 的 Value 开始（上层已剥掉 STORE DATA 的 5 字节头）。
    """
    s = apdu_data.upper().replace(" ", "")
    if "E3" in s:
        # === Response 风格：包含 E3（每个 profile 一个 E3 块）===
        output = "ProfileInfo（BF2D）\n"
        e3_index = s.find("E3")
        length = len(s[e3_index:])
        index = e3_index
        profile_id = 1
        while index < len(s):
            if s[index:index+2] == "E3":
                output += f"\t==== profile: {profile_id} ====\n"
                e3_length = int(s[index+2:index+4], 16)
                e3_data = s[index+4:index+4+e3_length*2]
                output += profileInfoList_parse(e3_data, e3_length * 2)
                index += 2
                index += e3_length * 2
                profile_id += 1
            else:
                index += 2
        return output
    else:
        # === Request 风格：不含 E3，解析 ProfileInfoListRequest ===
        return ProfileInfoListRequest(s)


def _read_tlv(buf: str, idx: int):
    """读取一个 BER-TLV，返回 (tag, length, value_hex, next_idx)。
       支持一字节(如 '5A')与两字节标签(如 '9F70'/'BF22')。
    """
    n = len(buf)
    if idx + 2 > n:
        return None, 0, "", idx
    tag = buf[idx:idx+2]
    if tag in ("9F", "BF"):
        if idx + 4 > n:
            return None, 0, "", idx
        tag = buf[idx:idx+4]
        idx += 4
    else:
        idx += 2
    if idx + 2 > n:
        return tag, 0, "", idx
    L = int(buf[idx:idx+2], 16)
    idx += 2
    vlen = L * 2
    val = buf[idx:idx+vlen] if idx+vlen <= n else buf[idx:]
    idx += vlen
    return tag, L, val, idx


def _parse_taglist_hex(taglist_hex: str):
    """
    解析 ProfileInfoListRequest 的 tagList（5C 的值，OCTET STRING），
    其中元素为 tag 编码序列：
      - 单字节标签：如 '5A','90','91','92','93','94','95','99','B6','B7','B8'
      - 双字节标签：以 '9F' 或 'BF' 开头，如 '9F70','BF76'
    返回 [(tag, meaning)] 列表。
    """
    s = taglist_hex.upper().replace(" ", "")
    idx = 0
    n = len(s)

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

    results = []
    while idx < n:
        if idx + 2 > n:
            break
        first_octet = s[idx:idx+2]
        if first_octet in ("9F", "BF"):
            if idx + 4 > n:
                break
            tag = s[idx:idx+4]
            idx += 4
        else:
            tag = first_octet
            idx += 2
        meaning = tag_meaning_map.get(tag, "Unknown")
        results.append((tag, meaning))
    return results


def ProfileInfoListRequest(apdu_hex: str) -> str:
    """
    按标准解析 ProfileInfoListRequest（BF2D 请求）：
      searchCriteria [0] CHOICE { isdpAid('4F') | iccid('5A') | profileClass('95') } 可选
      tagList        [APPLICATION 28] OCTET STRING 可选 -- tag '5C'
    传入 hex 字符串可以是：
      - 直接以 'BF2D...' 起头（外层 TLV），或
      - 从 BF2D 的 value 开始（大部分情况下是这种）。
    """
    s = apdu_hex.upper().replace(" ", "")
    # 若有外层 BF2D，先进入其 value
    if s.startswith("BF2D"):
        _tag0, L0, value0, _ = _read_tlv(s, 0)
        s = value0
        # 特殊处理：规范要求 'BF2D 00' 表示获取所有已安装 Profile 的默认 ProfileInfo
        if L0 == 0:
            return "ProfileInfoListRequest（BF2D）\n\tRetrieve the default ProfileInfo for all installed Profiles"

    out = ["ProfileInfoListRequest（BF2D）"]
    idx = 0
    n = len(s)

    # 逐个 TLV 读取：支持 4F / 5A / 95 / 5C
    while idx < n:
        tag, L, val, idx = _read_tlv(s, idx)
        if not tag:
            break
        if tag == "4F":
            out.append(f"\tsearchCriteria.isdpAid（4F）: {val}")
        elif tag == "5A":
            out.append(f"\tsearchCriteria.iccid（5A）: {parse_iccid(val)}")
        elif tag == "95":
            mapping = {"00": "test", "01": "provisioning", "02": "operational"}
            out.append(f"\tsearchCriteria.profileClass（95）: {mapping.get(val, 'Unknown')}")
        elif tag == "5C":
            out.append(f"\ttagList（5C）: {val}")
            pairs = _parse_taglist_hex(val)
            if pairs:
                for t, meaning in pairs:
                    out.append(f"\t  - {t}: {meaning}")
        else:
            out.append(f"\t未识别的 TLV {tag}: {val}")

    if len(out) == 1:
        out.append("\t（内容为空或非预期结构）")
    return "\n".join(out)


def profileInfoList_parse(apdu_data: str, length: int) -> str:
    output = ""
    index = 0
    while index < length:
        tag = apdu_data[index:index+2]
        if tag == "9F" or tag == "BF":
            tag = apdu_data[index:index+4]
            index += 4  # skip tag
            length_byte = int(apdu_data[index:index+2], 16)
        else:
            index += 2  # skip tag
            length_byte = int(apdu_data[index:index+2], 16)
        index += 2  # skip length
        value = apdu_data[index:index + (length_byte * 2)]
        index += length_byte * 2

        if tag == "5A":
            iccid = parse_iccid(value)
            output += f"\ticcid：{iccid}\n"
        elif tag == "4F":
            output += f"\tSD-P AID：{value}\n"
        elif tag == "9F70":
            if value == "00":
                output += f"\tProfile state：Disabled\n"
            elif value == "01":
                output += f"\tProfile state：Enabled\n"
            else:
                output += f"\tProfile state：Unknown\n"
        elif tag == "90":
            profile_nickname = hex_to_utf8(value)
            output += f"\tProfile Nickname：{profile_nickname}\n"
        elif tag == "91":
            service_provider_name = hex_to_utf8(value)
            output += f"\tService provider name：{service_provider_name}\n"
        elif tag == "92":
            profile_name = hex_to_utf8(value)
            output += f"\tProfile name：{profile_name}\n"
        elif tag == "93":
            output += f"\tIcon type：{value}\n"
        elif tag == "94":
            output += f"\tIcon: {value}\n"
        elif tag == "95":
            if value == "00":
                output += f"\tProfile Class：test\n"
            elif value == "01":
                output += f"\tProfile Class：provisioning\n"
            elif value == "02":
                output += f"\tProfile Class：operational\n"
            else:
                output += f"\tProfile Class：Unknown\n"
        elif tag == "B6":
            output += f"\tNotification Configuration Info：{value}\n"
        elif tag == "B7":
            output += f"\tProfile Owner：{value}\n"
        elif tag == "B8":
            output += f"\tSM-DP+ proprietary data：{value}\n"
        elif tag == "99":
            output += f"\tProfile Policy Rules：{value}\n"
        elif tag == "BF22":
            output += f"\tService Specific Data stored in eUICC：{value}\n"
        elif tag == "BA":
            output += f"\tRPM Configuration：{value}\n"
        elif tag == "9B":
            hri_server_address = hex_to_utf8(value)
            output += f"\tHRI Server address：{hri_server_address}\n"
        elif tag == "BC":
            output += f"\tLPR Configuration：{value}\n"
        elif tag == "BD":
            output += f"\tEnterprise Configuration：{value}\n"
        elif tag == "9F1F":
            output += f"\tService Description：{value}\n"
        elif tag == "BF20":
            output += f"\tDevice Change configuration：{value}\n"
        elif tag == "9F24":
            output += f"\tEnabled on eSIM Port：{value}\n"
        elif tag == "9F25":
            output += f"\tProfile Size：{value}\n"
        else:
            output += f"Unknown Tag {tag}: {value}\n"

    return output
