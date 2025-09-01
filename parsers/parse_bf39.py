from .tlv_utils import parse_ber_tlv, dump_ber_tlv

TITLE = "InitiateAuthentication"

def parse_bf39(raw_hex: str) -> str:
    try:
        items, _ = parse_ber_tlv(raw_hex)
        lines = [f"InitiateAuthentication (BF39)", ""]
        lines.extend(dump_ber_tlv(items))
        return "\n".join(lines)
    except Exception as e:
        return f"InitiateAuthentication 解析失败: {e}\nRAW:\n{raw_hex}"
