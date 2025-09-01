from .tlv_utils import parse_ber_tlv, dump_ber_tlv

TITLE = "AuthenticateClient"

def parse_bf3b(raw_hex: str) -> str:
    try:
        items, _ = parse_ber_tlv(raw_hex)
        lines = [f"AuthenticateClient (BF3B)", ""]
        lines.extend(dump_ber_tlv(items))
        return "\n".join(lines)
    except Exception as e:
        return f"AuthenticateClient 解析失败: {e}\nRAW:\n{raw_hex}"
