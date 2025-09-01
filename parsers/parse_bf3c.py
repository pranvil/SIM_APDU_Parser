from .tlv_utils import parse_ber_tlv, dump_ber_tlv

TITLE = "EuiccConfiguredData"

def parse_bf3c(raw_hex: str) -> str:
    try:
        items, _ = parse_ber_tlv(raw_hex)
        lines = [f"EuiccConfiguredData (BF3C)", ""]
        lines.extend(dump_ber_tlv(items))
        return "\n".join(lines)
    except Exception as e:
        return f"EuiccConfiguredData 解析失败: {e}\nRAW:\n{raw_hex}"
