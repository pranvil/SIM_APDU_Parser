
from typing import Optional
from parsers import get_parser

def _strip_store_data_header_if_needed(raw_hex: str) -> str:
    """If raw_hex is STORE DATA (CLA=80-83/C0-CF, INS=E2), remove 5-byte header and return TLV body."""
    hexpairs = [raw_hex[i:i+2] for i in range(0, len(raw_hex), 2)]
    if len(hexpairs) < 5:
        return raw_hex
    try:
        cla = int(hexpairs[0], 16)
        ins = int(hexpairs[1], 16)
    except Exception:
        return raw_hex
    if ((0x80 <= cla <= 0x83) or (0xC0 <= cla <= 0xCF)) and ins == 0xE2:
        return ''.join(hexpairs[5:]).upper()
    return raw_hex

def parse_esim_store_data(tag: str, raw_hex: str) -> str:
    """
    对 LPA=>ESIM 的 STORE DATA 请求：自动剥掉前 5 字节（CLA/INS/P1/P2/Lc），
    然后交给与响应侧相同的 BFxx 解析器解析 TLV。
    """
    body_hex = _strip_store_data_header_if_needed(raw_hex)
    if not tag:
        return "（暂无解析器）\n" + body_hex

    parser = get_parser(tag.lower())
    if parser is None:
        return "（暂无解析器）\n" + body_hex

    try:
        return parser(body_hex.strip())
    except Exception as e:
        return f"解析 {tag} 时出错: {e}\n\nRAW:\n{raw_hex}"

def parse_esim_detail(tag: str, raw_hex: str) -> str:
    """
    Dispatch to the eSIM BFxx parser if available.
    Returns a human-readable multiline string.
    """
    if not tag:
        return "（暂无解析器）\n" + raw_hex

    parser = get_parser(tag.lower())  # expects like 'bf22'
    if parser is None:
        return "（暂无解析器）\n" + raw_hex

    try:
        return parser(raw_hex.strip())
    except Exception as e:
        return f"解析 {tag} 时出错: {e}\n\nRAW:\n{raw_hex}"
