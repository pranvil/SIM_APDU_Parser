
from typing import Optional
from core.models import Message, ParseResult, MsgType, ParseNode, Apdu
from core.utils import parse_apdu_header
from core.tlv import parse_ber_tlvs
from core.registry import resolve

class IParser:
    def parse(self, msg: Message) -> ParseResult:
        raise NotImplementedError

class ProactiveParser(IParser):
    def parse(self, msg: Message) -> ParseResult:
        hdr = parse_apdu_header(msg.raw)
        direction = "TERMINAL=>UICC" if hdr.cla == 0x80 else "UICC=>TERMINAL"
        
        # Determine the command type and extract payload
        if msg.raw.startswith("D0"):
            # UICC => TERMINAL: D0 command
            payload = msg.raw[2:]  # Remove D0 prefix
            if len(payload) >= 2:
                length = int(payload[:2], 16)
                if len(payload) >= 2 + 2 * length:
                    payload = payload[2:2 + 2 * length]  # Extract actual payload
            handler_cls = resolve(MsgType.PROACTIVE, "D0")
            if handler_cls:
                handler = handler_cls()
                root = handler.build(payload, direction)
            else:
                root = ParseNode(name="Proactive UICC (D0)", value=msg.raw)
        elif hdr.cla == 0x80 and hdr.ins == 0x14:
            # TERMINAL RESPONSE
            payload = msg.raw[10:] if len(msg.raw) > 10 else ""  # Skip APDU header
            handler_cls = resolve(MsgType.PROACTIVE, "TERMINAL_RESPONSE")
            if handler_cls:
                handler = handler_cls()
                root = handler.build(payload, direction)
            else:
                root = ParseNode(name="TERMINAL RESPONSE (80 14)", value=msg.raw)
        elif hdr.cla == 0x80 and hdr.ins == 0xC2:
            # ENVELOPE
            payload = msg.raw[10:] if len(msg.raw) > 10 else ""  # Skip APDU header
            handler_cls = resolve(MsgType.PROACTIVE, "ENVELOPE")
            if handler_cls:
                handler = handler_cls()
                root = handler.build(payload, direction)
            else:
                root = ParseNode(name="ENVELOPE (80 C2)", value=msg.raw)
        else:
            # Other proactive commands (TERMINAL PROFILE, FETCH, etc.)
            name = "Proactive"
            if hdr.cla == 0x80 and hdr.ins == 0x10: name = "TERMINAL PROFILE (80 10)"
            elif hdr.cla == 0x80 and hdr.ins == 0x12: name = "FETCH (80 12)"
            root = ParseNode(name=name, value=msg.raw)
        
        # Use the detailed title from the parsed root node
        detailed_title = root.name
        return ParseResult(msg_type=MsgType.PROACTIVE, message=msg, apdu=hdr, root=root,
                           title=detailed_title, direction_hint=direction)

from parsers.esim import *  # ensure registration
from parsers.proactive import *  # ensure registration

class EsimParser(IParser):
    def parse(self, msg: Message) -> ParseResult:
        hdr = parse_apdu_header(msg.raw)
        direction = "ESIM=>LPA" if msg.raw.startswith("BF") else "LPA=>ESIM"
        # Compute body & top-level tag
        body = msg.raw
        if hdr and hdr.ins == 0xE2 and len(body) >= 10:
            body = body[10:]  # strip 5-byte header
        tlvs = parse_ber_tlvs(body)
        root = ParseNode(name="eSIM")
        if tlvs:
            top = tlvs[0]
            handler_cls = resolve(MsgType.ESIM, top.tag)
            if handler_cls:
                handler = handler_cls()
                root = handler.build(top.value_hex, direction)
            else:
                # default: list TLVs
                root = ParseNode(name=f"Unknown eSIM container {top.tag}")
                for t in tlvs:
                    root.children.append(ParseNode(name=f"TLV {t.tag}", value=f"len={t.length}", hint=t.value_hex[:120]))
        else:
            root = ParseNode(name="eSIM (empty)")
        return ParseResult(msg_type=MsgType.ESIM, message=msg, apdu=hdr, root=root,
                           title="eSIM APDU", direction_hint=direction)


class NormalSimParser(IParser):
    def parse(self, msg: Message) -> ParseResult:
        hdr = parse_apdu_header(msg.raw)
        name = f"SIM APDU INS={hdr.ins:02X}" if hdr.ins is not None else "SIM APDU"
        root = ParseNode(name=name, value=msg.raw)
        return ParseResult(msg_type=MsgType.NORMAL_SIM, message=msg, apdu=hdr, root=root,
                           title=name, direction_hint="UNKNOWN")
