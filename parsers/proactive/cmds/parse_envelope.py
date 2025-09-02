# parsers/proactive/cmds/parse_envelope.py
from core.models import MsgType, ParseNode
from core.registry import register
from parsers.proactive.common import parse_comp_tlvs_to_nodes

@register(MsgType.PROACTIVE, "ENVELOPE")
class EnvelopeParser:
    """TERMINAL => UICC: ENVELOPE (80C2)."""
    def build(self, payload_hex: str, direction: str) -> ParseNode:
        comp_root, first = parse_comp_tlvs_to_nodes(payload_hex)
        title = "Proactive: ENVELOPE" + (f" - {first}" if first else "")
        root = ParseNode(name=title)
        root.children.extend(comp_root.children)
        return root
