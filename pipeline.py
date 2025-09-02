
from typing import List
from core.models import ParseResult, MsgType, Message
from data_io.loaders import load_text
from data_io.extractors.mtk import MTKExtractor
from data_io.extractors.generic import GenericExtractor
from classify.rules import classify_message
from parsers.base import ProactiveParser, EsimParser, NormalSimParser
from render.gui_adapter import to_gui_events

class Pipeline:
    def __init__(self, prefer_mtk: bool = True, show_normal_sim: bool = False):
        self.extractor_mtk = MTKExtractor()
        self.extractor_generic = GenericExtractor()
        self.prefer_mtk = prefer_mtk
        self.show_normal_sim = show_normal_sim

    def run_from_file(self, path: str) -> List[ParseResult]:
        text = load_text(path)
        if self.prefer_mtk:
            messages = self.extractor_mtk.extract_from_text(text)
        else:
            messages = self.extractor_generic.extract(text.splitlines())
        return self._run_messages(messages)

    def _run_messages(self, messages: List[Message]) -> List[ParseResult]:
        results: List[ParseResult] = []
        for m in messages:
            msg_type, direction, tag, title = classify_message(m)
            if msg_type == MsgType.PROACTIVE:
                parser = ProactiveParser()
            elif msg_type == MsgType.ESIM:
                parser = EsimParser()
            elif msg_type == MsgType.NORMAL_SIM:
                parser = NormalSimParser()
            else:
                parser = NormalSimParser()
            pr = parser.parse(m)
            # For proactive messages, keep the detailed title from the parser
            # For other message types, use the title from classify_message
            if msg_type != MsgType.PROACTIVE:
                pr.title = title
            pr.direction_hint = direction
            pr.tag = tag
            results.append(pr)
        return results

    def run_for_gui(self, path: str):
        res = self.run_from_file(path)
        return to_gui_events(res, show_normal_sim=self.show_normal_sim)
