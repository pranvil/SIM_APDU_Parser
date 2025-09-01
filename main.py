
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from typing import List, Dict

from engines.esim_engine import parse_esim_detail, parse_esim_store_data
from utils_common import pretty_hex, normalize_hex_line
from extractors.mtk_unified import extract_events_from_mtk_log, build_events_from_apdu_lines
from engines.proactive_engine import parse_events_from_lines as proactive_parse_lines

# Colors for list items
COLOR_PROACTIVE_RX = "#d62728"   # UICC=>TERMINAL (red-ish)
COLOR_PROACTIVE_TX = "#1f77b4"   # TERMINAL=>UICC (blue-ish)
COLOR_ESIM_RX      = "#2ca02c"   # ESIM=>LPA (green-ish)
COLOR_ESIM_TX      = "#9467bd"   # LPA=>ESIM (purple-ish)
COLOR_UNKNOWN      = "#7f7f7f"   # unknown gray

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Proactive + eSIM APDU Unified Viewer")
        self.geometry("1100x720")

        self.events: List[Dict] = []  # unified Event list
        self.filtered_indices: List[int] = []

        self._build_widgets()

    def _build_widgets(self):
        topbar = tk.Frame(self)
        topbar.pack(fill=tk.X, padx=8, pady=6)

        btn_load_mtk = tk.Button(topbar, text="加载 MTK 原始日志（统一抽取）", command=self.on_load_mtk_log)
        btn_load_mtk.pack(side=tk.LEFT, padx=4)

        btn_load_txt = tk.Button(topbar, text="加载 APDU 文本（每行一条）", command=self.on_load_apdu_txt)
        btn_load_txt.pack(side=tk.LEFT, padx=4)

        # Search box
        tk.Label(topbar, text="搜索:").pack(side=tk.LEFT, padx=(16,4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_list())
        ent = tk.Entry(topbar, textvariable=self.search_var, width=28)
        ent.pack(side=tk.LEFT, padx=4)

        # Split panels
        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Left list
        left_frame = tk.Frame(main_pane)
        self.listbox = tk.Listbox(left_frame, width=48, activestyle="dotbox")
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        sb = tk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=sb.set)

        main_pane.add(left_frame, minsize=260)

        # Right detail panel
        right_pane = tk.PanedWindow(main_pane, orient=tk.VERTICAL)
        main_pane.add(right_pane)

        upper = tk.Frame(right_pane)
        tk.Label(upper, text="解析详情").pack(anchor="w")
        self.text_details = tk.Text(upper, wrap=tk.WORD)
        self.text_details.pack(fill=tk.BOTH, expand=True)
        right_pane.add(upper, minsize=260)

        lower = tk.Frame(right_pane)
        tk.Label(lower, text="RAW Hex").pack(anchor="w")
        self.text_raw = tk.Text(lower, wrap=tk.WORD, height=10)
        self.text_raw.pack(fill=tk.BOTH, expand=True)
        right_pane.add(lower, minsize=160)

        # Status bar
        self.status = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status, anchor="w").pack(fill=tk.X, padx=8, pady=4)

    # --- Loading actions ---
    def on_load_mtk_log(self):
        fp = filedialog.askopenfilename(title="选择 MTK 原始日志", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not fp: return
        try:
            events = extract_events_from_mtk_log(fp)

            # For proactive items, we can enrich details using the existing parser by batching their raws
            proactive_lines = [e["raw"] for e in events if e["kind"] == "proactive"]
            if proactive_lines:
                parsed = proactive_parse_lines(proactive_lines)
                # Build a map raw->(title,details)
                lookup = {normalize_hex_line(x["raw"]): (x.get("title",""), x.get("prepared_details","")) for x in parsed}
                for e in events:
                    if e["kind"] == "proactive":
                        t = lookup.get(normalize_hex_line(e["raw"]))
                        if t:
                            e["title"], e["prepared_details"] = t[0], t[1]

            self.events = events
            self.status.set(f"加载完成：{len(events)} 条")
            self.refresh_list()
        except Exception as ex:
            messagebox.showerror("错误", f"解析失败：{ex}")

    def on_load_apdu_txt(self):
        fp = filedialog.askopenfilename(title="选择 APDU 文本（每行一条）", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not fp: return
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            events = build_events_from_apdu_lines(lines)
            # Enrich proactive
            proactive_lines = [e["raw"] for e in events if e["kind"] == "proactive"]
            if proactive_lines:
                parsed = proactive_parse_lines(proactive_lines)
                lookup = {normalize_hex_line(x["raw"]): (x.get("title",""), x.get("prepared_details","")) for x in parsed}
                for e in events:
                    if e["kind"] == "proactive":
                        t = lookup.get(normalize_hex_line(e["raw"]))
                        if t:
                            e["title"], e["prepared_details"] = t[0], t[1]
            self.events = events
            self.status.set(f"加载完成：{len(events)} 条")
            self.refresh_list()
        except Exception as ex:
            messagebox.showerror("错误", f"解析失败：{ex}")

    # --- List rendering ---
    def refresh_list(self):
        q = self.search_var.get().strip().lower()
        self.listbox.delete(0, tk.END)
        self.filtered_indices.clear()
        for idx, e in enumerate(self.events):
            title = e.get("title","")
            if q and q not in title.lower():
                continue
            self.filtered_indices.append(idx)
            self.listbox.insert(tk.END, title)
            # Color
            color = COLOR_UNKNOWN
            if e["kind"] == "proactive":
                if e["direction"].upper() == "UICC=>TERMINAL":
                    color = COLOR_PROACTIVE_RX
                elif e["direction"].upper() == "TERMINAL=>UICC":
                    color = COLOR_PROACTIVE_TX
            elif e["kind"] == "esim":
                if e["direction"].upper() == "ESIM=>LPA":
                    color = COLOR_ESIM_RX
                elif e["direction"].upper() == "LPA=>ESIM":
                    color = COLOR_ESIM_TX
            self.listbox.itemconfig(tk.END, fg=color)

        self.status.set(f"已显示 {len(self.filtered_indices)}/{len(self.events)} 条")

    def on_select(self, _evt):
        sel = self.listbox.curselection()
        if not sel:
            return
        real_idx = self.filtered_indices[sel[0]]
        e = self.events[real_idx]

        # Details
        details = ""
        if "prepared_details" in e and e["prepared_details"]:
            details = e["prepared_details"]
        elif e["kind"] == "esim":
            # ESIM/eSIM section
            if e["direction"].upper() == "ESIM=>LPA":
                # 保持原逻辑：响应侧直接用现有解析器
                hint = e.get("parser_hint")
                if hint in ("bf22","bf2d","bf37") or (isinstance(hint, str) and hint.startswith("bf")):
                    details = parse_esim_detail(e["tag"], e["raw"])
                else:
                    details = "（暂无解析器，仅显示 RAW）\n"
            else:
                # LPA=>ESIM：自动剥 STORE DATA 头部再交给同名 BF 解析器
                details = parse_esim_store_data(e["tag"], e["raw"])
        else:
            # proactive without prepared_details (fallback)
            details = "（未预解析，仅显示 RAW）\n"

        # Update text boxes
        self.text_details.configure(state=tk.NORMAL)
        self.text_details.delete("1.0", tk.END)
        self.text_details.insert(tk.END, details)
        self.text_details.configure(state=tk.NORMAL)

        self.text_raw.configure(state=tk.NORMAL)
        self.text_raw.delete("1.0", tk.END)
        self.text_raw.insert(tk.END, pretty_hex(e["raw"]))
        self.text_raw.configure(state=tk.NORMAL)

        self.status.set(f"{e.get('title','')}")

if __name__ == "__main__":
    App().mainloop()
