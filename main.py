import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Dict, Optional
import re

from app.adapter import load_for_gui, GuiSession

# 颜色
COLOR_PROACTIVE_RX = "#d62728"
COLOR_PROACTIVE_TX = "#1f77b4"
COLOR_ESIM_RX      = "#2ca02c"
COLOR_ESIM_TX      = "#9467bd"
COLOR_UNKNOWN      = "#7f7f7f"

def color_for_direction(direction: str) -> str:
    if direction == "UICC=>TERMINAL":   return COLOR_PROACTIVE_RX
    if direction == "TERMINAL=>UICC":   return COLOR_PROACTIVE_TX
    if direction == "ESIM=>LPA":        return COLOR_ESIM_RX
    if direction == "LPA=>ESIM":        return COLOR_ESIM_TX
    return COLOR_UNKNOWN

class SearchDialog:
    def __init__(self, parent, app_instance):
        self.parent = parent
        self.app = app_instance
        self.dialog = None
        self.search_var = tk.StringVar()
        self.current_index = 0
        self.search_results = []
        self.last_pattern = ""
        
    def show(self):
        """显示搜索对话框"""
        if self.dialog and self.dialog.winfo_exists():
            self.dialog.lift()
            self.dialog.focus_force()
            return
            
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("搜索")
        self.dialog.geometry("400x100")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # 居中显示
        self.dialog.geometry("+%d+%d" % (
            self.parent.winfo_rootx() + 50,
            self.parent.winfo_rooty() + 50
        ))
        
        # 创建界面
        self._build_ui()
        
        # 绑定事件
        self.dialog.bind("<Return>", lambda e: self.search_next())
        self.dialog.bind("<Shift-Return>", lambda e: self.search_prev())
        self.dialog.bind("<Escape>", lambda e: self.dialog.destroy())
        
        # 聚焦到搜索框
        self.entry_search.focus_set()
        
        # 如果搜索框有内容，自动执行搜索
        if self.search_var.get().strip():
            self.perform_search()
        
    def _build_ui(self):
        """构建搜索对话框界面"""
        main_frame = tk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 搜索框
        search_frame = tk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(search_frame, text="搜索:").pack(side=tk.LEFT)
        self.entry_search = tk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.entry_search.pack(side=tk.LEFT, padx=(5, 10))
        self.entry_search.bind("<KeyRelease>", self.on_search_text_changed)
        

        
        # 按钮
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        self.btn_prev = tk.Button(button_frame, text="上一个", command=self.search_prev, state=tk.DISABLED)
        self.btn_prev.pack(side=tk.LEFT, padx=(0, 5))
        
        self.btn_next = tk.Button(button_frame, text="下一个", command=self.search_next, state=tk.DISABLED)
        self.btn_next.pack(side=tk.LEFT, padx=(0, 10))
        
        self.btn_close = tk.Button(button_frame, text="关闭", command=self.dialog.destroy)
        self.btn_close.pack(side=tk.RIGHT)
        
        # 状态标签
        self.status_label = tk.Label(main_frame, text="", fg="gray")
        self.status_label.pack(anchor=tk.W)
        
    def on_search_text_changed(self, event=None):
        """搜索文本改变时的处理"""
        pattern = self.search_var.get().strip()
        if pattern != self.last_pattern:
            self.last_pattern = pattern
            self.perform_search()
            
    def perform_search(self):
        """执行搜索"""
        pattern = self.search_var.get().strip()
        if not pattern:
            self.search_results = []
            self.current_index = 0
            self.update_buttons()
            self.status_label.config(text="")
            return
            
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.status_label.config(text="无效的正则表达式", fg="red")
            return
            
        self.search_results = []
        
        for idx, event in enumerate(self.app.events):
            # 搜索标题
            if regex.search(event.get("title", "")):
                self.search_results.append(idx)
                continue
                
            # 搜索详情内容（默认启用）
            if self.app._session:
                raw = event["raw"]
                detail_text = self.app._detail_cache.get(raw)
                if detail_text is None:
                    # 生成详情文本
                    tree = self.app._session.get_tree_by_raw(raw)
                    parts = []
                    def walk(node):
                        text = node.get("text")
                        hint = node.get("hint")
                        if text: parts.append(text)
                        if hint: parts.append(hint)
                        for child in node.get("children", []):
                            walk(child)
                    walk(tree)
                    detail_text = "\n".join(parts)
                    self.app._detail_cache[raw] = detail_text
                    
                if regex.search(detail_text):
                    self.search_results.append(idx)
                    
        self.current_index = 0
        self.update_buttons()
        self.update_status()
        
    def update_buttons(self):
        """更新按钮状态"""
        has_results = len(self.search_results) > 0
        self.btn_prev.config(state=tk.NORMAL if has_results else tk.DISABLED)
        self.btn_next.config(state=tk.NORMAL if has_results else tk.DISABLED)
        
    def update_status(self):
        """更新状态显示"""
        if not self.search_var.get().strip():
            self.status_label.config(text="")
        elif not self.search_results:
            self.status_label.config(text="未找到匹配项", fg="red")
        else:
            self.status_label.config(
                text=f"找到 {len(self.search_results)} 个匹配项 (第 {self.current_index + 1} 个)",
                fg="blue"
            )
            
    def search_next(self):
        """搜索下一个"""
        if not self.search_results:
            return
            
        self.current_index = (self.current_index + 1) % len(self.search_results)
        self.highlight_result()
        self.update_status()
        
    def search_prev(self):
        """搜索上一个"""
        if not self.search_results:
            return
            
        self.current_index = (self.current_index - 1) % len(self.search_results)
        self.highlight_result()
        self.update_status()
        
    def highlight_result(self):
        """高亮显示搜索结果"""
        if not self.search_results:
            return
            
        target_idx = self.search_results[self.current_index]
        
        # 滚动到目标项
        self.app.tree_events.selection_set(str(target_idx))
        self.app.tree_events.see(str(target_idx))
        
        # 触发选择事件以显示详情
        self.app.tree_events.event_generate("<<TreeviewSelect>>")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Proactive + eSIM APDU Viewer")
        self.geometry("1200x760")

        self._session: GuiSession | None = None
        self.events_all: List[Dict] = []
        self.events: List[Dict] = []
        self._detail_cache: dict[str, str] = {}
        self._search_dialog: Optional[SearchDialog] = None

        self._build_widgets()
        self._bind_shortcuts()

    # ---------- UI ----------
    def _build_widgets(self):
        top = tk.Frame(self); top.pack(fill=tk.X, padx=8, pady=6)
        tk.Button(top, text="加载 MTK 原始日志", command=self.on_load_mtk).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="加载 APDU 文本（每行）", command=self.on_load_apdu).pack(side=tk.LEFT, padx=4)

        # 多选下拉菜单：筛选类别
        self.var_filter_proactive = tk.BooleanVar(value=True)
        self.var_filter_esim = tk.BooleanVar(value=True)
        self.var_filter_normal = tk.BooleanVar(value=False)

        self.menu_btn = tk.Menubutton(top, text="筛选类别 ▾", relief=tk.RAISED)
        self.menu = tk.Menu(self.menu_btn, tearoff=0)
        self.menu_btn.configure(menu=self.menu)
        self.menu.add_checkbutton(label="proactive APDU", variable=self.var_filter_proactive, command=self.on_filter_changed)
        self.menu.add_checkbutton(label="eSIM APDU", variable=self.var_filter_esim, command=self.on_filter_changed)
        self.menu.add_checkbutton(label="other SIM APDU", variable=self.var_filter_normal, command=self.on_filter_changed)
        self.menu_btn.pack(side=tk.LEFT, padx=8)

        tk.Label(top, text="搜索:").pack(side=tk.LEFT, padx=(16, 4))
        self.search_var = tk.StringVar(value="")
        self.entry_search = tk.Entry(top, textvariable=self.search_var, width=36)
        self.entry_search.pack(side=tk.LEFT)
        self.entry_search.bind("<Return>", lambda e: self.apply_search())
        tk.Button(top, text="Search", command=self.apply_search).pack(side=tk.LEFT, padx=6)
        tk.Button(top, text="清除筛选", command=self.clear_filters).pack(side=tk.LEFT, padx=4)

        self.var_search_detail = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="搜索右侧详情", variable=self.var_search_detail,
                       command=self.apply_search).pack(side=tk.LEFT, padx=8)

        self.status = tk.StringVar(value="就绪")
        tk.Label(top, textvariable=self.status).pack(side=tk.RIGHT)

        main = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        main.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # 左侧列表
        left_frame = tk.Frame(main)
        
        # 创建滚动条框架
        scroll_frame = tk.Frame(left_frame)
        scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        # 垂直滚动条
        yscroll = ttk.Scrollbar(scroll_frame, orient="vertical")
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 水平滚动条
        xscroll = ttk.Scrollbar(scroll_frame, orient="horizontal")
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 树形视图
        self.tree_events = ttk.Treeview(scroll_frame, show="tree", 
                                       yscrollcommand=yscroll.set, 
                                       xscrollcommand=xscroll.set)
        self.tree_events.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 配置滚动条
        yscroll.config(command=self.tree_events.yview)
        xscroll.config(command=self.tree_events.xview)
        
        # 绑定事件
        self.tree_events.bind("<<TreeviewSelect>>", self.on_select_event)
        
        # 配置列
        self.tree_events.column("#0", anchor="w", stretch=True, width=800, minwidth=300)
        self.tree_events.heading("#0", text="")
        self.tree_events.bind("<Configure>", lambda e: self.tree_events.column("#0", width=max(self.tree_events.winfo_width()-4, 200)))
        
        main.add(left_frame, width=520)

        # 右侧详情 + RAW
        right_frame = tk.Frame(main)
        self.tree_detail = ttk.Treeview(right_frame, show="tree")
        self.tree_detail.pack(fill=tk.BOTH, expand=True)
        tk.Label(right_frame, text="RAW:").pack(anchor="w")
        self.txt_raw = tk.Text(right_frame, height=6, wrap="none")
        self.txt_raw.pack(fill=tk.X, expand=False)
        main.add(right_frame)

        # ---------- 复制功能：右键菜单 & 快捷键 ----------
        # 左侧菜单
        self.menu_left = tk.Menu(self, tearoff=0)
        self.menu_left.add_command(label="复制此行", command=self.copy_left_line)
        self.menu_left.add_command(label="复制 RAW", command=self.copy_left_raw)
        self.menu_left.add_separator()
        self.menu_left.add_command(label="复制右侧详情（全部）", command=self.copy_detail_all_from_left)
        self.tree_events.bind("<Button-3>", self._popup_left)

        # 右侧详情菜单
        self.menu_detail = tk.Menu(self, tearoff=0)
        self.menu_detail.add_command(label="复制所选节点", command=self.copy_detail_node)
        self.menu_detail.add_command(label="复制所选子树", command=self.copy_detail_subtree)
        self.menu_detail.add_separator()
        self.menu_detail.add_command(label="复制全部详情", command=self.copy_detail_all)
        self.tree_detail.bind("<Button-3>", self._popup_detail)

        # RAW 菜单
        self.menu_raw = tk.Menu(self, tearoff=0)
        self.menu_raw.add_command(label="复制选中", command=lambda: self._to_clip(self.txt_raw.get("sel.first", "sel.last")) if self.txt_raw.tag_ranges("sel") else None)
        self.menu_raw.add_command(label="复制全部", command=lambda: self._to_clip(self.txt_raw.get("1.0", "end-1c")))
        self.txt_raw.bind("<Button-3>", lambda e: self.menu_raw.tk_popup(e.x_root, e.y_root))
        self.txt_raw.bind("<Control-a>", lambda e: (self.txt_raw.tag_add("sel", "1.0", "end-1c"), "break"))

        # Ctrl+C 快捷键
        self.tree_events.bind("<Control-c>", lambda e: (self.copy_left_line(), "break"))
        self.tree_detail.bind("<Control-c>", lambda e: (self.copy_detail_node(), "break"))

    def _bind_shortcuts(self):
        """绑定全局快捷键"""
        # Ctrl+F 搜索
        self.bind("<Control-f>", lambda e: self.show_search_dialog())
        # 确保所有子控件都能响应Ctrl+F
        self.bind_all("<Control-f>", lambda e: self.show_search_dialog())
        
    def show_search_dialog(self):
        """显示搜索对话框"""
        if not self._search_dialog:
            self._search_dialog = SearchDialog(self, self)
        self._search_dialog.show()

    # ---------- 文件加载 ----------
    def on_load_mtk(self):
        fp = filedialog.askopenfilename(title="选择 MTK 原始日志",
                                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not fp: return
        try:
            self._session = load_for_gui(fp, prefer_mtk=True, show_normal=self.var_filter_normal.get())
            # 初始化筛选
            kinds = []
            if self.var_filter_proactive.get(): kinds.append('proactive')
            if self.var_filter_esim.get(): kinds.append('esim')
            if self.var_filter_normal.get(): kinds.append('normal_sim')
            self._session.set_allowed_types(kinds)
            self.events_all = self._session.events[:]
            self._detail_cache.clear()
            self.status.set(f"加载完成：{len(self.events_all)} 条")
            self.apply_search()
        except Exception as ex:
            messagebox.showerror("错误", f"解析失败：\n{ex}")

    def on_load_apdu(self):
        fp = filedialog.askopenfilename(title="选择 APDU 文本（每行一条）",
                                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not fp: return
        try:
            self._session = load_for_gui(fp, prefer_mtk=False, show_normal=self.var_filter_normal.get())
            # 初始化筛选
            kinds = []
            if self.var_filter_proactive.get(): kinds.append('proactive')
            if self.var_filter_esim.get(): kinds.append('esim')
            if self.var_filter_normal.get(): kinds.append('normal_sim')
            self._session.set_allowed_types(kinds)
            self.events_all = self._session.events[:]
            self._detail_cache.clear()
            self.status.set(f"加载完成：{len(self.events_all)} 条")
            self.apply_search()
        except Exception as ex:
            messagebox.showerror("错误", f"解析失败：\n{ex}")

    def on_filter_changed(self):
        kinds = []
        if self.var_filter_proactive.get(): kinds.append('proactive')
        if self.var_filter_esim.get(): kinds.append('esim')
        if self.var_filter_normal.get(): kinds.append('normal_sim')
        if self._session:
            self._session.set_allowed_types(kinds)
            self.events_all = self._session.events[:]
            self._detail_cache.clear()
            self.apply_search()

    def clear_filters(self):
        """清除所有筛选条件"""
        # 清除搜索框
        self.search_var.set("")
        # 重置类别筛选为默认状态
        self.var_filter_proactive.set(True)
        self.var_filter_esim.set(True)
        self.var_filter_normal.set(False)
        # 重置搜索详情选项
        self.var_search_detail.set(False)
        # 应用更改
        self.on_filter_changed()

    # ---------- 搜索 ----------
    def apply_search(self):
        if not self._session: return
        pattern = (self.search_var.get() or "").strip()
        include_detail = self.var_search_detail.get()

        if not pattern:
            self.events = self.events_all[:]
            self.status.set(f"共 {len(self.events_all)} 条")
        else:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                messagebox.showerror("Regex Error", f"无效的正则表达式: {e}")
                return

            out = []
            for e in self.events_all:
                if regex.search(e.get("title", "")):
                    out.append(e); continue
                if include_detail:
                    raw = e["raw"]
                    buf = self._detail_cache.get(raw)
                    if buf is None:
                        nd = self._session.get_tree_by_raw(raw)
                        parts = []
                        def walk(n):
                            t = n.get("text"); h = n.get("hint")
                            if t: parts.append(t)
                            if h: parts.append(h)
                            for c in n.get("children", []): walk(c)
                        walk(nd)
                        buf = "\n".join(parts)
                        self._detail_cache[raw] = buf
                    if regex.search(buf): out.append(e)
            self.events = out
            self.status.set(f"匹配 {len(self.events)} / {len(self.events_all)} 条")

        self._refresh_event_list()

    # ---------- 列表渲染 ----------
    def _refresh_event_list(self):
        self.tree_events.delete(*self.tree_events.get_children())
        for idx, e in enumerate(self.events):
            text = f"[{e['direction']}] {e.get('title') or ''}"
            iid = self.tree_events.insert("", "end", iid=str(idx), text=text)
            color = color_for_direction(e["direction"])
            self.tree_events.item(iid, tags=(e["direction"],))
            self.tree_events.tag_configure(e["direction"], foreground=color)

        self.tree_detail.delete(*self.tree_detail.get_children())
        self.txt_raw.delete("1.0", tk.END)

        if self.events:
            self.tree_events.selection_set("0")
            self.tree_events.event_generate("<<TreeviewSelect>>")
        else:
            self.status.set("无匹配结果")

    # ---------- 选择 / 详情 ----------
    def on_select_event(self, evt=None):
        if not self._session: return
        sel = self.tree_events.selection()
        if not sel: return
        idx = int(sel[0])
        e = self.events[idx]
        raw = e["raw"]

        self.txt_raw.configure(state=tk.NORMAL)
        self.txt_raw.delete("1.0", tk.END)
        self.txt_raw.insert(tk.END, raw)
        self.txt_raw.configure(state=tk.NORMAL)

        tree = self._session.get_tree_by_raw(raw)
        self._populate_detail_tree(tree)

    def _populate_detail_tree(self, node_dict):
        self.tree_detail.delete(*self.tree_detail.get_children())
        def add(parent, nd):
            text = nd.get("text") or ""
            iid = self.tree_detail.insert(parent, "end", text=text)
            for ch in nd.get("children", []): add(iid, ch)
        add("", node_dict)
        # 默认展开所有节点
        def expand_all(item=""):
            for child in self.tree_detail.get_children(item):
                self.tree_detail.item(child, open=True)
                expand_all(child)
        expand_all()

    # ---------- 右键菜单 / 复制 ----------
    def _popup_left(self, e):
        try:
            iid = self.tree_events.identify_row(e.y)
            if iid: self.tree_events.selection_set(iid)
            self.menu_left.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu_left.grab_release()

    def _popup_detail(self, e):
        try:
            iid = self.tree_detail.identify_row(e.y)
            if iid: self.tree_detail.selection_set(iid)
            self.menu_detail.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu_detail.grab_release()

    def _to_clip(self, text: str | None):
        if not text: return
        self.clipboard_clear()
        self.clipboard_append(text)
        try: self.update()
        except Exception: pass

    def copy_left_line(self):
        sel = self.tree_events.selection()
        if not sel: return
        self._to_clip(self.tree_events.item(sel[0], "text"))

    def copy_left_raw(self):
        sel = self.tree_events.selection()
        if not sel: return
        idx = int(sel[0])
        self._to_clip(self.events[idx]["raw"])

    def copy_detail_node(self):
        sel = self.tree_detail.selection()
        if not sel: return
        iid = sel[0]
        self._to_clip(self.tree_detail.item(iid, "text"))

    def copy_detail_subtree(self):
        sel = self.tree_detail.selection()
        if not sel: return
        iid = sel[0]
        lines = []
        def walk(node, depth=0):
            lines.append("  "*depth + (self.tree_detail.item(node, "text") or ""))
            for c in self.tree_detail.get_children(node):
                walk(c, depth+1)
        walk(iid)
        self._to_clip("\n".join(lines))

    def copy_detail_all(self):
        lines = []
        def walk(node, depth=0):
            lines.append("  "*depth + (self.tree_detail.item(node, "text") or ""))
            for c in self.tree_detail.get_children(node): walk(c, depth+1)
        for r in self.tree_detail.get_children(""):
            walk(r, 0)
        self._to_clip("\n".join(lines))

    def copy_detail_all_from_left(self):
        # 从左侧当前项直接取解析树，避免右侧未展开/滚动影响
        sel = self.tree_events.selection()
        if not sel or not self._session: return
        idx = int(sel[0]); raw = self.events[idx]["raw"]
        nd = self._session.get_tree_by_raw(raw)
        lines = []
        def walk(n, d=0):
            lines.append("  "*d + (n.get("text") or ""))
            for c in n.get("children", []):
                walk(c, d+1)
        walk(nd)
        self._to_clip("\n".join(lines))

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
