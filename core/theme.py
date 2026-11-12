"""
core/theme.py - Light and dark themes for the tkinter interface.

Light = the native Windows look ("vista" ttk theme, unchanged). Dark = the "clam" ttk theme
recoloured, plus the plain tk widgets (text zones, list, frames) and the colours set in the
code (grey hints, links, green / orange findings, TLS grades) swapped for lighter tones that
stay readable on a dark background. The choice is saved in settings.json next to keys.json;
without a saved choice the Windows setting (apps in dark mode) is followed.
"""

import json
import os
import tkinter as tk
from tkinter import scrolledtext, ttk

from . import ROOT

SETTINGS = ROOT / "settings.json"

DARK = {
    "bg": "#1e1f22",       # window, frames
    "field": "#2b2d31",    # text zones, entries, tables
    "button": "#34373d",
    "hover": "#3f434a",
    "fg": "#e6e8eb",
    "muted": "#9aa4b2",
    "border": "#3a3d43",
    "select": "#2f5a8a",
    "accent": "#3b82f6",
}

# Colours used in the code for a light background -> readable equivalent on a dark one
DARK_COLORS = {
    "#6b7280": "#9aa4b2",  # grey hint
    "#2563eb": "#60a5fa",  # link
    "#c2410c": "#fb923c",  # warning
    "#15803d": "#4ade80",  # good / grade A
    "#65a30d": "#a3e635",  # grade B
    "#ca8a04": "#facc15",  # grade C
    "#b91c1c": "#f87171",  # grade F
    "#dc2626": "#f87171",  # log error
}


def load_choice():
    """'dark', 'light', or None when nothing is saved."""
    try:
        value = json.loads(SETTINGS.read_text(encoding="utf-8")).get("theme")
    except (OSError, ValueError, AttributeError):
        return None
    return value if value in ("dark", "light") else None


def save_choice(theme):
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["theme"] = theme
    try:
        SETTINGS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass  # read-only folder: the choice simply is not remembered


def system_prefers_dark():
    """Windows 'apps in dark mode' setting; False elsewhere or when unreadable."""
    if os.name != "nt":
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except OSError:
        return False


def _dark_title_bar(root, dark):
    """Dark or light Windows title bar (Windows 10 2004+ and 11); ignored elsewhere."""
    if os.name != "nt":
        return
    try:
        import ctypes
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
        for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE, then its pre-20H1 number
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value),
                                                          ctypes.sizeof(value)) == 0:
                break
        # SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED: redraw the frame now
        ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0020)
    except (AttributeError, OSError):
        pass


class ThemeManager:
    def __init__(self, root):
        self.root = root
        self.style = ttk.Style(root)
        self.light_theme = self.style.theme_use()
        self.dark = False
        self._orig = {}  # (widget path, option) -> light value, captured once

    def _keep(self, key, value):
        return self._orig.setdefault(key, value)

    def apply(self, dark):
        self.dark = dark
        if dark:
            self._style_dark()
        else:
            self.style.theme_use(self.light_theme)
        self.root.configure(background=DARK["bg"] if dark else self._keep(("root", "bg"), self.root.cget("background")))
        self._walk(self.root)
        _dark_title_bar(self.root, dark)

    # --- ttk widgets ---------------------------------------------------------------------------
    def _style_dark(self):
        s, d = self.style, DARK
        s.theme_use("clam")
        s.configure(".", background=d["bg"], foreground=d["fg"], fieldbackground=d["field"],
                    bordercolor=d["border"], lightcolor=d["bg"], darkcolor=d["bg"], troughcolor=d["field"],
                    selectbackground=d["select"], selectforeground=d["fg"], insertcolor=d["fg"],
                    focuscolor=d["select"], arrowcolor=d["fg"])
        s.map(".", foreground=[("disabled", d["muted"])], background=[("disabled", d["bg"])])
        s.configure("TButton", background=d["button"], bordercolor=d["border"], padding=(8, 2))
        s.map("TButton", background=[("disabled", d["bg"]), ("pressed", d["select"]), ("active", d["hover"])])
        s.configure("TNotebook", background=d["bg"], bordercolor=d["border"], tabmargins=(2, 4, 2, 0))
        s.configure("TNotebook.Tab", background=d["button"], foreground=d["muted"], bordercolor=d["border"],
                    padding=(8, 3))
        s.map("TNotebook.Tab", background=[("selected", d["bg"]), ("active", d["hover"])],
              foreground=[("selected", d["fg"]), ("active", d["fg"])])
        s.configure("Treeview", background=d["field"], fieldbackground=d["field"], foreground=d["fg"],
                    bordercolor=d["border"])
        s.map("Treeview", background=[("selected", d["select"])], foreground=[("selected", d["fg"])])
        s.configure("Treeview.Heading", background=d["button"], foreground=d["fg"], bordercolor=d["border"])
        s.map("Treeview.Heading", background=[("active", d["hover"])])
        for w in ("TEntry", "TSpinbox", "TCombobox"):
            s.configure(w, fieldbackground=d["field"], foreground=d["fg"], background=d["button"],
                        bordercolor=d["border"], arrowcolor=d["fg"])
        s.map("TCombobox", fieldbackground=[("readonly", d["field"])], foreground=[("readonly", d["fg"])],
              selectbackground=[("readonly", d["field"])], selectforeground=[("readonly", d["fg"])])
        s.map("TEntry", fieldbackground=[("disabled", d["bg"])])
        s.configure("TCheckbutton", background=d["bg"], indicatorbackground=d["field"],
                    indicatorforeground=d["fg"])
        s.map("TCheckbutton", background=[("active", d["bg"])],
              indicatorbackground=[("selected", d["select"]), ("disabled", d["bg"])])
        for orient in ("Vertical", "Horizontal"):
            s.configure(f"{orient}.TScrollbar", background=d["button"], troughcolor=d["bg"],
                        bordercolor=d["bg"], arrowcolor=d["muted"])
            s.map(f"{orient}.TScrollbar", background=[("active", d["hover"])])
        s.configure("Horizontal.TProgressbar", background=d["accent"], troughcolor=d["field"])
        s.configure("TLabelframe", background=d["bg"], bordercolor=d["border"])
        s.configure("TLabelframe.Label", background=d["bg"], foreground=d["muted"])
        s.configure("TPanedwindow", background=d["bg"])
        s.configure("Sash", background=d["border"], sashthickness=5)
        # Drop-down list of the comboboxes (created on first opening)
        for opt, val in (("background", d["field"]), ("foreground", d["fg"]),
                         ("selectBackground", d["select"]), ("selectForeground", d["fg"])):
            self.root.option_add(f"*TCombobox*Listbox.{opt}", val)

    # --- plain tk widgets and colours set in the code ---------------------------------------------
    def _swap(self, color):
        return DARK_COLORS.get(str(color).lower(), color) if self.dark else color

    def _walk(self, widget):
        from .gui import SoftButton  # avoid a circular import at load time
        # widget._w, not str(widget): a ScrolledText reports the path of its outer frame
        d, dark, path = DARK, self.dark, widget._w
        if isinstance(widget, SoftButton):
            widget.set_dark(dark)
        elif isinstance(widget, tk.Text):
            bg0 = self._keep((path, "bg"), widget.cget("background"))
            fg0 = self._keep((path, "fg"), widget.cget("foreground"))
            sel0 = self._keep((path, "sel"), widget.cget("selectbackground"))
            ins0 = self._keep((path, "ins"), widget.cget("insertbackground"))
            # Findings zones take the window colour, editable zones the field colour
            flat = bg0 == self._orig.get(("root", "bg"))
            widget.configure(background=(d["bg"] if flat else d["field"]) if dark else bg0,
                             foreground=d["fg"] if dark else fg0, insertbackground=d["fg"] if dark else ins0,
                             selectbackground=d["select"] if dark else sel0,
                             highlightbackground=d["border"] if dark else bg0)
            for tag in widget.tag_names():
                if tag == "sel":
                    continue
                fg = self._keep((path, "tag", tag), widget.tag_cget(tag, "foreground"))
                if fg:
                    widget.tag_configure(tag, foreground=self._swap(fg))
        elif isinstance(widget, tk.Listbox):
            keys = ("background", "foreground", "selectbackground", "selectforeground", "highlightbackground")
            orig = {k: self._keep((path, k), widget.cget(k)) for k in keys}
            new = dict(zip(keys, (d["field"], d["fg"], d["select"], d["fg"], d["border"]))) if dark else orig
            widget.configure(**new)
        elif isinstance(widget, tk.Frame) and not isinstance(widget, ttk.Frame):
            widget.configure(background=d["bg"] if dark else self._keep((path, "bg"), widget.cget("background")))
        elif isinstance(widget, ttk.Label):
            fg = self._keep((path, "fg"), str(widget.cget("foreground")))
            if fg:
                widget.configure(foreground=self._swap(fg))
        elif isinstance(widget, ttk.Treeview):
            for tag in widget.tk.splitlist(widget.tk.call(widget, "tag", "names")):
                fg = self._keep((path, "tag", tag), str(widget.tag_configure(tag, "foreground") or ""))
                if fg:
                    widget.tag_configure(tag, foreground=self._swap(fg))
        for child in widget.winfo_children():
            self._walk(child)


def themed_scrollbars(widget):
    """Replace the native scrollbar of every ScrolledText by a ttk one, which the dark theme can
    recolour (the native Windows scrollbar ignores colours)."""
    if isinstance(widget, scrolledtext.ScrolledText):
        bar = ttk.Scrollbar(widget.frame, orient="vertical", command=widget.yview)
        widget.vbar.pack_forget()
        widget.vbar.destroy()
        widget.vbar = bar
        bar.pack(side="right", fill="y", before=widget._w)  # str(widget) is the outer frame
        widget.configure(yscrollcommand=bar.set)
    for child in widget.winfo_children():
        themed_scrollbars(child)
