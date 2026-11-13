#!/usr/bin/env python3
"""
core/gui.py (run through netshot_gui.py) - Graphical interface (tkinter) for NetShot.

Same engine as the command line version: IP / CIDR / hostname targets,
subdomains from Certificate Transparency logs, TCP port check,
headless Chromium screenshots, HTML + CSV report.

Run:
    python netshot_gui.py
"""

import asyncio
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from types import SimpleNamespace

from .webinfo import dir_words
from .scope import parse_proxy, read_exclusions
from .recon import file_rules
from . import ROOT as HERE, ASSETS, __version__
from . import dns as netshot_dns
from . import whois as netshot_whois
from . import leakcheck
from . import scan as netshot
from . import sources
from . import theme
from . import tls as netshot_tls

RESOLUTIONS = {
    "1366 x 768": (1366, 768),
    "1920 x 1080 (Full HD)": (1920, 1080),
    "2560 x 1440": (2560, 1440),
    "3840 x 2160 (4K)": (3840, 2160),
    "390 x 844 (mobile)": (390, 844),
}
MAX_LOG_LINES = 3000  # keep the window light on big scans
# Tab titles with an icon. Tk 8.6 cannot draw characters above U+FFFF (colour emoji),
# so these are plain symbols from the Basic Multilingual Plane.
TAB_DOMAIN, TAB_SCAN, TAB_DNS, TAB_CERTS, TAB_KEYS = (
    "\u25ce Domaine", "\u25b6 Scan", "\u2630 DNS", "\u2714 Certificats", "\u26bf Clés API")
TAB_LEAKS = "\u26a0 Leaks"
TAB_WHOIS = "\u2139 Whois"

# Columns of the Leaks tab: the source fields first, then the data fields in this order;
# any other field LeakCheck returns gets its own column after these.
LEAK_SOURCE_COLS = [("source", "Source", 150), ("breach_date", "Date fuite", 80),
                    ("unverified", "Non vérifiée", 80), ("passwordless", "Sans mot de passe", 110),
                    ("compilation", "Compilation", 85)]
LEAK_DATA_COLS = {"email": ("E-mail", 220), "username": ("Identifiant", 120), "password": ("Mot de passe", 120),
                  "first_name": ("Prénom", 100), "last_name": ("Nom", 110), "name": ("Nom complet", 140),
                  "dob": ("Naissance", 85), "phone": ("Téléphone", 110), "address": ("Adresse", 220),
                  "zip": ("Code postal", 80), "city": ("Ville", 120), "country": ("Pays", 70),
                  "ip": ("IP", 110), "collected": ("Collecté le", 110)}
LEAK_MASK = "••••••••"  # fixed length: the length of a password is information too


class ThinProgress(tk.Canvas):
    """6 px progress bar (a ttk one cannot be that thin in the clam theme). Same calls as the
    ttk.Progressbar it replaces: configure(maximum=..., value=...)."""

    def __init__(self, parent, height=6):
        super().__init__(parent, height=height, highlightthickness=0, bd=0)
        self._max, self._value, self._colors = 1.0, 0.0, ("#d1d5db", "#2563eb")
        self.bind("<Configure>", lambda e: self._draw())

    def set_colors(self, trough, bar):
        self._colors = (trough, bar)
        self._draw()

    def _draw(self):
        w, h = self.winfo_width(), int(self.cget("height"))
        self.delete("all")
        tk.Canvas.configure(self, background=self._colors[0])
        if self._max > 0 and self._value > 0:
            self.create_rectangle(0, 0, w * min(1.0, self._value / self._max), h, fill=self._colors[1], width=0)

    def configure(self, cnf=None, **kw):
        if "maximum" in kw:
            self._max = float(kw.pop("maximum"))
        if "value" in kw:
            self._value = float(kw.pop("value"))
        result = super().configure(cnf, **kw) if (cnf or kw) else None
        self._draw()
        return result

    config = configure


class NetshotApp:
    def __init__(self, root):
        self.root = root
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.report = None

        root.title(f"NetShot {__version__} - captures réseau")
        # Centered on the screen; smaller than 1180x880 on a small screen (taskbar kept visible)
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        w, h = min(1180, sw - 40), min(880, sh - 80)
        root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 2 - 20)}")
        root.minsize(min(900, w), min(680, h))
        self.preview_img = None
        self.preview_path = None
        icon = ASSETS / "icon.png"
        if icon.exists():
            self.icon = tk.PhotoImage(file=str(icon))
            root.iconphoto(True, self.icon)

        outer = ttk.Frame(root, padding=(10, 6, 10, 10))
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=6)  # tabs get most of the height, journal / capture stay compact
        outer.rowconfigure(2, weight=1)

        # Header: Quit button on the right of the tabs
        header = ttk.Frame(outer)
        header.grid(row=0, column=0, sticky="ew")
        # Brand: small logo + NetShot (icon-32.png is drawn for 32 px; else icon.png subsampled)
        small = ASSETS / "icon-32.png"
        if small.exists():
            self.logo_small = tk.PhotoImage(file=str(small))
        elif icon.exists():
            self.logo_small = self.icon.subsample(8)
        if small.exists() or icon.exists():
            ttk.Label(header, image=self.logo_small).pack(side="left", padx=(0, 6))
        ttk.Label(header, text="NetShot", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Label(header, text=f"v{__version__}", foreground="#888").pack(side="left", padx=(6, 0), pady=(4, 0))
        ttk.Button(header, text="Quitter", command=self.on_close, style="Quit.TButton").pack(side="right")
        self.theme_btn = ttk.Button(header, command=self.toggle_theme, width=10)
        self.theme_btn.pack(side="right", padx=(0, 8))

        self.nb = ttk.Notebook(outer)
        self.nb.grid(row=1, column=0, sticky="nsew", pady=(4, 6))
        self.keys = sources.load_keys()
        self._build_subs_tab()
        self.scan_tab = self._build_scan_tab()
        self._build_dns_tab()
        self._build_whois_tab()
        self.certs_tab = self._build_certs_tab()
        self._build_leaks_tab()
        self.keys_tab = self._build_keys_tab()

        # Journal and last capture: one panel with two tabs (the capture tab only on the Scan tab)
        bottom = ttk.Notebook(outer)
        bottom.grid(row=2, column=0, sticky="nsew")
        self.bottom, self.outer = bottom, outer
        log_box = ttk.Frame(bottom, padding=4)
        bottom.add(log_box, text="Journal")
        # Reset of the log also clears the last capture
        self._tool_buttons(log_box, lambda: self.log.get("1.0", "end"), self.reset_bottom).pack(anchor="e")
        self.log = scrolledtext.ScrolledText(log_box, height=5, width=50, font=("Consolas", 9), state="disabled",
                                             relief="flat", padx=8, pady=6)
        self.log.is_log = True  # dark console in both themes (theme.py)
        self.log.tag_configure("err", foreground="#f87171")
        self.log.pack(fill="both", expand=True)
        preview = ttk.Frame(bottom, padding=4)
        bottom.add(preview, text="Dernière capture")
        self.preview_box = preview
        self.preview_info = tk.StringVar(value="-")
        info_row = ttk.Frame(preview)
        info_row.pack(fill="x")
        ttk.Button(info_row, text="Effacer", width=8, command=self.reset_preview).pack(side="right")
        ttk.Label(info_row, textvariable=self.preview_info, wraplength=700).pack(side="left", anchor="w")
        # Fixed-size area: the image is scaled to it, so it never pushes the window
        self.preview_area = ttk.Frame(preview)
        self.preview_area.pack(fill="both", expand=True)
        self.preview_area.pack_propagate(False)
        self.preview = ttk.Label(self.preview_area, anchor="center", cursor="hand2", text="Aucune capture pour l'instant")
        self.preview.pack(fill="both", expand=True)
        self.preview.bind("<Button-1>", lambda e: self.preview_path and self.open_path(self.preview_path))
        self.refresh_sources(first=True)
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.layout_for_tab())
        self.bottom.bind("<<NotebookTabChanged>>", lambda e: self.bottom.tab(self.preview_box, text="Dernière capture")
                         if self.bottom.index("current") == self.bottom.index(self.preview_box) else None)
        self.update_targets_count()
        theme.themed_scrollbars(root)
        self.theme = theme.ThemeManager(root)
        self.set_theme(theme.load_choice() or ("dark" if theme.system_prefers_dark() else "light"), save=False)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.poll_queue)

    # --- Tabs -------------------------------------------------------------

    def _build_scan_tab(self):
        """Same layout as the Go version: targets, ports and user agents on the left; option groups
        on the right (passive analysis, active tests, folded settings); action bar at the bottom."""
        main = ttk.Frame(self.nb, padding=(10, 8, 10, 6))
        self.nb.add(main, text=TAB_SCAN)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=1)

        # --- Left: targets, ports, user agents
        left = ttk.LabelFrame(main, text="CIBLES", padding=8)
        left.grid(row=0, column=0, sticky="nsew")
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)
        head = ttk.Frame(left)
        head.grid(row=0, column=0, sticky="ew")
        self.targets_pill = tk.StringVar()
        ttk.Label(head, textvariable=self.targets_pill, style="Pill.TLabel").pack(side="left")
        self._tool_buttons(head, lambda: self.targets.get("1.0", "end"), self.reset_targets).pack(side="right")
        ttk.Button(head, text="Charger fichier / CSV…", command=self.load_file).pack(side="right", padx=(0, 6))
        self.targets = scrolledtext.ScrolledText(left, height=6, font=("Consolas", 10), relief="flat",
                                                 padx=8, pady=6, highlightthickness=1)
        self.targets.grid(row=1, column=0, sticky="nsew", pady=(6, 2))
        self.targets.bind("<KeyRelease>", lambda e: self.update_targets_count())
        ttk.Label(left, style="Muted.TLabel", text="IP, plage CIDR, nom d'hôte, AS1234 ou export CSV (AD, ADCS, "
                  "CMDB). Une cible par ligne, # pour un commentaire.").grid(row=2, column=0, sticky="w")

        ports_row = ttk.Frame(left)
        ports_row.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        ports_row.columnconfigure(1, weight=1)
        ttk.Label(ports_row, text="Ports", style="Section.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.ports = tk.StringVar(value=",".join(map(str, netshot.DEFAULT_PORTS)))
        ttk.Entry(ports_row, textvariable=self.ports, font=("Consolas", 10)).grid(row=0, column=1, sticky="ew")
        chips = ttk.Frame(ports_row)
        chips.grid(row=0, column=2, padx=(8, 0))
        self.ports_preset = tk.StringVar()
        defaults = ",".join(map(str, netshot.DEFAULT_PORTS))
        for label, value in (("Défaut", defaults), ("Web étendu (~100)", "web"),
                             ("Services non web", "services"), ("Web + services", "web,services")):
            ttk.Radiobutton(chips, text=label, value=value, variable=self.ports_preset, style="Chip.Toolbutton",
                            command=lambda v=value: self.ports.set(v)).pack(side="left", padx=(0, 4))
        self.ports.trace_add("write", lambda *a: self.ports_preset.set(self.ports.get().replace(" ", "")))
        self.ports_preset.set(defaults)

        # User agents: toggle chips. Nothing selected = Chromium's own UA.
        ua_head = ttk.Frame(left)
        ua_head.grid(row=4, column=0, sticky="ew", pady=(10, 2))
        ttk.Label(ua_head, text="User agents", style="Section.TLabel").pack(side="left")
        for label, names in (("Aucun", {}), ("Tous", netshot.USER_AGENTS), ("Robots", netshot.BOT_UAS),
                             ("Navigateurs", netshot.BROWSER_UAS)):
            ttk.Button(ua_head, text=label, style="Link.TButton", width=0,
                       command=lambda n=names: self.select_uas(n)).pack(side="right")
        self.ua_count = tk.StringVar()
        ttk.Label(ua_head, textvariable=self.ua_count, style="Muted.TLabel").pack(side="right", padx=(0, 8))
        ua_box = ttk.Frame(left)
        ua_box.grid(row=5, column=0, sticky="ew")
        self.ua_names = list(netshot.USER_AGENTS)
        self.ua_vars = {}
        for i, name in enumerate(self.ua_names):
            kind = "bot" if name in netshot.BOT_UAS else "nav"
            self.ua_vars[name] = tk.BooleanVar(value=False)
            ttk.Checkbutton(ua_box, text=f"{name}  {kind}", variable=self.ua_vars[name], style="Chip.Toolbutton",
                            command=self.update_ua_count).grid(row=i // 4, column=i % 4, sticky="ew", padx=(0, 4), pady=2)
        for col in range(4):
            ua_box.columnconfigure(col, weight=1, uniform="ua")
        self.custom_ua = tk.StringVar()
        custom = ttk.Frame(left)
        custom.grid(row=6, column=0, sticky="ew", pady=(4, 0))
        custom.columnconfigure(1, weight=1)
        ttk.Label(custom, text="UA personnalisé", style="Muted.TLabel").grid(row=0, column=0, padx=(0, 8))
        ttk.Entry(custom, textvariable=self.custom_ua).grid(row=0, column=1, sticky="ew")
        self.update_ua_count()

        # --- Right: option groups
        side = ttk.Frame(main, width=360)
        side.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        def option(parent, var, title, detail, active=False):
            box = ttk.Frame(parent)
            box.pack(fill="x", pady=(4, 2))
            ttk.Checkbutton(box, text=title, variable=var,
                            style="Active.TCheckbutton" if active else "TCheckbutton").pack(anchor="w")
            ttk.Label(box, text=detail, style="Muted.TLabel").pack(anchor="w", padx=(22, 0))

        passive = ttk.LabelFrame(side, text="ANALYSE PASSIVE", style="Passive.TLabelframe", padding=(10, 4, 10, 8))
        passive.pack(fill="x")
        self.enrich = tk.BooleanVar(value=True)
        self.reputation = tk.BooleanVar(value=True)
        self.tls_scan = tk.BooleanVar(value=True)
        self.label_shots = tk.BooleanVar(value=True)
        option(passive, self.enrich, "Enrichir les IP et les versions", "Shodan, LeakIX, NVD, CISA KEV, EPSS")
        option(passive, self.reputation, "Réputation des noms", "Listes de blocage, URLhaus, VirusTotal, Safe Browsing")
        option(passive, self.tls_scan, "Analyser les certificats TLS", "Versions, suites, PQC, chaîne, HSTS")
        option(passive, self.label_shots, "Inscrire l'URL sur les captures", "Bandeau hôte:port, URL, statut, date")

        active = ttk.LabelFrame(side, text="TESTS ACTIFS  ·  requêtes en plus", style="Active.TLabelframe",
                                padding=(10, 4, 10, 8))
        active.pack(fill="x", pady=(10, 0))
        self.probe_dirs = tk.BooleanVar(value=False)
        self.probe_files = tk.BooleanVar(value=False)
        self.waf_probe = tk.BooleanVar(value=False)
        option(active, self.probe_dirs, "Dossiers courants (Index of)", "~95 requêtes par service web", True)
        option(active, self.probe_files, "Fichiers sensibles (.env, .git…)", "~65 requêtes par service web", True)
        option(active, self.waf_probe, "Présence d'un WAF", "1 requête de test par service web", True)

        # Folded settings: a header button with a one-line summary, the fields once opened
        self.outdir = tk.StringVar(value=str(HERE / "screenshots"))
        self.concurrency = tk.IntVar(value=10)
        self.connect_timeout = tk.DoubleVar(value=1.5)
        self.page_timeout = tk.DoubleVar(value=15)
        self.delay = tk.DoubleVar(value=0)
        self.resolution = tk.StringVar(value="1920 x 1080 (Full HD)")
        self.proxy = tk.StringVar()
        self.exclude = tk.StringVar()

        def fold(title, build, summary):
            box = ttk.Frame(side)
            box.pack(fill="x", pady=(10, 0))
            text = tk.StringVar()
            body = ttk.Frame(box, padding=(18, 4, 0, 0))
            body.columnconfigure(1, weight=1)
            build(body)

            def toggle():
                if body.winfo_ismapped():
                    body.pack_forget()
                    btn.configure(text="\u25b8  " + title)
                    hint.pack(anchor="w", padx=(18, 0))
                else:
                    hint.pack_forget()
                    body.pack(fill="x")
                    btn.configure(text="\u25be  " + title)
            btn = ttk.Button(box, text="\u25b8  " + title, style="Fold.TButton", command=toggle)
            btn.pack(fill="x")
            hint = ttk.Label(box, textvariable=text, style="Muted.TLabel")
            hint.pack(anchor="w", padx=(18, 0))
            return text

        def advanced(body):
            ttk.Label(body, text="Dossier de sortie").grid(row=0, column=0, sticky="w", pady=2)
            out = ttk.Frame(body)
            out.grid(row=0, column=1, sticky="ew", pady=2)
            out.columnconfigure(0, weight=1)
            ttk.Entry(out, textvariable=self.outdir).grid(row=0, column=0, sticky="ew")
            ttk.Button(out, text="…", width=3, command=self.pick_outdir).grid(row=0, column=1, padx=(4, 0))
            for row, (label, var, lo, hi, inc) in enumerate((
                    ("Parallèle", self.concurrency, 1, 200, 1),
                    ("Timeout TCP (s)", self.connect_timeout, 0.2, 30, 0.5),
                    ("Timeout page (s)", self.page_timeout, 1, 120, 1),
                    ("Délai entre captures (s)", self.delay, 0, 600, 0.5)), start=1):
                ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=2, padx=(0, 8))
                ttk.Spinbox(body, textvariable=var, from_=lo, to=hi, increment=inc, width=8).grid(
                    row=row, column=1, sticky="w", pady=2)
            ttk.Label(body, text="Résolution").grid(row=5, column=0, sticky="w", pady=2)
            ttk.Combobox(body, textvariable=self.resolution, values=list(RESOLUTIONS), state="readonly",
                         width=22).grid(row=5, column=1, sticky="w", pady=2)

        def scope(body):
            ttk.Label(body, text="Proxy").grid(row=0, column=0, sticky="w", pady=2, padx=(0, 8))
            ttk.Entry(body, textvariable=self.proxy).grid(row=0, column=1, sticky="ew", pady=2)
            ttk.Label(body, text="ex. http://127.0.0.1:8080 ou socks5://hôte:1080",
                      style="Muted.TLabel").grid(row=1, column=1, sticky="w")
            ttk.Label(body, text="Hors périmètre").grid(row=2, column=0, sticky="w", pady=2, padx=(0, 8))
            ex = ttk.Frame(body)
            ex.grid(row=2, column=1, sticky="ew", pady=2)
            ex.columnconfigure(0, weight=1)
            ttk.Entry(ex, textvariable=self.exclude).grid(row=0, column=0, sticky="ew")
            ttk.Button(ex, text="Fichier…", command=self.load_exclusions).grid(row=0, column=1, padx=(4, 0))

        self.adv_sum = fold("RÉGLAGES AVANCÉS", advanced, None)
        self.scope_sum = fold("PÉRIMÈTRE ET PROXY", scope, None)
        for var in (self.concurrency, self.connect_timeout, self.page_timeout, self.delay, self.resolution,
                    self.proxy, self.exclude):
            var.trace_add("write", lambda *a: self.update_fold_summaries())
        self.update_fold_summaries()

        # --- Action bar: always visible at the bottom of the tab
        actions = ttk.Frame(main, padding=(0, 8, 0, 0))
        actions.grid(row=1, column=0, columnspan=2, sticky="ew")
        actions.columnconfigure(2, weight=1)
        self.start_btn = ttk.Button(actions, text="\u25b6  Lancer le scan", style="Accent.TButton", command=self.start)
        self.start_btn.grid(row=0, column=0, rowspan=2, sticky="ns")
        self.stop_btn = ttk.Button(actions, text="\u25a0  Arrêter", style="Big.TButton", command=self.stop, state="disabled")
        self.stop_btn.grid(row=0, column=1, rowspan=2, sticky="ns", padx=8)
        self.progress = ThinProgress(actions)
        self.progress.grid(row=0, column=2, sticky="ew", padx=(4, 8), pady=(10, 2))
        self.status = tk.StringVar(value="Prêt.")
        ttk.Label(actions, textvariable=self.status, style="Muted.TLabel").grid(row=1, column=2, sticky="w", padx=(4, 8))
        self.folder_btn = ttk.Button(actions, text="Ouvrir le dossier", command=self.open_folder, state="disabled")
        self.folder_btn.grid(row=0, column=3, rowspan=2, sticky="ns")
        self.report_btn = ttk.Button(actions, text="Ouvrir le rapport", command=self.open_report, state="disabled")
        self.report_btn.grid(row=0, column=4, rowspan=2, sticky="ns", padx=(6, 0))
        return main

    def _build_subs_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text=TAB_DOMAIN)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
        ttk.Label(tab, text="Domaines :").grid(row=0, column=0, sticky="w")
        self.ct_domains = tk.StringVar()
        ttk.Entry(tab, textvariable=self.ct_domains).grid(row=0, column=1, sticky="ew", padx=4)
        self.ct_btn = ttk.Button(tab, style="Primary.TButton", text="Rechercher", command=self.ct_search)
        self.ct_btn.grid(row=0, column=2)
        # Source checkboxes: keyed sources without a key are disabled (see refresh_sources)
        checks = ttk.Frame(tab)
        checks.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.ct_sources, self.ct_checks = {}, {}
        for i, s in enumerate(sources.SUB_SOURCES):
            self.ct_sources[s["name"]] = tk.BooleanVar(value=False)
            cb = ttk.Checkbutton(checks, variable=self.ct_sources[s["name"]],
                                 text=s["label"] + (" (lent)" if s["slow"] else ""))
            cb.grid(row=i // 5, column=i % 5, sticky="w", padx=(0, 12))
            self.ct_checks[s["name"]] = cb
        filters = ttk.Frame(tab)
        filters.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.ct_resolve = tk.BooleanVar(value=True)
        self.ct_private = tk.BooleanVar(value=False)
        ttk.Checkbutton(filters, text="seulement les noms qui résolvent", variable=self.ct_resolve).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(filters, text="seulement IP privées", variable=self.ct_private).pack(side="left")
        ttk.Label(tab, style="Hint.TLabel", text="Les sources marquées (clé) demandent une clé gratuite "
                  "(onglet Clés API). Les noms trouvés sont ajoutés aux cibles de l'onglet Scan.").grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.ct_title = tk.StringVar()
        ttk.Label(tab, textvariable=self.ct_title, font=("Segoe UI", 9, "bold")).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._tool_buttons(tab, lambda: self.ct_names.get("1.0", "end"), self.reset_subs).grid(row=4, column=2, sticky="e", pady=(8, 0))
        self.ct_names = scrolledtext.ScrolledText(tab, height=8, font=("Consolas", 9), state="disabled")
        self.ct_names.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(2, 0))

    def _build_dns_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text=TAB_DNS)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
        ttk.Label(tab, text="Domaine :").grid(row=0, column=0, sticky="w")
        self.dns_domain = tk.StringVar()
        entry = ttk.Entry(tab, textvariable=self.dns_domain)
        entry.grid(row=0, column=1, sticky="ew", padx=4)
        entry.bind("<Return>", lambda e: self.dns_run())
        ttk.Label(tab, text="Serveur :").grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.dns_server = tk.StringVar()
        ttk.Entry(tab, textvariable=self.dns_server, width=18).grid(row=0, column=3, padx=4)
        self.dns_btn = ttk.Button(tab, style="Primary.TButton", text="Interroger", command=self.dns_run)
        self.dns_btn.grid(row=0, column=4)
        ttk.Label(tab, style="Hint.TLabel", wraplength=1050, text="Serveur vide = résolveurs du système. "
                  "Une requête ANY est tentée, mais la plupart des serveurs la refusent (RFC 8482) : chaque type "
                  "est aussi interrogé un par un (A, AAAA, NS, SOA, MX, TXT, CAA, DS, DNSKEY, HTTPS, DMARC, "
                  "MTA-STS, SRV Active Directory et Microsoft 365…).").grid(row=1, column=0, columnspan=5, sticky="w", pady=(6, 0))
        self.dns_title = tk.StringVar()
        ttk.Label(tab, textvariable=self.dns_title, font=("Segoe UI", 9, "bold")).grid(row=2, column=0, columnspan=5, sticky="w", pady=(8, 0))
        self.dns_findings = tk.Text(tab, height=5, font=("Segoe UI", 9), relief="flat", state="disabled",
                                    background=self.root.cget("background"))
        self.dns_findings.tag_configure("warn", foreground="#c2410c")
        self.dns_findings.tag_configure("good", foreground="#15803d")
        self.dns_findings.grid(row=3, column=0, columnspan=5, sticky="ew")
        buttons = ttk.Frame(tab)
        buttons.grid(row=4, column=0, columnspan=5, sticky="w", pady=(4, 4))
        ttk.Button(buttons, text="Ajouter les hôtes aux cibles", command=self.dns_add_hosts).pack(side="left")
        ttk.Button(buttons, text="Copier au format dig", command=self.dns_copy).pack(side="left", padx=8)
        ttk.Button(buttons, text="Reset", command=self.reset_dns).pack(side="left")
        table = ttk.Frame(tab)
        table.grid(row=5, column=0, columnspan=5, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.dns_tree = ttk.Treeview(table, columns=("name", "ttl", "type", "data"), show="headings", height=8)
        for col, label, width, stretch in (("name", "Nom", 230, False), ("ttl", "TTL", 60, False),
                                           ("type", "Type", 70, False), ("data", "Valeur", 600, True)):
            self.dns_tree.heading(col, text=label, anchor="w")
            self.dns_tree.column(col, width=width, stretch=stretch, anchor="w")
        self.dns_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.dns_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.dns_tree.configure(yscrollcommand=scroll.set)
        self.dns_last = None

    def set_theme(self, name, save=True):
        dark = name == "dark"
        self.theme.apply(dark)
        self.theme_btn.configure(text="\u2600 Clair" if dark else "\u263e Sombre")
        self.log.configure(highlightthickness=0)
        if save:
            theme.save_choice(name)

    def toggle_theme(self):
        self.set_theme("light" if self.theme.dark else "dark")

    def layout_for_tab(self):
        """Whois uses the whole window height (no journal); Scan shows the journal and the last capture
        as two tabs; every other tab shows the journal alone."""
        tab = self.nb.tab(self.nb.select(), "text")
        if tab == TAB_WHOIS:
            self.bottom.grid_remove()
            self.outer.rowconfigure(2, weight=0)
            return
        self.bottom.grid()
        scan = self.nb.select() == str(self.scan_tab)
        self.outer.rowconfigure(1, weight=5 if scan else 6)
        self.outer.rowconfigure(2, weight=1)
        if scan:
            self.bottom.add(self.preview_box)  # shows the capture tab again (it stays in place)
        else:
            self.bottom.select(0)
            self.bottom.hide(self.preview_box)

    def _build_whois_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.whois_tab = tab
        self.nb.add(tab, text=TAB_WHOIS)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(4, weight=1)
        ttk.Label(tab, text="Domaine, IP ou AS :").grid(row=0, column=0, sticky="w")
        self.whois_query = tk.StringVar()
        entry = ttk.Entry(tab, textvariable=self.whois_query)
        entry.grid(row=0, column=1, sticky="ew", padx=4)
        entry.bind("<Return>", lambda e: self.whois_run())
        self.whois_btn = ttk.Button(tab, style="Primary.TButton", text="Interroger", command=self.whois_run)
        self.whois_btn.grid(row=0, column=2)
        ttk.Label(tab, style="Hint.TLabel", wraplength=1050, text="RDAP (registre officiel, via HTTPS) pour le "
                  "tableau et les constats, WHOIS port 43 pour le texte brut (souvent filtré en entreprise). "
                  "Un sous-domaine est cherché sous son domaine enregistré. Exemples : exemple.fr, 8.8.8.8, AS3215.").grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        head = ttk.Frame(tab)
        head.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.whois_title = tk.StringVar()
        ttk.Label(head, textvariable=self.whois_title, font=("Segoe UI", 9, "bold")).pack(side="left")
        self._tool_buttons(head, lambda: netshot_whois.format_whois(self.whois_last) if self.whois_last else "",
                           self.reset_whois).pack(side="right")
        self.whois_findings = tk.Text(tab, height=4, font=("Segoe UI", 9), relief="flat", state="disabled",
                                      background=self.root.cget("background"))
        self.whois_findings.tag_configure("warn", foreground="#c2410c")
        self.whois_findings.tag_configure("good", foreground="#15803d")
        self.whois_findings.grid(row=3, column=0, columnspan=3, sticky="ew")
        # Side by side: summary table on the left, raw WHOIS text on the right
        panes = ttk.PanedWindow(tab, orient="horizontal")
        panes.grid(row=4, column=0, columnspan=3, sticky="nsew")
        # Both sides in a titled frame with the same padding, so their tops line up
        table = ttk.LabelFrame(panes, text="Résumé (RDAP)", padding=4)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.whois_tree = ttk.Treeview(table, columns=("field", "value"), show="headings", height=8)
        self.whois_tree.heading("field", text="Champ", anchor="w")
        self.whois_tree.heading("value", text="Valeur", anchor="w")
        self.whois_tree.column("field", width=160, stretch=False, anchor="w")
        self.whois_tree.column("value", width=420, stretch=True, anchor="w")
        self.whois_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.whois_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.whois_tree.configure(yscrollcommand=scroll.set)
        panes.add(table, weight=1)
        raw = ttk.LabelFrame(panes, text="WHOIS brut (port 43)", padding=4)
        self.whois_raw = scrolledtext.ScrolledText(raw, height=6, width=60, font=("Consolas", 9), state="disabled",
                                                   wrap="word")
        self.whois_raw.pack(fill="both", expand=True)
        panes.add(raw, weight=1)
        # Equal widths: the divider goes back to the middle whenever the window is resized
        panes.bind("<Configure>", lambda e: panes.sashpos(0, e.width // 2))
        self.whois_last = None

    def _build_leaks_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text=TAB_LEAKS)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(3, weight=1)
        ttk.Label(tab, text="Recherche :").grid(row=0, column=0, sticky="w")
        self.leak_query = tk.StringVar()
        entry = ttk.Entry(tab, textvariable=self.leak_query)
        entry.grid(row=0, column=1, sticky="ew", padx=4)
        entry.bind("<Return>", lambda e: self.leak_run())
        ttk.Label(tab, text="Type :").grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.leak_type = tk.StringVar(value="domain")
        ttk.Combobox(tab, textvariable=self.leak_type, values=leakcheck.SEARCH_TYPES, width=10,
                     state="readonly").grid(row=0, column=3, padx=4)
        ttk.Label(tab, text="Limite :").grid(row=0, column=4, sticky="w", padx=(8, 0))
        self.leak_limit = tk.StringVar(value="100")
        ttk.Spinbox(tab, from_=1, to=1000, increment=100, textvariable=self.leak_limit, width=6).grid(row=0, column=5, padx=4)
        self.leak_btn = ttk.Button(tab, style="Primary.TButton", text="Rechercher", command=self.leak_run)
        self.leak_btn.grid(row=0, column=6)
        opts = ttk.Frame(tab)
        opts.grid(row=1, column=0, columnspan=7, sticky="w", pady=(6, 0))
        self.leak_show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Afficher les mots de passe", variable=self.leak_show_pw,
                        command=self.leak_render).pack(side="left")
        ttk.Label(opts, style="Hint.TLabel", text="   LeakCheck Pro API v2 (clé dans l'onglet Clés API). "
                  "Type auto : e-mail, identifiant, téléphone, hash. Domaine : choisir le type domain. "
                  "Seule la valeur recherchée est envoyée à LeakCheck.").pack(side="left")
        head = ttk.Frame(tab)
        head.grid(row=2, column=0, columnspan=7, sticky="ew", pady=(8, 2))
        self.leak_title = tk.StringVar()
        ttk.Label(head, textvariable=self.leak_title, font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Button(head, text="Exporter CSV", command=self.leak_export).pack(side="right", padx=(4, 0))
        self._tool_buttons(head, self.leak_table_text, self.reset_leaks).pack(side="right")
        table = ttk.Frame(tab)
        table.grid(row=3, column=0, columnspan=7, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.leak_tree = ttk.Treeview(table, show="headings", height=8)
        self.leak_tree.grid(row=0, column=0, sticky="nsew")
        vs = ttk.Scrollbar(table, orient="vertical", command=self.leak_tree.yview)
        vs.grid(row=0, column=1, sticky="ns")
        hs = ttk.Scrollbar(table, orient="horizontal", command=self.leak_tree.xview)
        hs.grid(row=1, column=0, sticky="ew")
        self.leak_tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.leak_rows, self.leak_cols = [], []

    def _build_keys_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text=TAB_KEYS)
        tab.columnconfigure(1, weight=1)
        head = ttk.Frame(tab)
        head.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        ttk.Label(head, text="Clés API des services gratuits", style="Section.TLabel").pack(anchor="w")
        ttk.Label(head, text="Champ vide = garder la clé actuelle, « - » = l'effacer.", style="Hint.TLabel").pack(anchor="w")
        self.key_entries, self.key_states = {}, {}
        for i, (name, label, url) in enumerate(sources.KEY_SOURCES, start=1):
            ttk.Label(tab, text=label, font=("Segoe UI", 9, "bold")).grid(row=i, column=0, sticky="w", padx=(0, 8), pady=2)
            var = tk.StringVar()
            ttk.Entry(tab, textvariable=var, show="•").grid(row=i, column=1, sticky="ew", pady=2)
            state = tk.StringVar()
            link = ttk.Label(tab, textvariable=state, style="Link.TLabel", cursor="hand2")
            link.grid(row=i, column=2, sticky="w", padx=(8, 0))
            link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))
            self.key_entries[name], self.key_states[name] = var, state
        row = len(self.key_entries) + 1
        ttk.Button(tab, style="Primary.TButton", text="Enregistrer les clés", command=self.save_keys).grid(row=row, column=0, sticky="w", pady=(10, 0))
        ttk.Label(tab, text=f"Stockées dans {sources.keys_path()}",
                  style="Hint.TLabel").grid(row=row, column=1, columnspan=2, sticky="w", pady=(10, 0))
        return tab

    def _build_certs_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text=TAB_CERTS)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=2)
        tab.rowconfigure(4, weight=1)
        ttk.Label(tab, text="Points d'accès (hôte, hôte:port ou URL https, un par ligne, port 443 par défaut) :").grid(
            row=0, column=0, sticky="w")
        top = ttk.Frame(tab)
        top.grid(row=1, column=0, sticky="ew")
        top.columnconfigure(0, weight=1)
        self.tls_targets = scrolledtext.ScrolledText(top, height=4, font=("Consolas", 10))
        self.tls_targets.grid(row=0, column=0, sticky="ew")
        side = ttk.Frame(top)
        side.grid(row=0, column=1, sticky="n", padx=(8, 0))
        ttk.Button(side, text="Services https du dernier scan", command=self.tls_from_last).pack(fill="x")
        self.tls_btn = ttk.Button(side, style="Primary.TButton", text="Analyser", command=self.tls_run)
        self.tls_btn.pack(fill="x", pady=(6, 0))
        self._tool_buttons(side, lambda: self.tls_targets.get("1.0", "end"),
                           lambda: self.tls_targets.delete("1.0", "end")).pack(fill="x", pady=(6, 0))
        head = ttk.Frame(tab)
        head.grid(row=2, column=0, sticky="ew", pady=(8, 2))
        self.tls_title = tk.StringVar(value="Versions SSLv3 à TLS 1.3, suites de chiffrement, PQC (X25519MLKEM768), "
                                            "certificat, chaîne, confiance, OCSP, CT, HSTS. Cliquer sur une ligne pour le détail.")
        ttk.Label(head, textvariable=self.tls_title, font=("Segoe UI", 9, "bold")).pack(side="left")
        self._tool_buttons(head, self.tls_table_text, self.reset_tls).pack(side="right")
        table = ttk.Frame(tab)
        table.grid(row=3, column=0, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        cols = (("target", "Cible", 210), ("grade", "Note", 45), ("exp", "Expiration", 130), ("ssl3", "SSLv3", 50),
                ("t10", "1.0", 40), ("t11", "1.1", 40), ("t12", "1.2", 40), ("t13", "1.3", 40), ("pqc", "PQC", 45),
                ("key", "Clé", 120), ("issuer", "Émetteur", 180), ("trust", "Confiance", 80), ("hsts", "HSTS", 50),
                ("alerts", "Alertes", 55))
        self.tls_tree = ttk.Treeview(table, columns=[c[0] for c in cols], show="headings", height=7)
        for col, label, width in cols:
            self.tls_tree.heading(col, text=label, anchor="w")
            self.tls_tree.column(col, width=width, stretch=col in ("target", "issuer"), anchor="w")
        for grade, color in (("A", "#15803d"), ("B", "#65a30d"), ("C", "#ca8a04"), ("T", "#c2410c"), ("F", "#b91c1c")):
            self.tls_tree.tag_configure("g" + grade, foreground=color)
        self.tls_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tls_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tls_tree.configure(yscrollcommand=scroll.set)
        self.tls_tree.bind("<<TreeviewSelect>>", lambda e: self.tls_show_detail())
        self.tls_detail = scrolledtext.ScrolledText(tab, height=8, font=("Consolas", 9), state="disabled")
        self.tls_detail.grid(row=4, column=0, sticky="nsew", pady=(6, 0))
        self.tls_results = {}
        self.last_results = []
        return tab

    def _tool_buttons(self, parent, get_text, reset):
        """Small 'Copier' / 'Reset' pair: get_text returns what to copy, reset empties the zone."""
        box = ttk.Frame(parent)
        ttk.Button(box, text="Copier", width=8, command=lambda: self.copy_text(get_text())).pack(side="left")
        ttk.Button(box, text="Reset", width=8, command=reset).pack(side="left", padx=(4, 0))
        return box

    def copy_text(self, text):
        text = (text or "").strip()
        if not text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.write_log(f"[copie] {len(text.splitlines())} ligne(s) copiée(s) dans le presse-papiers")

    def reset_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def reset_preview(self):
        """Clear the capture shown (the PNG file stays in the output folder)."""
        self.preview_img = None
        self.preview_path = None
        self.preview.configure(image="", text="Aucune capture pour l'instant")
        self.preview_info.set("-")

    def reset_bottom(self):
        self.reset_log()
        self.reset_preview()

    def reset_targets(self):
        self.targets.delete("1.0", "end")
        self.update_targets_count()

    def reset_subs(self):
        self.ct_domains.set("")
        self.ct_title.set("")
        self.ct_names.configure(state="normal")
        self.ct_names.delete("1.0", "end")
        self.ct_names.configure(state="disabled")

    def reset_dns(self):
        self.dns_domain.set("")
        self.dns_title.set("")
        self.dns_last = None
        self.dns_findings.configure(state="normal")
        self.dns_findings.delete("1.0", "end")
        self.dns_findings.configure(state="disabled")
        self.dns_tree.delete(*self.dns_tree.get_children())

    # --- Whois ---------------------------------------------------------------

    def whois_run(self):
        query = self.whois_query.get().strip()
        if not query:
            messagebox.showwarning("NetShot", "Indique un domaine, une IP ou un AS.")
            return
        self.whois_btn.configure(state="disabled", text="Requêtes…")
        q = self.queue

        def work():
            try:
                q.put(("whois", netshot_whois.whois_lookup(query)))
            except Exception as exc:
                q.put(("log", f"[!] Erreur whois : {exc}"))
                q.put(("whois", None))

        threading.Thread(target=work, daemon=True).start()

    def whois_done(self, rep):
        self.whois_btn.configure(state="normal", text="Interroger")
        if not rep:
            return
        self.whois_last = rep
        kinds = {"domain": "domaine", "ip": "adresse IP", "autnum": "AS"}
        name = rep["name"] or rep["query"]
        self.whois_title.set(f"{name} ({kinds.get(rep['kind'], '?')})"
                             + (f" - {rep['rdap_url']}" if rep["rdap_url"] else ""))
        self.whois_findings.configure(state="normal")
        self.whois_findings.delete("1.0", "end")
        for f in rep["findings"]:
            tag = "warn" if f.startswith("⚠") else "good" if f.startswith("✓") else ""
            self.whois_findings.insert("end", "• " + f + "\n", (tag,) if tag else ())
        for e in rep["errors"]:
            self.whois_findings.insert("end", "Erreur : " + e + "\n", ("warn",))
        self.whois_findings.configure(state="disabled")
        self.whois_tree.delete(*self.whois_tree.get_children())
        # A table row cannot wrap: long lists (statut, serveurs de noms) go on continuation rows
        max_chars = max(30, int(self.whois_tree.column("value", "width")) // 7)
        for k, v in rep["rows"]:
            lines, cur = [], ""
            for part in v.split(", "):
                if cur and len(cur) + 2 + len(part) > max_chars:
                    lines.append(cur + ",")
                    cur = part
                else:
                    cur = f"{cur}, {part}" if cur else part
            lines.append(cur)
            for i, line in enumerate(lines):
                self.whois_tree.insert("", "end", values=(k if i == 0 else "", line))
        self.whois_raw.configure(state="normal")
        self.whois_raw.delete("1.0", "end")
        self.whois_raw.insert("end", rep["raw"] or "(pas de réponse WHOIS sur le port 43)")
        self.whois_raw.configure(state="disabled")
        warn = sum(f.startswith("⚠") for f in rep["findings"])
        self.write_log(f"[whois] {name} : {len(rep['rows'])} champ(s), {warn} point(s) d'attention"
                       + (f", {len(rep['errors'])} erreur(s)" if rep["errors"] else ""))

    def reset_whois(self):
        self.whois_query.set("")
        self.whois_title.set("")
        self.whois_last = None
        for w in (self.whois_findings, self.whois_raw):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")
        self.whois_tree.delete(*self.whois_tree.get_children())

    # --- Certificates / TLS -------------------------------------------------

    def tls_from_last(self):
        targets = netshot_tls.tls_targets_from_results(self.last_results)
        if not targets:
            messagebox.showinfo("NetShot", "Aucun service https dans le dernier scan (ou pas encore de scan).")
            return
        existing = set(self.tls_targets.get("1.0", "end").split())
        added = [t for t in targets if t not in existing]
        if added:
            current = self.tls_targets.get("1.0", "end").strip()
            self.tls_targets.insert("end", ("\n" if current else "") + "\n".join(added))
        self.write_log(f"[tls] {len(added)} service(s) https repris du dernier scan")

    def tls_run(self):
        targets = netshot_tls.parse_tls_targets(self.tls_targets.get("1.0", "end").splitlines())
        if not targets:
            messagebox.showwarning("NetShot", "Indique au moins un point d'accès (hôte ou hôte:port).")
            return
        self.tls_btn.configure(state="disabled", text="Analyse…")
        outdir = Path(self.outdir.get())
        q = self.queue

        def work():
            results = netshot_tls.analyze_tls_all(targets, log=lambda m: q.put(("log", m)),
                                                  each=lambda r: q.put(("tls", r)))
            try:
                outdir.mkdir(parents=True, exist_ok=True)
                path = outdir / f"certificats_{datetime.now():%Y%m%d_%H%M%S}.csv"
                netshot_tls.write_tls_csv(results, path)
                q.put(("log", f"[tls] résultats enregistrés dans {path}"))
            except OSError as exc:
                q.put(("log", f"[!] CSV impossible : {exc}"))
            q.put(("tls_done", None))

        self.write_log(f"[tls] analyse de {len(targets)} point(s) d'accès")
        threading.Thread(target=work, daemon=True).start()

    def tls_add(self, r):
        """Add or update one result row; rows are kept sorted from worst to best grade."""
        self.tls_results[r["target"]] = r
        order = {"F": 0, "T": 1, "C": 2, "B": 3, "A": 4, "A+": 5, "-": 6}
        self.tls_tree.delete(*self.tls_tree.get_children())
        for t, x in sorted(self.tls_results.items(), key=lambda kv: (order.get(kv[1]["grade"], 9), kv[0])):
            c = x["cert"] or {}
            yn = lambda b: "oui" if b else "non"  # noqa: E731
            pr = x["protocols"]
            exp = f"{c['not_after']} ({c['days_left']} j)" if c else (x["error"] or "?")
            trust = "" if not c else ("oui" if c["trusted"] and c["name_match"] else
                                      "auto-signé" if c["self_signed"] else "nom ≠" if not c["name_match"] else "non")
            alerts = sum(1 for f in x["findings"] if f.startswith("⚠"))
            self.tls_tree.insert("", "end", iid=t, tags=("g" + x["grade"].rstrip("+"),), values=(
                t, x["grade"], exp, yn(pr.get("SSLv3")), yn(pr.get("TLS1.0")), yn(pr.get("TLS1.1")),
                yn(pr.get("TLS1.2")), yn(pr.get("TLS1.3")), yn(x["pq"]), c.get("key", ""),
                netshot_tls._cn(c.get("issuer", "")), trust, yn(x["hsts"]), alerts))
        bad = sum(1 for x in self.tls_results.values() if x["grade"] in ("F", "T", "C"))
        self.tls_title.set(f"{len(self.tls_results)} point(s) d'accès analysé(s), {bad} à corriger (note C, T ou F)")
        self.nb.tab(self.certs_tab, text=f"{TAB_CERTS} ({len(self.tls_results)})")

    def tls_show_detail(self):
        sel = self.tls_tree.selection()
        if not sel or sel[0] not in self.tls_results:
            return
        self.tls_detail.configure(state="normal")
        self.tls_detail.delete("1.0", "end")
        self.tls_detail.insert("1.0", netshot_tls.format_tls(self.tls_results[sel[0]]))
        self.tls_detail.configure(state="disabled")

    def tls_table_text(self):
        """Every analyzed endpoint in the CLI text format (full detail)."""
        return "".join(netshot_tls.format_tls(r) for r in self.tls_results.values())

    def reset_tls(self):
        self.tls_results.clear()
        self.tls_tree.delete(*self.tls_tree.get_children())
        self.tls_detail.configure(state="normal")
        self.tls_detail.delete("1.0", "end")
        self.tls_detail.configure(state="disabled")
        self.tls_title.set("")
        self.nb.tab(self.certs_tab, text=TAB_CERTS)

    def update_targets_count(self):
        lines = [l.split("#", 1)[0].strip() for l in self.targets.get("1.0", "end").splitlines()]
        lines = [l for l in lines if l]
        n = len(lines)
        self.nb.tab(self.scan_tab, text=f"{TAB_SCAN} ({n})" if n else TAB_SCAN)
        # Rough count of addresses: IPv4 CIDR ranges are expanded, AS numbers are not known yet
        addrs, has_as = 0, False
        for l in lines:
            ip, sep, bits = l.partition("/")
            if sep and bits.isdigit() and ip.count(".") == 3:
                addrs += 2 ** (32 - min(32, int(bits)))
            elif sources.ASN_RE.match(l):
                has_as = True
            else:
                addrs += 1
        text = f"{n} entrée{'s' if n > 1 else ''}" if n else "Aucune cible"
        if addrs > n:
            text += f" · ~{addrs:,} adresses".replace(",", " ")
        self.targets_pill.set(text + (" + AS" if has_as else ""))

    def update_ua_count(self):
        n = sum(v.get() for v in self.ua_vars.values())
        self.ua_count.set(f"{n} sélectionné{'s' if n > 1 else ''}" if n else "UA du navigateur")

    def update_fold_summaries(self):
        try:
            delay = float(self.delay.get())
            adv = (f"{self.concurrency.get()} en parallèle · TCP {self.connect_timeout.get()} s · "
                   f"page {self.page_timeout.get()} s" + (f" · délai {delay:g} s" if delay > 0 else ""))
        except (tk.TclError, ValueError):
            adv = "valeur invalide"
        self.adv_sum.set(f"{adv} · {self.resolution.get().split(' (')[0].replace(' x ', '×')}")
        n = len([x for x in self.exclude.get().replace(",", " ").split() if x])
        proxy = self.proxy.get().strip()
        self.scope_sum.set((f"proxy {proxy}" if proxy else "aucun proxy") + " · " +
                           (f"{n} exclusion{'s' if n > 1 else ''}" if n else "aucune exclusion"))

    # --- UI helpers -------------------------------------------------------

    def load_file(self):
        path = filedialog.askopenfilename(title="Fichier de cibles",
                                          filetypes=[("Texte ou CSV", "*.txt *.csv"), ("Tous", "*.*")])
        if path:
            n = self.add_targets(netshot.read_target_file(path))
            self.write_log(f"[import] {Path(path).name} : {n} cible(s) ajoutée(s)")

    def add_targets(self, lines):
        """Append lines to the targets box, skipping ones already there. Returns how many were added."""
        existing = {l.strip() for l in self.targets.get("1.0", "end").splitlines() if l.strip()}
        added = [l for l in lines if l.strip() and l.strip() not in existing]
        if added:
            current = self.targets.get("1.0", "end").strip()
            self.targets.insert("end", ("\n" if current else "") + "\n".join(added))
        self.update_targets_count()
        return len(added)

    def pick_outdir(self):
        path = filedialog.askdirectory(title="Dossier de sortie", initialdir=self.outdir.get())
        if path:
            self.outdir.set(path)

    def write_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n", ("err",) if text.startswith(("[-]", "[!]")) else ())
        lines = int(self.log.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            self.log.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self.write_log(payload)
                elif kind == "progress":
                    done, total, found = payload
                    self.progress.configure(maximum=max(total, 1), value=done)
                    self.status.set(f"{done}/{total} vérifiés - {found} services trouvés")
                elif kind == "shot":
                    self.show_preview(*payload)
                elif kind == "ct":
                    self.ct_done(payload)
                elif kind == "whois":
                    self.whois_done(payload)
                elif kind == "dns":
                    self.dns_done(payload)
                elif kind == "leak":
                    self.leak_done(payload)
                elif kind == "tls":
                    self.tls_add(payload)
                elif kind == "tls_done":
                    self.tls_btn.configure(state="normal", text="Analyser")
                elif kind == "results":
                    self.last_results = payload
                elif kind == "done":
                    self.finish(payload)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def select_uas(self, names):
        for name, var in self.ua_vars.items():
            var.set(name in names)
        self.update_ua_count()

    def selected_uas(self):
        values = [name for name in self.ua_names if self.ua_vars[name].get()]
        if self.custom_ua.get().strip():
            values.append(self.custom_ua.get().strip())
        return netshot.resolve_user_agents(values)

    def show_preview(self, path, url, status, title, ua_name):
        try:
            img = tk.PhotoImage(file=path)  # Tk 8.6 reads PNG natively
        except tk.TclError:
            return
        # Integer downscale to fit the fixed preview area (no Pillow needed)
        avail_w = max(self.preview_area.winfo_width(), 200)
        avail_h = max(self.preview_area.winfo_height(), 120)
        factor = max(1, -(-img.width() // avail_w), -(-img.height() // avail_h))
        self.preview_img = img.subsample(factor) if factor > 1 else img
        self.preview.configure(image=self.preview_img, text="")
        self.preview_path = Path(path)
        self.preview_info.set(f"{url}  [{status}]  {title}  - UA : {ua_name}")
        if self.bottom.index("current") != self.bottom.index(self.preview_box):
            self.bottom.tab(self.preview_box, text="Dernière capture  \u25cf")

    # --- Passive sources and API keys ----------------------------------------

    def refresh_sources(self, first=False):
        """Enable the sources that can run with the current keys; tick defaults on first call
        and the keyed sources that just got a key."""
        for s in sources.SUB_SOURCES:
            ok = sources.usable(s, self.keys)
            cb, var = self.ct_checks[s["name"]], self.ct_sources[s["name"]]
            was_disabled = cb.instate(["disabled"])
            cb.state(["!disabled"] if ok else ["disabled"])
            if not ok:
                var.set(False)
            elif first or (was_disabled and s["default"]):
                var.set(s["default"])
            suffix = " (lent)" if s["slow"] else ""
            cb.configure(text=s["label"] + suffix + ("" if ok else " (clé)"))
        n_set = 0
        for name, state in self.key_states.items():
            is_set = bool(self.keys.get(name))
            n_set += is_set
            state.set(("configurée" if is_set else "non configurée") + " · obtenir")
        self.nb.tab(self.keys_tab, text=f"{TAB_KEYS} ({n_set}/{len(sources.KEY_SOURCES)})")

    def save_keys(self):
        """Save the keys typed in the Clés API tab. Empty field = keep, '-' = remove."""
        changes = {}
        for name, var in self.key_entries.items():
            value = var.get().strip()
            if value == "-":
                changes[name] = None
            elif value:
                changes[name] = value
        if not changes:
            self.write_log("[keys] aucun champ rempli : rien à enregistrer")
            return
        try:
            sources.update_keys(changes)  # merges into the file on disk, only the fields typed
        except (OSError, ValueError) as exc:
            messagebox.showerror("NetShot", f"Impossible d'enregistrer : {exc}")
            return
        for var in self.key_entries.values():
            var.set("")
        self.keys = sources.load_keys()
        self.refresh_sources()
        self.write_log(f"[keys] clés enregistrées dans {sources.keys_path()}")

    def ct_search(self):
        domains = [d for d in self.ct_domains.get().replace(";", ",").replace(" ", ",").split(",") if d.strip()]
        chosen = [name for name, var in self.ct_sources.items() if var.get()]
        if not domains or not chosen:
            messagebox.showwarning("NetShot", "Indique au moins un domaine et une source.")
            return
        self.ct_btn.configure(state="disabled", text="Recherche…")
        q = self.queue
        # Read tkinter variables here: they must not be touched from the worker thread
        keys, resolve, private = dict(self.keys), self.ct_resolve.get(), self.ct_private.get()

        def work():
            try:
                names = sources.ct_lookup(domains, chosen, keys, resolve=resolve, private_only=private,
                                          log=lambda m: q.put(("log", m)))
            except Exception as exc:
                q.put(("log", f"[!] Erreur sources : {exc}"))
                names = []
            q.put(("ct", names))

        threading.Thread(target=work, daemon=True).start()

    def ct_done(self, names):
        self.ct_btn.configure(state="normal", text="Rechercher")
        added = self.add_targets(names)
        self.ct_title.set(f"{len(names)} nom(s) trouvé(s), {added} nouveau(x) ajouté(s) aux cibles")
        self.ct_names.configure(state="normal")
        self.ct_names.delete("1.0", "end")
        self.ct_names.insert("1.0", "\n".join(names))
        self.ct_names.configure(state="disabled")
        self.write_log(f"[src] {added} nom(s) ajouté(s) aux cibles")

    # --- DNS --------------------------------------------------------------

    def dns_run(self):
        domain, server = self.dns_domain.get().strip(), self.dns_server.get().strip()
        if not sources.normalize_domain(domain):
            messagebox.showwarning("NetShot", "Indique un domaine.")
            return
        self.dns_btn.configure(state="disabled", text="Requêtes…")
        q = self.queue

        def work():
            try:
                q.put(("dns", netshot_dns.dns_lookup(domain, server)))
            except Exception as exc:
                q.put(("log", f"[!] Erreur DNS : {exc}"))
                q.put(("dns", None))

        threading.Thread(target=work, daemon=True).start()

    def dns_done(self, rep):
        self.dns_btn.configure(state="normal", text="Interroger")
        if not rep:
            return
        self.dns_last = rep
        any_part = " : " + " | ".join(f"{r['type']} {r['data']}" for r in rep["any"]) if rep["any"] else ""
        self.dns_title.set(f"{rep['domain']} - {len(rep['records'])} enregistrements (serveur {rep['server'] or '?'})"
                           f"    {rep['any_note']}{any_part}")
        self.dns_findings.configure(state="normal")
        self.dns_findings.delete("1.0", "end")
        for f in rep["findings"]:
            tag = "warn" if f.startswith("⚠") else "good" if f.startswith("✓") else ""
            self.dns_findings.insert("end", "• " + f + "\n", (tag,) if tag else ())
        if rep["errors"]:
            self.dns_findings.insert("end", "Erreurs : " + " · ".join(rep["errors"]) + "\n")
        self.dns_findings.configure(state="disabled")
        self.dns_tree.delete(*self.dns_tree.get_children())
        for r in rep["records"]:
            self.dns_tree.insert("", "end", values=(r["name"], r["ttl"], r["type"], r["data"]))
        warn = sum(f.startswith("⚠") for f in rep["findings"])
        self.write_log(f"[dns] {rep['domain']} : {len(rep['records'])} enregistrements, {warn} point(s) d'attention")

    # --- Leaks (LeakCheck) ----------------------------------------------------

    def leak_run(self):
        query, qtype = self.leak_query.get().strip(), self.leak_type.get()
        key = sources.load_keys().get("leakcheck", "")
        if not key:
            messagebox.showwarning("NetShot", "Clé LeakCheck absente : la saisir dans l'onglet Clés API.")
            return
        if len(query) < 3:
            messagebox.showwarning("NetShot", "Indique au moins 3 caractères.")
            return
        try:
            limit = int(self.leak_limit.get())
        except ValueError:
            limit = 100
        self.leak_btn.configure(state="disabled", text="Recherche…")
        q = self.queue

        def work():
            try:
                q.put(("leak", (query, leakcheck.lookup(query, key, qtype, limit))))
            except Exception as exc:
                q.put(("log", f"[!] {exc}"))
                q.put(("leak", None))

        threading.Thread(target=work, daemon=True).start()

    def leak_done(self, payload):
        self.leak_btn.configure(state="normal", text="Rechercher")
        if not payload:
            return
        query, data = payload
        rows = data.get("result") or []
        # Same columns as the data: known fields in a fixed order, then any other field returned
        present = []
        for r in rows:
            for k in r:
                if k not in ("source", "fields") and k not in present:
                    present.append(k)
        data_cols = [k for k in LEAK_DATA_COLS if k in present] + sorted(k for k in present if k not in LEAK_DATA_COLS)
        self.leak_cols = [c for c, _, _ in LEAK_SOURCE_COLS] + data_cols + ["fields"]
        self.leak_tree.configure(columns=self.leak_cols)
        headings = {c: (label, w) for c, label, w in LEAK_SOURCE_COLS}
        headings.update(LEAK_DATA_COLS)
        headings["fields"] = ("Champs exposés", 220)
        for c in self.leak_cols:
            label, width = headings.get(c, (c, 110))
            self.leak_tree.heading(c, text=label, anchor="w", command=lambda c=c: self.leak_sort(c))
            self.leak_tree.column(c, width=width, stretch=False, anchor="w")
        self.leak_rows = rows
        self.leak_sort_state = (None, False)
        self.leak_render()
        self.leak_title.set(f"{query} : {data.get('found', len(rows))} trouvé(s), {len(rows)} affiché(s) - "
                            f"quota restant {data.get('quota', '?')}")
        n_src = len({(r.get('source') or {}).get('name') for r in rows})
        n_pw = sum(1 for r in rows if r.get("password"))
        self.write_log(f"[fuites] {query} : {len(rows)} ligne(s), {n_src} source(s), {n_pw} avec mot de passe")

    def _leak_values(self, r, show_pw):
        src = r.get("source") or {}
        flag = lambda v: "oui" if v in (1, True, "1") else ""  # noqa: E731
        out = [src.get("name", ""), src.get("breach_date", ""), flag(src.get("unverified")),
               flag(src.get("passwordless")), flag(src.get("compilation"))]
        for c in self.leak_cols[len(LEAK_SOURCE_COLS):-1]:
            v = r.get(c, "")
            v = ", ".join(map(str, v)) if isinstance(v, list) else ("" if v is None else str(v))
            if c == "password" and v and not show_pw:
                v = LEAK_MASK
            out.append(v)
        out.append(", ".join(r.get("fields") or []))
        return out

    def leak_render(self):
        self.leak_tree.delete(*self.leak_tree.get_children())
        show = self.leak_show_pw.get()
        for r in self.leak_rows:
            self.leak_tree.insert("", "end", values=self._leak_values(r, show))

    def leak_sort(self, col):
        last, rev = getattr(self, "leak_sort_state", (None, False))
        rev = not rev if last == col else False
        self.leak_sort_state = (col, rev)
        i = self.leak_cols.index(col)
        self.leak_rows.sort(key=lambda r: self._leak_values(r, True)[i].lower(), reverse=rev)
        self.leak_render()

    def leak_table_text(self):
        """Tab-separated table, as shown (passwords masked unless displayed)."""
        if not self.leak_rows:
            return ""
        lines = ["\t".join(self.leak_tree.heading(c, "text") for c in self.leak_cols)]
        show = self.leak_show_pw.get()
        lines += ["\t".join(self._leak_values(r, show)) for r in self.leak_rows]
        return "\n".join(lines)

    def leak_export(self):
        if not self.leak_rows:
            messagebox.showinfo("NetShot", "Aucun résultat à exporter.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile=f"fuites_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path:
            return
        import csv
        show = self.leak_show_pw.get()
        # utf-8-sig and ';' so that Excel with French settings opens it directly
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow([self.leak_tree.heading(c, "text") for c in self.leak_cols])
            for r in self.leak_rows:
                w.writerow(self._leak_values(r, show))
        self.write_log(f"[fuites] {len(self.leak_rows)} ligne(s) exportée(s) dans {path}"
                       + ("" if show else " (mots de passe masqués)"))

    def reset_leaks(self):
        self.leak_rows = []
        self.leak_tree.delete(*self.leak_tree.get_children())
        self.leak_title.set("")

    def dns_add_hosts(self):
        if self.dns_last:
            n = self.add_targets(netshot_dns.dns_hosts(self.dns_last["records"]))
            self.write_log(f"[dns] {n} hôte(s) ajouté(s) aux cibles")

    def dns_copy(self):
        if self.dns_last:
            self.root.clipboard_clear()
            self.root.clipboard_append(netshot_dns.format_dig(self.dns_last))
            self.write_log("[dns] résultat copié au format dig")

    # --- Scan -------------------------------------------------------------

    def load_exclusions(self):
        path = filedialog.askopenfilename(title="Cibles hors périmètre (une par ligne)",
                                          filetypes=[("Texte", "*.txt *.csv"), ("Tous", "*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                items = [l.split("#", 1)[0].strip() for l in fh.read().splitlines()]
        except OSError as exc:
            messagebox.showerror("NetShot", str(exc))
            return
        current = self.exclude.get().strip()
        self.exclude.set(", ".join(x for x in [current] + items if x))
        self.write_log(f"[exclusion] {sum(1 for x in items if x)} entrée(s) chargée(s) depuis {path}")

    def start(self):
        if netshot.async_playwright is None:
            messagebox.showerror("NetShot", netshot.PLAYWRIGHT_MISSING.replace(": ", " :\n", 1))
            return
        items = self.targets.get("1.0", "end").splitlines()
        if not any(i.split("#", 1)[0].strip() for i in items):
            messagebox.showwarning("NetShot", "Aucune cible.")
            return
        try:
            ports = netshot.parse_ports(self.ports.get())
            concurrency = int(self.concurrency.get())
            connect_timeout = float(self.connect_timeout.get())
            page_timeout = float(self.page_timeout.get())
            delay = max(0.0, float(self.delay.get()))
        except (ValueError, tk.TclError):
            messagebox.showerror("NetShot", "Ports ou options invalides.")
            return
        if not ports:
            messagebox.showerror("NetShot", "Aucun port valide.")
            return
        try:
            proxy = parse_proxy(self.proxy.get())
        except ValueError as exc:
            messagebox.showerror("NetShot", f"Proxy invalide : {exc}")
            return
        exclusions = read_exclusions([self.exclude.get()])

        if any(sources.ASN_RE.match(i.split("#", 1)[0].strip()) for i in items):
            self.status.set("Lecture des plages des AS (RIPEstat)…")
            self.root.update_idletasks()
            items = sources.expand_asns(items, log=self.write_log)
        n = netshot.count_targets(items)
        if n > netshot.MAX_HOSTS_DEFAULT:
            messagebox.showerror("NetShot", f"{n} adresses : plage trop grande (max {netshot.MAX_HOSTS_DEFAULT}).")
            return
        hosts = netshot.parse_targets(items)
        user_agents = self.selected_uas()
        if len(hosts) * len(ports) > 5000 and not messagebox.askyesno(
                "netshot", f"{len(hosts)} hôtes x {len(ports)} ports = {len(hosts) * len(ports)} tests.\nContinuer ?"):
            return

        # One sub-folder per scan so results never overwrite each other
        output = Path(self.outdir.get()) / f"scan_{datetime.now():%Y%m%d_%H%M%S}"
        width, height = RESOLUTIONS.get(self.resolution.get(), (1920, 1080))
        args = SimpleNamespace(output=output, concurrency=concurrency, connect_timeout=connect_timeout,
                               page_timeout=page_timeout, delay=delay, user_agents=user_agents,
                               width=width, height=height, enrich=self.enrich.get(),
                               reputation=self.reputation.get(), keys=dict(self.keys),
                               tls=self.tls_scan.get(), label=self.label_shots.get(),
                               dirs=dir_words() if self.probe_dirs.get() else None,
                               proxy=proxy, exclusions=exclusions,
                               files=file_rules() if self.probe_files.get() else None,
                               waf_probe=self.waf_probe.get())
        self.report = output / "report.html"

        self.stop_event.clear()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.report_btn.configure(state="disabled")
        self.folder_btn.configure(state="disabled")
        self.progress.configure(value=0)
        self.write_log(f"=== {len(hosts)} hôtes x {len(ports)} ports x {len(user_agents)} UA, "
                       f"{width}x{height} -> {output}")

        self.worker = threading.Thread(target=self.run_scan, args=(args, hosts, ports), daemon=True)
        self.worker.start()

    def run_scan(self, args, hosts, ports):
        """Runs in a background thread with its own asyncio loop."""
        q = self.queue
        try:
            results = asyncio.run(netshot.main_async(
                args, hosts, ports,
                log=lambda m: q.put(("log", m)),
                stop=self.stop_event,
                on_progress=lambda d, t, f: q.put(("progress", (d, t, f))),
                on_shot=lambda *shot: q.put(("shot", shot)),
                on_tls=lambda r: q.put(("tls", r)),
            ))
            q.put(("results", results))
            q.put(("done", None))
        except Exception as exc:
            q.put(("done", f"{type(exc).__name__}: {exc}"))

    def stop(self):
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self.status.set("Arrêt en cours (fin des pages déjà ouvertes)…")

    def finish(self, error):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if error:
            self.write_log(f"[!] Erreur : {error}")
            self.status.set("Erreur - voir le journal.")
            if "Executable doesn't exist" in error:
                messagebox.showerror("NetShot", "Chromium manquant :\npython -m playwright install chromium")
            return
        if self.report and self.report.exists():
            self.report_btn.configure(state="normal")
            self.folder_btn.configure(state="normal")
        self.status.set(("Arrêté. " if self.stop_event.is_set() else "Terminé. ") + self.status.get())

    @staticmethod
    def open_path(path):
        if os.name == "nt":
            os.startfile(path)
        else:
            webbrowser.open(path.as_uri())

    def open_report(self):
        if self.report and self.report.exists():
            self.open_path(self.report)

    def open_folder(self):
        if self.report and self.report.parent.exists():
            self.open_path(self.report.parent)

    def on_close(self):
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("NetShot", "Un scan est en cours. Quitter quand même ?"):
                return
            self.stop_event.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista" if os.name == "nt" else "clam")
    except tk.TclError:
        pass
    NetshotApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
