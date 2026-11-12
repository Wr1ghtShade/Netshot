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
from . import ROOT as HERE, ASSETS
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


# Soft colours for the main action buttons: (background, hover, text)
SOFT_COLORS = {"primary": ("#dbeafe", "#bfdbfe", "#1e3a8a"),   # soft blue
               "danger": ("#fee2e2", "#fecaca", "#991b1b")}    # soft red
SOFT_DISABLED = ("#f1f5f9", "#94a3b8")                         # background, text
SOFT_COLORS_DARK = {"primary": ("#1e3a5f", "#26507f", "#bfdbfe"),
                    "danger": ("#4c1d1d", "#652626", "#fecaca")}
SOFT_DISABLED_DARK = ("#2a2d33", "#6b7280")


class SoftButton(tk.Button):
    """Flat tk.Button in a soft colour, lighter on hover, greyed out when disabled.
    Same API as the ttk buttons it replaces: configure(state=..., text=...)."""

    def __init__(self, parent, kind="primary", **kw):
        self._kind, self._disabled = kind, SOFT_DISABLED
        self._bg, self._hover, fg = SOFT_COLORS[kind]
        super().__init__(parent, fg=fg, activeforeground=fg, activebackground=self._hover,
                         disabledforeground=SOFT_DISABLED[1], relief="flat", bd=0, highlightthickness=0,
                         padx=14, pady=4, font=("Segoe UI", 9, "bold"), **kw)
        self._paint()
        self.bind("<Enter>", lambda e: self._paint(hover=True))
        self.bind("<Leave>", lambda e: self._paint())

    def _paint(self, hover=False):
        off = str(self["state"]) == "disabled"
        tk.Button.configure(self, bg=self._disabled[0] if off else (self._hover if hover else self._bg),
                            cursor="arrow" if off else "hand2")

    def set_dark(self, dark):
        self._bg, self._hover, fg = (SOFT_COLORS_DARK if dark else SOFT_COLORS)[self._kind]
        self._disabled = SOFT_DISABLED_DARK if dark else SOFT_DISABLED
        tk.Button.configure(self, fg=fg, activeforeground=fg, activebackground=self._hover,
                            disabledforeground=self._disabled[1])
        self._paint()

    def configure(self, cnf=None, **kw):
        result = super().configure(cnf, **kw)
        if "state" in kw or (isinstance(cnf, dict) and "state" in cnf):
            self._paint()
        return result

    config = configure


class NetshotApp:
    def __init__(self, root):
        self.root = root
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.report = None

        root.title("NetShot - captures réseau")
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
        # Brand: small logo + NetShot (icon.png is 256 px: subsample to 32 px)
        if icon.exists():
            self.logo_small = self.icon.subsample(8)
            ttk.Label(header, image=self.logo_small).pack(side="left", padx=(0, 6))
        ttk.Label(header, text="NetShot", font=("Segoe UI", 14, "bold")).pack(side="left")
        tk.Button(header, text="Quitter", command=self.on_close, bg="#dc2626", fg="white",
                  activebackground="#b91c1c", activeforeground="white", relief="flat",
                  font=("Segoe UI", 9, "bold"), padx=14, pady=2, cursor="hand2").pack(side="right")
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

        # Log (left) + preview of the last screenshot (right), shared by all tabs
        bottom = ttk.PanedWindow(outer, orient="horizontal")
        bottom.grid(row=2, column=0, sticky="nsew")
        self.bottom, self.outer = bottom, outer
        log_box = ttk.LabelFrame(bottom, text="Journal", padding=4)
        bottom.add(log_box, weight=1)
        # Reset of the log also clears the last capture shown on the right
        self._tool_buttons(log_box, lambda: self.log.get("1.0", "end"), self.reset_bottom).pack(anchor="e")
        self.log = scrolledtext.ScrolledText(log_box, height=5, width=50, font=("Consolas", 9), state="disabled")
        self.log.tag_configure("err", foreground="#dc2626")
        self.log.pack(fill="both", expand=True)
        preview = ttk.LabelFrame(bottom, text="Dernière capture", padding=4)
        bottom.add(preview, weight=1)
        self.preview_box = preview
        self.preview_info = tk.StringVar(value="-")
        info_row = ttk.Frame(preview)
        info_row.pack(fill="x")
        ttk.Button(info_row, text="Effacer", width=8, command=self.reset_preview).pack(side="right")
        ttk.Label(info_row, textvariable=self.preview_info, wraplength=420).pack(side="left", anchor="w")
        # Fixed-size area: the image is scaled to it, so it never pushes the window
        self.preview_area = ttk.Frame(preview)
        self.preview_area.pack(fill="both", expand=True)
        self.preview_area.pack_propagate(False)
        self.preview = ttk.Label(self.preview_area, anchor="center", cursor="hand2", text="Aucune capture pour l'instant")
        self.preview.pack(fill="both", expand=True)
        self.preview.bind("<Button-1>", lambda e: self.preview_path and self.open_path(self.preview_path))
        self.refresh_sources(first=True)
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.layout_for_tab())
        theme.themed_scrollbars(root)
        self.theme = theme.ThemeManager(root)
        self.set_theme(theme.load_choice() or ("dark" if theme.system_prefers_dark() else "light"), save=False)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.poll_queue)

    # --- Tabs -------------------------------------------------------------

    def _build_scan_tab(self):
        main = ttk.Frame(self.nb, padding=10)
        self.nb.add(main, text=TAB_SCAN)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(1, weight=1)

        ttk.Label(main, text="Cibles (IP, CIDR, AS1234 ou hôte, une par ligne) :").grid(row=0, column=0, columnspan=3, sticky="w")
        self.targets = scrolledtext.ScrolledText(main, height=6, font=("Consolas", 10))
        self.targets.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(2, 8))
        self.targets.bind("<KeyRelease>", lambda e: self.update_targets_count())
        side = ttk.Frame(main)
        side.grid(row=1, column=2, sticky="n", padx=(8, 0), pady=(2, 0))
        ttk.Button(side, text="Charger fichier / CSV…", command=self.load_file).pack(fill="x")
        self._tool_buttons(side, lambda: self.targets.get("1.0", "end"), self.reset_targets).pack(fill="x", pady=(6, 0))

        ttk.Label(main, text="Ports :").grid(row=2, column=0, sticky="w")
        self.ports = tk.StringVar(value=",".join(map(str, netshot.DEFAULT_PORTS)))
        ttk.Entry(main, textvariable=self.ports).grid(row=2, column=1, sticky="ew", pady=2)
        presets = ttk.Menubutton(main, text="Préréglages ▾")
        menu = tk.Menu(presets, tearoff=0)
        for label, value in (("Par défaut (80, 443, 8000, 8080, 8443)", ",".join(map(str, netshot.DEFAULT_PORTS))),
                             ("Web étendu (~100 ports)", "web"), ("Services non web (SSH, FTP, RDP, bases…)", "services"),
                             ("Web étendu + services", "web,services")):
            menu.add_command(label=label, command=lambda v=value: self.ports.set(v))
        presets["menu"] = menu
        presets.grid(row=2, column=2, padx=(8, 0), sticky="w")
        ttk.Label(main, text="Dossier de sortie :").grid(row=3, column=0, sticky="w")
        self.outdir = tk.StringVar(value=str(HERE / "screenshots"))
        ttk.Entry(main, textvariable=self.outdir).grid(row=3, column=1, sticky="ew", pady=2)
        ttk.Button(main, text="Parcourir…", command=self.pick_outdir).grid(row=3, column=2, padx=(8, 0))

        opts = ttk.Frame(main)
        opts.grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 2))
        self.concurrency = tk.IntVar(value=10)
        self.connect_timeout = tk.DoubleVar(value=1.5)
        self.page_timeout = tk.DoubleVar(value=15)
        self.delay = tk.DoubleVar(value=0)
        for label, var, lo, hi, inc in (
            ("Parallèle", self.concurrency, 1, 200, 1),
            ("Timeout TCP (s)", self.connect_timeout, 0.2, 30, 0.5),
            ("Timeout page (s)", self.page_timeout, 1, 120, 1),
            ("Délai entre captures (s)", self.delay, 0, 600, 0.5),
        ):
            ttk.Label(opts, text=label).pack(side="left")
            ttk.Spinbox(opts, textvariable=var, from_=lo, to=hi, increment=inc, width=6).pack(side="left", padx=(4, 16))
        opts2 = ttk.Frame(main)
        opts2.grid(row=5, column=0, columnspan=3, sticky="w", pady=(2, 8))
        ttk.Label(opts2, text="Résolution").pack(side="left")
        self.resolution = tk.StringVar(value="1920 x 1080 (Full HD)")
        ttk.Combobox(opts2, textvariable=self.resolution, values=list(RESOLUTIONS), state="readonly",
                     width=20).pack(side="left", padx=(4, 16))
        self.enrich = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts2, text="Enrichir les IP et les versions (Shodan, LeakIX, NVD, KEV, EPSS)",
                        variable=self.enrich).pack(side="left", padx=(0, 16))
        self.tls_scan = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts2, text="Analyser les certificats TLS", variable=self.tls_scan).pack(side="left")
        self.label_shots = tk.BooleanVar(value=True)
        opts3 = ttk.Frame(main)
        opts3.grid(row=6, column=0, columnspan=3, sticky="w", pady=(0, 8))
        ttk.Checkbutton(opts3, text="Inscrire l'URL sur les captures", variable=self.label_shots).pack(side="left")
        self.probe_dirs = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts3, text="Tester les dossiers courants (Index of)", variable=self.probe_dirs).pack(
            side="left", padx=(16, 0))
        self.probe_files = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts3, text="Tester les fichiers sensibles (.env, .git…)", variable=self.probe_files).pack(
            side="left", padx=(16, 0))
        opts4 = ttk.Frame(main)
        opts4.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        ttk.Label(opts4, text="Proxy").pack(side="left")
        self.proxy = tk.StringVar()
        ttk.Entry(opts4, textvariable=self.proxy, width=26).pack(side="left", padx=(4, 4))
        ttk.Label(opts4, text="ex. http://127.0.0.1:8080", foreground="#888").pack(side="left", padx=(0, 16))
        ttk.Label(opts4, text="Hors périmètre").pack(side="left")
        self.exclude = tk.StringVar()
        ttk.Entry(opts4, textvariable=self.exclude).pack(side="left", fill="x", expand=True, padx=(4, 4))
        ttk.Button(opts4, text="Fichier…", command=self.load_exclusions).pack(side="left")

        # User agents (right column). Nothing selected = Chromium's own UA.
        ua_box = ttk.LabelFrame(main, text="User agents (une capture par UA)", padding=6)
        ua_box.grid(row=0, column=3, rowspan=8, sticky="nsew", padx=(12, 0))
        ua_box.rowconfigure(0, weight=1)
        ua_box.columnconfigure(0, weight=1)
        self.ua_names = list(netshot.USER_AGENTS)
        self.ua_list = tk.Listbox(ua_box, selectmode="multiple", height=8, exportselection=False, width=24)
        for name in self.ua_names:
            kind = "bot" if name in netshot.BOT_UAS else "nav"
            self.ua_list.insert("end", f"{name}  [{kind}]")
        self.ua_list.grid(row=0, column=0, columnspan=4, sticky="nsew")
        for col, (label, names) in enumerate((
                ("Navig.", netshot.BROWSER_UAS), ("Bots", netshot.BOT_UAS),
                ("Tous", netshot.USER_AGENTS), ("Aucun", {}))):
            ttk.Button(ua_box, text=label, width=7,
                       command=lambda n=names: self.select_uas(n)).grid(row=1, column=col, pady=(4, 0))
        ttk.Label(ua_box, text="UA personnalisé :").grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        self.custom_ua = tk.StringVar()
        ttk.Entry(ua_box, textvariable=self.custom_ua).grid(row=3, column=0, columnspan=4, sticky="ew")

        actions = ttk.Frame(main)
        actions.grid(row=8, column=0, columnspan=4, sticky="ew")
        self.start_btn = SoftButton(actions, text="Lancer le scan", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = SoftButton(actions, "danger", text="Arrêter", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.report_btn = ttk.Button(actions, text="Ouvrir le rapport", command=self.open_report, state="disabled")
        self.report_btn.pack(side="right")
        self.folder_btn = ttk.Button(actions, text="Ouvrir le dossier", command=self.open_folder, state="disabled")
        self.folder_btn.pack(side="right", padx=8)
        self.progress = ttk.Progressbar(main, mode="determinate")
        self.progress.grid(row=9, column=0, columnspan=4, sticky="ew", pady=(10, 2))
        self.status = tk.StringVar(value="Prêt. Aucun UA sélectionné = UA du navigateur.")
        ttk.Label(main, textvariable=self.status).grid(row=10, column=0, columnspan=4, sticky="w")
        return main

    def _build_subs_tab(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text=TAB_DOMAIN)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
        ttk.Label(tab, text="Domaines :").grid(row=0, column=0, sticky="w")
        self.ct_domains = tk.StringVar()
        ttk.Entry(tab, textvariable=self.ct_domains).grid(row=0, column=1, sticky="ew", padx=4)
        self.ct_btn = SoftButton(tab, text="Rechercher", command=self.ct_search)
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
        ttk.Label(tab, foreground="#6b7280", text="Les sources marquées (clé) demandent une clé gratuite "
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
        self.dns_btn = SoftButton(tab, text="Interroger", command=self.dns_run)
        self.dns_btn.grid(row=0, column=4)
        ttk.Label(tab, foreground="#6b7280", wraplength=1050, text="Serveur vide = résolveurs du système. "
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
        if save:
            theme.save_choice(name)

    def toggle_theme(self):
        self.set_theme("light" if self.theme.dark else "dark")

    def layout_for_tab(self):
        """Whois uses the whole window height (no journal, no capture); Scan shows the journal and the
        last capture; every other tab shows the journal alone, over the full width."""
        tab = self.nb.tab(self.nb.select(), "text")
        if tab == TAB_WHOIS:
            self.bottom.grid_remove()
            self.outer.rowconfigure(2, weight=0)
            return
        self.bottom.grid()
        # Scan: taller journal and capture (original layout); other tabs: compact journal
        scan = self.nb.select() == str(self.scan_tab)
        self.outer.rowconfigure(1, weight=3 if scan else 6)
        self.outer.rowconfigure(2, weight=2 if scan else 1)
        self.log.configure(height=10 if scan else 5)
        shown = str(self.preview_box) in self.bottom.panes()
        if self.nb.select() != str(self.scan_tab):  # the capture only matters while scanning
            if shown:
                self.bottom.forget(self.preview_box)
        elif not shown:
            self.bottom.add(self.preview_box, weight=1)

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
        self.whois_btn = SoftButton(tab, text="Interroger", command=self.whois_run)
        self.whois_btn.grid(row=0, column=2)
        ttk.Label(tab, foreground="#6b7280", wraplength=1050, text="RDAP (registre officiel, via HTTPS) pour le "
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
        self.leak_btn = SoftButton(tab, text="Rechercher", command=self.leak_run)
        self.leak_btn.grid(row=0, column=6)
        opts = ttk.Frame(tab)
        opts.grid(row=1, column=0, columnspan=7, sticky="w", pady=(6, 0))
        self.leak_show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Afficher les mots de passe", variable=self.leak_show_pw,
                        command=self.leak_render).pack(side="left")
        ttk.Label(opts, foreground="#6b7280", text="   LeakCheck Pro API v2 (clé dans l'onglet Clés API). "
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
        ttk.Label(tab, text="Champ vide = garder la clé actuelle, « - » = l'effacer.").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self.key_entries, self.key_states = {}, {}
        for i, (name, label, url) in enumerate(sources.KEY_SOURCES, start=1):
            ttk.Label(tab, text=label).grid(row=i, column=0, sticky="w", padx=(0, 8), pady=2)
            var = tk.StringVar()
            ttk.Entry(tab, textvariable=var, show="•").grid(row=i, column=1, sticky="ew", pady=2)
            state = tk.StringVar()
            link = ttk.Label(tab, textvariable=state, foreground="#2563eb", cursor="hand2")
            link.grid(row=i, column=2, sticky="w", padx=(8, 0))
            link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))
            self.key_entries[name], self.key_states[name] = var, state
        row = len(self.key_entries) + 1
        SoftButton(tab, text="Enregistrer les clés", command=self.save_keys).grid(row=row, column=0, sticky="w", pady=(10, 0))
        ttk.Label(tab, text=f"Stockées dans {sources.keys_path()}",
                  foreground="#6b7280").grid(row=row, column=1, columnspan=2, sticky="w", pady=(10, 0))
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
        self.tls_btn = SoftButton(side, text="Analyser", command=self.tls_run)
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
        n = sum(1 for l in self.targets.get("1.0", "end").splitlines() if l.split("#", 1)[0].strip())
        self.nb.tab(self.scan_tab, text=f"{TAB_SCAN} ({n})" if n else TAB_SCAN)

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
        self.ua_list.selection_clear(0, "end")
        for i, name in enumerate(self.ua_names):
            if name in names:
                self.ua_list.selection_set(i)

    def selected_uas(self):
        values = [self.ua_names[i] for i in self.ua_list.curselection()]
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
                               width=width, height=height, enrich=self.enrich.get(), keys=dict(self.keys),
                               tls=self.tls_scan.get(), label=self.label_shots.get(),
                               dirs=dir_words() if self.probe_dirs.get() else None,
                               proxy=proxy, exclusions=exclusions,
                               files=file_rules() if self.probe_files.get() else None)
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
