# Journal des modifications - NetShot (Python)

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). La version Go a son
propre journal dans le dépôt [Netshot-Go](https://github.com/Wr1ghtShade/Netshot-Go).

## [1.2.3] - 2026-11-13

Nouveau logo « radar », choisi parmi les six pistes proposées (même dessin que la version Go,
aux couleurs de la version Python).

### Modifié
- Logo : carré arrondi en dégradé marine → indigo, trois cercles de radar, secteur de balayage
  ambre, ligne de balayage et trois points blancs (les services trouvés).
- `assets/icon.png` (256 px : icône de la fenêtre, logo du rapport) régénéré, et nouveau
  `assets/icon-32.png` dessiné pour 32 px, utilisé dans l'en-tête de la fenêtre à la place de
  l'image de 256 px réduite (plus net). Les deux sont produits par `tools/mkicon` de la version Go
  (`go run ./tools/mkicon -variant python -out ../netshot/assets`).
- Captures du README refaites sur un intranet de démonstration (page de connexion en http et
  https) : onglet Scan après la capture, et nouvelle capture du rapport HTML du même scan
  (`docs/netshot-python-rapport.png`).

### Fichiers
- `assets/icon.png`, `assets/icon-32.png`, `core/gui.py`, `core/__init__.py`, `README.md`,
  `docs/netshot-python.png`.

### Tests
- Interface ouverte sous Xvfb (Tk 8.6) : logo de l'en-tête et icône de fenêtre vérifiés.

## [1.2.2] - 2026-11-13

Refonte de l'interface, étape 2 : les autres onglets prennent le style de l'onglet Scan (même
étape que la version Go 1.2.2).

### Modifié
- Boutons principaux de tous les onglets (Rechercher, Interroger, Analyser, Enregistrer les clés)
  en bleu plein, style `Primary.TButton` ; la classe `SoftButton` (boutons pastel) est supprimée.
- Aides en gris via le style `Hint.TLabel` (lisible dans les deux thèmes).
- **Clés API** : titre de section, nom des services en gras, état et lien en couleur d'accent
  (`Link.TLabel`).
- Statut initial de la barre d'action : « Prêt. » (le nombre d'UA est affiché à côté de la liste).
- Capture du README mise à jour.

### Fichiers
- `core/gui.py`, `core/theme.py`, `core/__init__.py`, `README.md`, `docs/netshot-python.png`.

### Tests
- Chaque onglet ouvert sous Xvfb (Tk 8.6), thèmes clair et sombre ; scan complet lancé depuis
  l'interface sur une page locale.

## [1.2.1] - 2026-11-13

Refonte de l'interface, étape 1 : en-tête et onglet Scan, d'après la maquette validée (même
organisation que la version Go 1.2.1).

### Modifié

**Thème**
- Les deux thèmes utilisent maintenant le thème ttk « clam » recoloré à partir d'une palette
  (`LIGHT`, `DARK` dans `core/theme.py`). Le thème clair n'est plus l'aspect natif Windows
  (« vista ») : c'est ce qui permet le bouton bleu, les groupes colorés et les boutons à cocher,
  identiques à la version Go.
- Nouveaux styles : `Accent.TButton`, `Big.TButton`, `Quit.TButton`, `Link.TButton`,
  `Fold.TButton`, `Chip.Toolbutton`, `Passive.TLabelframe`, `Active.TLabelframe`,
  `Active.TCheckbutton`, `Muted.TLabel`, `Pill.TLabel`, `Section.TLabel`.
- Journal en console sombre dans les deux thèmes.

**En-tête**
- Bouton « Quitter » discret (texte rouge, plein au survol).

**Onglet Scan**
- Colonne de gauche : cibles avec un compteur (entrées et estimation du nombre d'adresses des plages
  CIDR, « + AS » si un AS est présent), aide sous la zone, ports avec préréglages en boutons
  (Défaut, Web étendu, Services non web, Web + services), user agents en boutons à cocher (4 par
  ligne) avec compteur et sélection rapide Navigateurs / Robots / Tous / Aucun.
- Colonne de droite : **Analyse passive** (bleu) et **Tests actifs** (orange, « requêtes en plus »),
  chaque option avec une ligne de détail ; **Réglages avancés** et **Périmètre et proxy** repliés
  avec un résumé mis à jour en direct.
- Barre d'action toujours visible en bas de l'onglet : Lancer le scan (bleu), Arrêter, barre de
  progression fine (6 px, nouvelle classe `ThinProgress`), Ouvrir le dossier, Ouvrir le rapport.
  La grosse barre verte disparaît.
- Journal et dernière capture dans un `ttk.Notebook` à deux onglets ; « ● » sur l'onglet capture
  signale une capture pas encore vue. Les autres onglets n'affichent que le journal.

**Réputation des noms**
- Case séparée de l'enrichissement dans l'interface.
- Nouvelle option `--no-reputation` ; `--no-enrich` coupe toujours les deux.
- Sans enrichissement, les noms sont résolus par le résolveur du système pour écarter ceux qui
  pointent vers une IP interne (aucun appel à un tiers pour ça).

### Fichiers
- `core/gui.py` (en-tête, `_build_scan_tab`, panneau du bas, `layout_for_tab`, compteurs,
  `ThinProgress`, user agents en cases à cocher au lieu d'une liste).
- `core/theme.py` (palettes, styles), `core/scan.py` (`--no-reputation`, `args.reputation`),
  `core/reputation.py` (`_resolve_hosts`), `core/__init__.py`, `README.md`.

### Tests
- Interface lancée sous Xvfb (Tk 8.6), thèmes clair et sombre, captures d'écran vérifiées ;
  scan lancé depuis l'interface sur une page locale : progression, rapport, aperçu de capture et
  marque de nouvelle capture vérifiés.
- Non vérifié sous Windows : le rendu du thème « clam » y est très proche, mais pas testé.

## [1.2.0] - 2026-11-13

Ajout des contrôles de [web-check](https://web-check.xyz/checks) qui manquaient à NetShot, sans passer
par l'API web-check (encore en développement) : tout est fait localement ou auprès des sources
d'origine. Même fonctionnement que la version Go 1.2.0.

### Ajouté

**Contenu mixte et SRI** (analyse des pages, active par défaut)
- Liste des ressources (`script`, `link`, `img`, `iframe`, `audio`, `video`, `source`, `embed`,
  `track`, `object`) et des formulaires en `http://` sur une page HTTPS, lue dans le DOM de la page
  déjà chargée. Aucune requête de plus.
- Liste des scripts et feuilles de style d'un autre site chargés sans attribut `integrity` (SRI).
- Les deux constats s'ajoutent aux « Constats en-têtes » (`contenu mixte : N ressource(s)…`,
  `SRI absent : N script(s)…`).

**Traqueurs et tiers** (analyse des pages, active par défaut)
- Environ 80 domaines connus classés par catégorie : mesure d'audience, publicité, réseaux sociaux,
  analyse comportementale, gestionnaire de balises, consentement, polices (Google Fonts), vidéo,
  chat, monitoring, anti-robot.
- Liste des hôtes tiers appelés par la page (balises du DOM et Resource Timing), 100 au plus.

**WAF / CDN de protection**
- Détection passive dans les en-têtes et les cookies de chaque page : Cloudflare, Akamai, Imperva /
  Incapsula, Sucuri, F5 BIG-IP ASM, AWS WAF, AWS CloudFront, Azure Front Door, Azure Application
  Gateway, FortiWeb, Barracuda, Citrix NetScaler AppFirewall, ModSecurity, Fastly, DDoS-Guard,
  Wallarm, Reblaze, Radware. Le WAF trouvé s'affiche dans le journal (`WAF …`).
- `--waf-probe` (désactivé par défaut, test **actif**) : une requête normale puis une requête avec une
  chaîne inoffensive qui ressemble à une attaque (`<script>`, `' OR '1'='1`, `../`) dans le paramètre
  `netshot_waf_test`. Un code 400 / 403 / 406 / 418 / 429 / 501 / 503 / 999 différent de la page
  normale, ou une page de blocage reconnue (Cloudflare, Imperva, Akamai, AWS, F5, ModSecurity,
  Sucuri, FortiWeb, Barracuda, NetScaler, Wordfence, NAXSI, Wallarm, DDoS-Guard), donne
  `bloqué (403 au lieu de 200) : <produit>`. Respecte `-d` / `--delay` et le proxy.
- Interface : case « Tester la présence d'un WAF (requête de test) ».

**Réputation des noms** (avec l'enrichissement, `--no-enrich` la coupe)
- Résolveurs DNS filtrants, sans clé : Quad9 (malware / phishing), Cloudflare 1.1.1.2 (malware),
  OpenDNS (phishing), AdGuard DNS (publicité / traqueurs). Un nom qui résout chez 1.1.1.1 (ou
  9.9.9.10) mais que le résolveur filtrant bloque (NXDOMAIN, `0.0.0.0`, `127.0.0.1`, IP de page de
  blocage) est signalé. Si le port 53 sortant est filtré, le journal le dit.
- URLhaus (abuse.ch), nouvelle clé gratuite `abusech` : URL malveillantes connues sur le nom, nombre
  encore en ligne, type de menace, présence dans Spamhaus DBL et SURBL.
- VirusTotal (clé `virustotal` existante) : moteurs qui classent le domaine malveillant ou suspect.
  Limité aux 8 premiers noms, une requête toutes les 15 s (API gratuite : 4 / minute).
- Google Safe Browsing, nouvelle clé gratuite `safebrowsing` : malware, hameçonnage, logiciel
  indésirable sur les URL capturées (une seule requête pour 500 URL).
- Seuls les noms publics partent : un nom qui pointe vers une IP interne n'est jamais envoyé.
- Niveau par nom : critique, haute, moyenne, info (voir README).

**DKIM** (`--dns` et onglet DNS)
- 32 sélecteurs courants interrogés (`google`, `selector1`, `selector2`, `k1`, `s1`, `mailjet`,
  `brevo1`, `protonmail`, `fm1`…), y compris via le CNAME de Microsoft 365.
- Nouveaux constats : `✓ DKIM publié (sélecteur(s) : …)`, `DKIM non trouvé parmi 32 sélecteurs
  courants` (seulement si le domaine a un MX ou un SPF), `Clé DKIM révoquée (p= vide)`.

**Rapport et exports**
- Rapport : section « Réputation » en tête, sections « WAF / CDN de protection », « Contenu mixte et
  SRI » et « Traqueurs et tiers » après les en-têtes de sécurité.
- `results.csv` : nouvelles colonnes `waf`, `waf_probe`, `mixed_content`, `no_sri`, `trackers`,
  `third_party_hosts`.
- `results.json` : nouveaux champs par service (`waf`, `waf_probe`, `mixed_content`, `no_sri`,
  `trackers`, `third_party_hosts`) et nouvelle clé `reputation`.
- `results.xlsx` : nouveaux onglets « WAF, SRI, traqueurs » et « Réputation ».
- Nouveau fichier `reputation.csv`.

### Modifié
- `--no-enrich` coupe aussi la réputation des noms ; la case de l'interface s'appelle « Enrichir les
  IP, les versions et la réputation ».
- `--list-sources` décrit les sources de réputation.
- `detect_tech` accepte un paramètre `rules` pour réutiliser le moteur de signatures avec les règles
  WAF (listes compilées une fois, en cache).
- Version 1.2.0.

### Fichiers
- Nouveaux : `core/pagecheck.py`, `core/reputation.py`.
- Modifiés : `core/scan.py` (appel des contrôles et de la réputation, `--waf-probe`, colonnes CSV,
  sections du rapport), `core/webinfo.py` (`detect_tech(rules=…)`), `core/dns.py` (DKIM),
  `core/export.py`, `core/sources.py` (clés `abusech`, `safebrowsing`), `core/gui.py`,
  `core/__init__.py`, `README.md`.

### Tests
- Mêmes cas que les tests Go : contenu mixte, SRI, traqueurs, WAF passif, DKIM (dont CNAME
  Microsoft 365 et clé révoquée), niveaux de réputation.
- Scan de bout en bout sur une page locale (HTTPS, Chromium headless) avec `--waf-probe` : mêmes
  résultats que la version Go.
- Non testé en conditions réelles : les appels à Quad9 / Cloudflare / OpenDNS / AdGuard, URLhaus,
  VirusTotal et Safe Browsing (réseau de l'environnement de développement filtré).

## [1.1.0] - 2026-11-12

### Ajouté

**Analyse des pages** (active par défaut, `--no-analyze` pour la couper)
- Détection des technologies et de leur version : serveur, langage, CMS, framework, équipements
  (FortiGate, NetScaler, BIG-IP…), lus dans les en-têtes, les cookies, la balise `generator`, les
  scripts et le HTML.
- Recherche des CVE de chaque version dans NVD, classées avec CISA KEV, EPSS et CVSS. Seuls le
  produit et la version sont envoyés. Nouvelle clé optionnelle `nvd` pour aller plus vite.
- Hash du favicon, identique au filtre Shodan `http.favicon.hash`, avec un lien de recherche.
- Repérage des pages sensibles : `index-of` (liste de fichiers), `debug`, `default` (page par
  défaut), `admin`, `login`, `auth-http`.
- Regroupement des captures visuellement identiques, avec une case pour masquer les doublons. Une
  page sensible n'est jamais masquée.
- Contrôle des en-têtes de sécurité : HSTS, CSP, anti-clickjacking, `nosniff`, `Referrer-Policy`,
  version divulguée, cookies sans `Secure` / `HttpOnly` / `SameSite`, mot de passe envoyé en HTTP.

**Reconnaissance approfondie**
- `--files` : test d'environ 65 fichiers sensibles (`.env`, `.git/HEAD`, sauvegardes, `phpinfo`,
  `actuator/env`…). Chaque réponse doit contenir la signature du fichier, ce qui écarte les pages
  404 personnalisées. Liste modifiable : `assets/files.txt` ou `--files-wordlist`.
- `--dirs` : test d'environ 95 dossiers courants et capture de ceux qui affichent une liste de
  fichiers. Liste modifiable : `assets/dirs.txt` ou `--dirs-wordlist`.
- Analyse du JavaScript chargé par les pages, sans requête de plus : chemins d'API, URL internes,
  secrets (clés AWS, Google, GitHub, Slack, JWT…). Les secrets sont masqués dans toutes les sorties.
- Lecture de `robots.txt`, `sitemap.xml` et `security.txt`.
- Détection des sous-domaines exposés à une prise de contrôle (CNAME vers un service cloud
  disparu).
- Lecture des bannières des services non web (SSH, FTP, SMTP, POP, IMAP, MySQL, Redis, VNC, RDP).
  La version trouvée part dans la recherche de CVE.
- Rappel des identifiants par défaut connus de chaque technologie trouvée. Rien n'est essayé.
- Préréglages de ports : `-p web` (une centaine de ports web), `-p services` (services non web),
  combinables entre eux et avec une liste.

**Périmètre et proxy**
- `--exclude` et `--exclude-file` : les cibles hors périmètre ne sont jamais testées, y compris un
  nom d'hôte qui pointe vers une plage exclue.
- `--proxy` : proxy HTTP (Burp, ZAP) ou SOCKS5 pour les pages, favicons, dossiers et fichiers. Avec
  SOCKS5, le test des ports passe aussi par le proxy.

**Rapport et exports**
- Barre de filtres dans `report.html` : recherche libre, code HTTP, repère, technologie.
- Nouvelles sections en tête du rapport : fichiers exposés, pages sensibles, JavaScript,
  technologies, services non web, robots et sitemap, en-têtes, pages similaires, prises de contrôle.
- `results.xlsx` : un onglet par thème, avec filtres et en-tête figé, sans dépendance ajoutée.
- `results.json` : tout le scan, pour un autre outil.
- `technologies.csv` et nouvelles colonnes dans `results.csv`.

**Interface graphique**
- Menu « Préréglages » pour les ports.
- Cases « Tester les dossiers courants » et « Tester les fichiers sensibles ».
- Champs « Proxy » et « Hors périmètre », avec chargement d'une liste depuis un fichier.

## [1.0.0] - 2026-11-12

Première version publiée sur GitHub.

### Contenu
- Captures d'écran des services web trouvés sur des IP, plages CIDR, AS ou noms d'hôte, avec
  plusieurs user agents et comparaison des réponses.
- Sources passives de sous-domaines (logs CT, DNS passif, archives) et dictionnaire DNS.
- Outils DNS (comme dig), whois (RDAP et port 43), analyse TLS (comme sslscan), fuites de données
  (LeakCheck).
- Enrichissement des IP : Shodan, LeakIX, CISA KEV, EPSS.
- Interface graphique tkinter avec thème clair ou sombre.

### Modifié
- `keys.json` est toujours à côté de `netshot.py`. S'il manque, un modèle vide est créé ; un fichier
  existant n'est jamais écrasé. À l'enregistrement, seuls les champs remplis sont modifiés et
  l'ancien fichier est gardé en `keys.json.bak`.

### Retiré
- Reprise des clés depuis `%APPDATA%\netshot`.
