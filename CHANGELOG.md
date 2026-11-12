# Journal des modifications - NetShot (Python)

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). La version Go a son
propre journal dans le dépôt [Netshot-Go](https://github.com/Wr1ghtShade/Netshot-Go).

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
