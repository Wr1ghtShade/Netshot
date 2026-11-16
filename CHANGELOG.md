# Journal des modifications - NetShot (Python)

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). La version Go a son
propre journal dans le dépôt [Netshot-Go](https://github.com/Wr1ghtShade/Netshot-Go).

## [1.2.17] - 2026-11-16

### Modifié
- **Onglet DNS : serveur 1.1.1.1 par défaut** (au lieu des résolveurs du système) et liste des
  résolveurs publics connus, en IPv4 et en IPv6 : Cloudflare (1.1.1.1, 1.0.0.1,
  2606:4700:4700::1111 / ::1001), Google (8.8.8.8, 8.8.4.4, 2001:4860:4860::8888 / ::8844),
  Quad9 filtrant et sans filtrage (9.9.9.9, 149.112.112.112, 9.9.9.10, 2620:fe::fe, 2620:fe::10),
  OpenDNS (208.67.222.222, 208.67.220.220, 2620:119:35::35), AdGuard sans filtrage
  (94.140.14.140, 2a10:50c0::1:ff), FDN (80.67.169.12, 2001:910:800::12), Mullvad (194.242.2.2,
  2a07:e340::2), et « Système » pour les résolveurs de la machine. liste déroulante modifiable ; toute autre adresse
  reste possible (10.0.0.1, [2001:db8::1]:5353). Les résolveurs filtrants sont signalés : ils
  peuvent masquer la réponse d'un domaine malveillant.
- La ligne de commande garde les résolveurs du système par défaut.

Fichiers : `core/gui.py`, CHANGELOG.

## [1.2.16] - 2026-11-16

### Ajouté
- **Mode furtif** (`--stealth`), pour tester la détection du client (IDS, WAF, SOC) lors d'un
  audit autorisé :
  - 1 vérification à la fois ; pause aléatoire avant chaque connexion TCP (`--stealth-delay`,
    3-8 s par défaut, « 5 » pour une pause fixe), interrompue aussitôt par « Arrêter » ;
  - hôtes et ports testés dans un ordre aléatoire (pas de balayage séquentiel d'un hôte) ;
  - pause entre deux pages au moins égale à la pause maximale ;
  - User-Agent Chrome Windows ordinaire au lieu de celui du navigateur sans interface
    (« HeadlessChrome », vérifié sur un serveur de test), aucun User-Agent de robot ;
  - coupés : dossiers, fichiers sensibles, sonde WAF, UDP, analyse TLS, parité IPv6, lecture des
    certificats des cibles ; le journal liste ce qui a été coupé ;
  - inchangés : les recherches qui ne touchent pas la cible (enrichissement, réputation, empreinte
    cloud, crt.sh, RDAP) ;
  - durée estimée des tests de ports dans le journal ; confirmation demandée au-delà de 2 h.
- Interface : cadre « MODE FURTIF » au-dessus d'ANALYSE PASSIVE, avec le champ de pause ; les options coupées sont grisées.

Fichiers : `core/stealth.py` (nouveau), `core/scan.py`, `core/gui.py`, README, CHANGELOG.

## [1.2.15] - 2026-11-16

### Corrigé
- **« Ouvrir le dossier » grisé pendant le scan** : le dossier du scan est créé dès le lancement et
  le bouton est actif tout de suite, pour regarder les captures au fur et à mesure. Il reste actif
  après un scan arrêté. « Ouvrir le rapport » s'active à la fin, quand le rapport est écrit.
- « Ouvrir le dossier » / « Ouvrir le rapport » ne faisaient rien quand le dossier ou le rapport
  n'existaient pas encore : le chemin est rendu absolu, le dossier le plus proche qui existe est
  ouvert, et un message explique que le rapport n'est écrit qu'à la fin du scan. Une erreur
  d'ouverture est affichée au lieu d'être ignorée (Linux : `xdg-open`, macOS : `open`).

Fichiers : `core/gui.py`, CHANGELOG.

## [1.2.14] - 2026-11-16

### Corrigé
- **Scan bloqué après « [cloud] empreinte cloud et SaaS de … »** : avant le scan, chaque domaine
  était examiné l'un après l'autre (3 types DNS, 6 noms standard suivis de CNAME en CNAME, puis
  3 requêtes Microsoft de 15 s de délai chacune). Sur un réseau filtré (résolveurs lents, Microsoft
  injoignable, proxy), cela pouvait durer plusieurs minutes sans rien écrire au journal. Désormais :
  - tous les domaines et toutes leurs requêtes partent **en parallèle** ;
  - l'ensemble a un **budget de 60 s** : au-delà, le scan démarre quand même et le journal indique
    « pas de réponse en 60 s (réseau filtré ?), empreinte incomplète » pour les domaines en retard ;
  - le journal affiche une ligne **par domaine terminé** (services reconnus, tenant Microsoft) ;
  - délai des requêtes Microsoft ramené de 15 à 10 s ;
  - le bouton « Arrêter » interrompt l'attente aussitôt.

Fichiers : `core/cloud.py`, CHANGELOG.

## [1.2.13] - 2026-11-16

### Modifié
- **Boutons d'user agent à leur largeur naturelle** (onglet Scan) : ils ne s'étirent plus pour
  remplir une grille de 5 colonnes ; ils s'enchaînent à la ligne comme du texte, comme les
  pastilles de l'interface Go, et se réorganisent quand la fenêtre change de largeur.

Fichiers : `core/gui.py`, CHANGELOG.

## [1.2.12] - 2026-11-16

### Modifié
- **Boutons d'user agent plus compacts** (onglet Scan) : 5 par ligne au lieu de 4, marge
  intérieure 6 x 1 px au lieu de 10 x 3, police 8 pt : 3 lignes au lieu de 4 pour les 17 user
  agents. Les boutons de choix des ports (Défaut, Web étendu…) partagent ce style et rétrécissent
  aussi.
- **Journal plus haut** : il demande 12 lignes au lieu de 5 ; la place gagnée sur les boutons lui
  revient (environ 170 px de journal et de dernière capture à 800 px de haut, contre 110 px), la
  zone des cibles gardant ses 4 lignes minimum.

Vérifié : onglets Scan (800 et 1000 px, réglages dépliés) et DNS (800 px).

Fichiers : `core/gui.py`, `core/theme.py`, CHANGELOG.

## [1.2.11] - 2026-11-16

### Corrigé
- **Onglet Scan : colonne d'options tronquée** quand on dépliait « Réglages avancés » ou
  « Périmètre et proxy », sans moyen de descendre, et dont la hauteur écrasait le journal et la
  dernière capture. La colonne de droite défile maintenant (barre de défilement affichée seulement
  quand le contenu dépasse, molette de la souris au-dessus de la colonne) et garde une largeur fixe
  de 390 px : déplier un réglage ne change plus la mise en page. Au-dessus de la colonne, la
  molette fait défiler au lieu de changer la valeur des listes et des compteurs.
- **Journal et dernière capture plus hauts** sur l'onglet Scan : ils reçoivent 40 % de la hauteur
  libre (contre 17 %), et la zone des cibles demande 4 lignes au lieu de 6 (elle grandit avec la
  fenêtre).
- **Bouton « Arrêter »** : plusieurs étapes ajoutées en 1.2.8 à 1.2.10 ignoraient la demande
  d'arrêt et pouvaient tourner plusieurs minutes. L'arrêt est maintenant vérifié dans
  l'enrichissement des IP, l'analyse TLS, le contrôle de prise de contrôle de sous-domaine,
  l'empreinte cloud (sondes DNS, tenant Microsoft, téléchargement des plages), la lecture des
  certificats, crt.sh par organisation, les blocs RDAP et la parité IPv6. Le journal note
  « [stop] arrêt demandé » ; si l'arrêt dure, le statut indique toutes les 15 s qu'il attend la fin
  des requêtes déjà envoyées.
- **« Quitter » pendant un scan** : NetShot attendait la fin des requêtes en cours avant de se
  fermer (les fils de travail de Python le retenaient). Il se ferme maintenant tout de suite.
- **crt.sh par organisation** : 100 domaines nouveaux au plus sont examinés, résolus en parallèle
  et listés (des milliers étaient résolus un par un pour une grande organisation).

Vérifié : scan de démonstration arrêté au bout de 4 s, arrêt effectif en 1,5 s ; captures de
l'onglet Scan à 800 et 1000 px de haut, réglages dépliés, thèmes clair et sombre.

Fichiers : `core/gui.py`, `core/theme.py`, `core/scan.py`, `core/enrich.py`, `core/tls.py`,
`core/recon.py`, `core/cloud.py`, `core/discover.py`, CHANGELOG.

## [1.2.10] - 2026-11-15

### Ajouté
- **Noms des certificats** (`--no-pivot` pour désactiver) : avant le scan, le certificat servi sur
  le port 443 de chaque cible (300 au plus) est lu ; les noms SAN des domaines de l'organisation
  (domaines scannés et domaines du tenant) sont ajoutés au scan s'ils résolvent.
- **crt.sh par organisation** : le nom d'organisation (O=) de ces certificats, hors CDN,
  hébergeurs, clouds et autorités (Cloudflare, Amazon, Google, Microsoft, OVH…), est cherché dans
  crt.sh (`?O=`, certificats non expirés, 3 noms au plus) ; les domaines certifiés au même nom
  sont ajoutés au scan (25 au plus, ceux qui résolvent).
- **Blocs d'IP de l'organisation** : RDAP des IP publiques trouvées (40 au plus, IP cloud
  exclues) ; un bloc est retenu si son nom, son titulaire ou ses remarques contiennent un terme
  de l'organisation (organisation des certificats, marque du tenant, premier label des domaines),
  et s'il n'est pas plus large qu'un /16. Listé avec les IP déjà scannées et la ligne de cibles à
  copier ; **jamais scanné** sans accord du client.
- **Services UDP** (`--udp`, test actif, inactif par défaut) : sur chaque IP cible (256 au plus),
  DNS (requête récursive : résolveur ouvert = gravité haute), NTP, SNMP (découverte SNMPv3 RFC
  3414, aucune communauté essayée ; exposé = moyenne), IKE v1 Main Mode, OpenVPN
  (HARD_RESET_CLIENT_V2), SSDP (M-SEARCH, en-tête SERVER relevé ; exposé = moyenne). Deux essais
  de 2 s par sonde. Non lancé à travers un proxy.
- **Parité IPv4 / IPv6** (`--no-ipv6-parity` pour désactiver) : les ports scannés des noms
  double pile (50 au plus) sont essayés sur leur première IPv4 et leur première IPv6 ; un port
  ouvert seulement en IPv6 est signalé (gravité haute). Sauté, avec une note, si le poste n'a pas
  d'accès IPv6 ou passe par un proxy.
- **Code public GitHub** (clé `github`) : recherche de code de 3 domaines de l'organisation au
  plus, seule puis avec password / secret / token / apikey, 7 s entre deux requêtes ; dépôt,
  fichier et lien relevés, fichiers non téléchargés. Jeton refusé ou limite atteinte : arrêt avec
  une note.
- **Top risques** en tête du rapport : KEV, EPSS ≥ 50 %, fuites LeakIX, fichiers sensibles
  critiques ou élevés, secrets JavaScript, pages de débogage, interfaces d'administration, listes
  de fichiers ouvertes, TLS noté F ou T, prise de contrôle de sous-domaine, réputation critique ou
  haute, UDP risqué, ports IPv6 seuls, code public citant un secret. 10 premiers constats,
  identiques regroupés ; liste complète dans `risks` de `results.json`.
- **API documentées** : `swagger/v1/swagger.json`, `api/swagger.json`, `api/openapi.json`,
  `openapi.yaml`, `swagger.yaml`, `api-docs` ajoutés à `files.txt` (71 fichiers).
- Sorties : sections « Découverte élargie », « Services UDP », « Parité IPv4 / IPv6 », « Code
  public (GitHub) » ; `discovery.csv` ; onglet « Découverte » ; clés `discovery` et `risks` de
  `results.json`. Clé `github` dans l'onglet Clés. cases « Découverte élargie » et « Parité IPv4 / IPv6 » (ANALYSE PASSIVE), « Services UDP » (TESTS ACTIFS).
- Lecture des certificats avec le décodeur DER de `core/tls.py` (aucune dépendance ajoutée) ; non lancée à travers un proxy.
- Tests : paquets UDP (longueurs SNMP BER et IKE), lecture DNS (résolveur ouvert ou non) et SSDP,
  termes d'organisation et organisations ignorées, recherche GitHub (jeton refusé, résultats),
  Top risques et sections ; scan de démonstration avec de faux services DNS et SSDP locaux.

### Modifié
- `--no-cloud-targets` empêche maintenant tout ajout au scan (cloud, certificats, crt.sh).
- L'empreinte cloud expose les domaines de l'organisation (`org_domains`) utilisés par la
  découverte élargie et la recherche GitHub.

Non vérifié en conditions réelles : crt.sh, RDAP et l'API GitHub ne sont pas joignables depuis
l'environnement de développement.

Fichiers : `core/discover.py` (nouveau), `core/scan.py`, `core/gui.py`, `core/export.py`, `core/cloud.py`, `core/sources.py`, `assets/files.txt`, README, CHANGELOG.

## [1.2.9] - 2026-11-15

### Corrigé
- **Périmètre des pages SaaS ajoutées par l'empreinte cloud** (`xxx.sharepoint.com`,
  `xxx-my.sharepoint.com`, fournisseur d'identité hébergé chez un tiers) : elles recevaient la
  recherche de dossiers (`--dirs`), de fichiers sensibles (`--files`) et la sonde WAF
  (`--waf-probe`) quand ces options étaient activées, c'est-à-dire des requêtes actives sur
  l'infrastructure de Microsoft ou de l'éditeur. Elles n'ont plus que la capture et l'analyse
  passive.

### Précisé
- Les domaines de l'organisation ajoutés au scan (autres domaines du tenant, fournisseur
  d'identité de l'organisation) passent par tout le scan habituel, dossiers, fichiers sensibles et
  sonde WAF compris quand ces options sont activées (README).

Fichiers : `core/scan.py`, README, CHANGELOG.

## [1.2.8] - 2026-11-15

### Ajouté
- **Empreinte cloud et SaaS** de l'organisation scannée, passive et sans clé, sur les domaines
  enregistrables des noms scannés (5 au plus, les plus fréquents ; domaines internes `.lan`,
  `.local`, `.corp`… exclus) :
  1. **Tenant Microsoft 365 / Entra ID** : configuration OpenID de `login.microsoftonline.com`
     (ID du tenant, région), `getuserrealm.srf` (authentification gérée ou fédérée, fournisseur
     d'identité et nom de marque), Autodiscover d'Exchange Online `GetFederationInformation`
     (autres domaines du tenant et nom `xxx.onmicrosoft.com`). **Google Workspace** d'après les MX.
  2. **SaaS, PaaS et IaaS** reconnus par ~190 signatures : TXT de vérification, `include:` du SPF,
     MX, NS, et CNAME de chaque nom scanné ainsi que de `autodiscover`, `lyncdiscover`, `sip`,
     `enterpriseregistration`, `enterpriseenrollment` et `www` de chaque domaine.
  3. **IP publiques rattachées** à AWS (`ip-ranges.json`), Azure (Service Tags, lien lu sur la page
     de téléchargement Microsoft), Google Cloud (`cloud.json`) et Cloudflare : fournisseur, service,
     région, plage la plus précise. Plages gardées 7 jours dans le cache utilisateur
     (`netshot/cloud-ranges`), copie périmée utilisée si le téléchargement échoue.
  4. **CNAME orphelins** : le contrôle de prise de contrôle de sous-domaine tourne aussi quand
     l'analyse des pages est désactivée ; ses résultats apparaissent dans l'empreinte (« CNAME
     orphelin », gravité haute).
  5. Section « Empreinte cloud et SaaS » en tête du rapport, `cloud.csv`, onglet « Cloud et SaaS »
     de `results.xlsx`, clé `cloud` de `results.json`.
- **Ajout automatique au scan** de ce qui est découvert, avant le début du scan : les autres
  domaines du tenant (25 au plus, `*.onmicrosoft.com` exclus) et le fournisseur d'identité quand
  il appartient à l'organisation, sur tous les ports demandés ; les pages SaaS du tenant
  (`xxx.sharepoint.com`, `xxx-my.sharepoint.com`, fournisseur d'identité hébergé chez un tiers)
  sur le port 443 seulement. Seuls les noms qui résolvent sont ajoutés ; le fichier d'exclusions
  s'applique ; la barre de progression compte ces cibles.
- Options `--no-cloud` et `--no-cloud-targets` ; case « Empreinte cloud et SaaS » dans ANALYSE PASSIVE.
- Tests : signatures (TXT, SPF, MX, NS, CNAME), lecture Autodiscover, faux serveur Microsoft
  (tenant fédéré, domaine sans tenant), plage la plus précise, lien des Service Tags (échappé
  JSON ou non), fin d'empreinte (IP, CNAME orphelin, section, lignes CSV).

### Choix
- Aucun nom de bucket S3 ni de compte de stockage Azure n'est deviné : ce serait sonder des
  ressources qui n'appartiennent peut-être pas au client.

Non vérifié en conditions réelles : les services Microsoft et les listes de plages ne sont pas
joignables depuis l'environnement de développement ; formats suivis : documentation publique des
fournisseurs et méthode AADInternals pour Autodiscover.

Fichiers : `core/cloud.py` (nouveau), `core/scan.py`, `core/gui.py`, `core/export.py`, README, CHANGELOG.

## [1.2.7] - 2026-11-14

### Ajouté
- **Criminal IP** dans la réputation (clé `criminalip`, compte gratuit : 50 consultations d'IP et
  100 analyses de domaine par mois) :
  - **domaine** : analyse « lite » (`/v1/domain/lite/scan`, suivi de `/progress`, puis `/report`)
    du domaine enregistrable le plus scanné : score du domaine, catégorie (malware, phishing…),
    probabilité de phishing, faux lien https, punycode, IP liées signalées. Le résultat va sur la
    ligne du domaine, créée si le domaine lui-même n'a pas été scanné. Abandon après 3 min.
  - **IP** : `/v1/feature/ip/suspicious-info` sur les IP publiques qui portent le plus de services :
    score entrant et sortant, VPN / Tor / proxy / scanner / Snort, nombre de signalements d'abus.
    Chaque IP a sa propre ligne « Réputation », avec les noms scannés qui y pointent.
  - Plafonds par scan pour ne pas vider le quota : `--criminalip-ips` (5 par défaut) et
    `--criminalip-domains` (1 par défaut), 0 = aucun ; deux champs « Criminal IP : IP » et « Criminal IP : domaines » dans RÉGLAGES AVANCÉS, avec un rappel des quotas gratuits.
  - Le journal annonce le nombre de domaines et d'IP vérifiés et celles laissées de côté par le
    plafond. Clé refusée (401) ou crédits épuisés (403 / 429) : arrêt immédiat des appels.
  - Jamais d'IP interne ni de nom pointant vers une IP interne envoyé à Criminal IP.
  - Clé `criminalip` ajoutée à l'onglet Clés (lien vers la page du compte où la copier).
- Tests : faux serveur Criminal IP (scores en mot ou en chiffre, classification, plafonds, IP
  internes jamais envoyées, clé refusée).

### Modifié
- Niveaux de réputation : un score Criminal IP « Critical » ou un domaine classé malware / phishing
  donne **critique** ; « Dangerous », un phishing probable à 70 % ou plus ou un faux lien https
  donnent **haute** ; « Moderate » donne **moyenne**. Le niveau retenu est le plus grave des sources.
- Rapport : la section Réputation compte « signalé(s) » (noms et IP) et la colonne devient
  « Nom / IP ». `reputation.csv` gagne les colonnes `criminalip` et `names` ; l'onglet
  « Réputation » de `results.xlsx` gagne « Criminal IP » et « Noms de l'IP ».
- `registrable_domain` déplacée de `core/gui.py` vers `core/sources.py` (utilisée aussi par Criminal IP, sans dépendre de tkinter).
- README : ligne Criminal IP dans le tableau des sources de réputation, options `--criminalip-ips`
  et `--criminalip-domains`, nouveaux niveaux.

Non vérifié en conditions réelles : l'API Criminal IP n'est pas joignable depuis l'environnement de
développement ; le format des réponses suit le plugin officiel Criminal IP (Volatility3) et les
intégrations publiques. Premier scan avec la clé : vérifier le journal `[criminalip]`.

Fichiers : `core/criminalip.py` (nouveau), `core/reputation.py`, `core/scan.py`, `core/gui.py`, `core/sources.py`, `core/export.py`, README, CHANGELOG.

## [1.2.6] - 2026-11-14

### Retiré
- **Réputation des noms** : VirusTotal et Google Safe Browsing ne sont plus interrogés. La
  vérification repose sur les résolveurs DNS filtrants (Quad9, Cloudflare 1.1.1.2, OpenDNS,
  AdGuard, sans clé) et sur URLhaus (clé `abusech`). Raisons : l'API publique VirusTotal interdit
  l'usage commercial (audits facturés) et ralentissait le scan (15 s entre deux noms, 8 noms max) ;
  Safe Browsing demandait un projet Google Cloud pour peu de gain par rapport à URLhaus.
- Clé `safebrowsing` retirée de l'onglet Clés et de la liste des services acceptant une clé (une
  valeur déjà présente dans `keys.json` est simplement ignorée).
- Colonnes `virustotal`, `vt_malicious` et `safe_browsing` retirées de `reputation.csv` ; colonnes
  « VirusTotal » et « Safe Browsing » retirées de l'onglet « Réputation » de `results.xlsx` ; champs
  correspondants retirés du JSON.

### Modifié
- Niveaux de réputation : **critique** = URL malveillante encore en ligne selon URLhaus ; **haute** =
  bloqué par un résolveur de sécurité ou nom connu d'URLhaus ; **info** = bloqué seulement par
  AdGuard. Le niveau « moyenne » (suspect VirusTotal) n'est plus produit.
- Le journal indique « URLhaus ignoré (pas de clé abusech) » quand la clé manque.
- Libellés mis à jour : case « Réputation des noms » (« Listes de blocage DNS, URLhaus »), aide de
  `--no-reputation`, README.
- La clé `virustotal` reste utilisée par la source de sous-domaines VirusTotal (inchangée, optionnelle).

Fichiers : `core/reputation.py`, `core/export.py`, `core/sources.py`, `core/scan.py`, `core/gui.py`, README, CHANGELOG.

## [1.2.5] - 2026-11-14

### Modifié
- **Rapport HTML** : les captures ne s'empilent plus une par ligne. Chaque service (hôte:port)
  devient une vignette, et les vignettes remplissent la largeur de la page en grille (4 par ligne
  en 1440 px, moins sur un écran étroit). Un service capturé avec plusieurs user agents garde une
  ligne entière pour comparer ses captures côte à côte. Toutes les vignettes ont la même hauteur
  (capture en 16:9, recadrée depuis le haut ; clic pour l'image entière). Les filtres, la
  recherche et « masquer les doublons » fonctionnent comme avant.
- **Dossier d'un scan lancé depuis l'interface** : `scan_<domaine>_<date>` au lieu de
  `scan_<date>`, par exemple `scan_guifort.ovh_20261114_095743`. Le domaine est celui que partagent
  tous les noms de la liste (suffixes comme `.co.uk` ou `.gouv.fr` pris en compte). Avec une seule
  cible, c'est la cible elle-même (`scan_10.0.0.0-24_…`, `scan_AS3215_…`). Avec des cibles sans
  domaine commun, le nom reste `scan_<date>`. En ligne de commande, `-o` donne toujours le dossier.
- Captures du README refaites (`docs/netshot-python-scan-v125.png`,
  `docs/netshot-python-rapport-v125.png`).

### Fichiers
- `core/scan.py` (grille des vignettes), `core/gui.py` (`scan_folder_name`, `scan_label`,
  `registrable_domain`), `core/__init__.py`, `README.md`, `docs/`.

### Tests
- Mêmes 7 cas de nommage que la version Go.
- Rapport généré et ouvert dans Chromium headless ; scan lancé depuis l'interface (Xvfb) :
  dossier `scan_demo.lan_…` créé.

## [1.2.4] - 2026-11-14

### Modifié
- Bas de la fenêtre : le journal et la dernière capture ne sont plus deux onglets
  (`ttk.Notebook`). Ce sont deux cadres côte à côte sur une ligne, en deux colonnes égales
  (« JOURNAL » à gauche, « DERNIÈRE CAPTURE » à droite), visibles en permanence sur tous les
  onglets sauf Whois. La marque « ● » de nouvelle capture disparaît, devenue inutile.
- Le texte au-dessus de l'aperçu (URL, statut, titre, UA) revient à la ligne avant le bouton
  Effacer, quelle que soit la largeur de la colonne.
- Captures du README refaites (`docs/netshot-python-scan-v124.png`,
  `docs/netshot-python-rapport-v124.png`).

### Fichiers
- `core/gui.py` (bas de la fenêtre, `layout_for_tab`), `core/__init__.py`, `README.md`, `docs/`.

### Tests
- Interface lancée sous Xvfb (Tk 8.6), onglets Scan et DNS, scan complet de l'intranet de
  démonstration.

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
- Captures du README refaites sur un intranet de démonstration cohérent : deux sites
  (`intranet.demo.lan` avec page de connexion, `wiki.demo.lan`), http redirigé vers https,
  certificat ECDSA P-256 valable un an signé par une autorité interne de confiance, TLS 1.2
  (suites AEAD seulement) et 1.3, PQC, HSTS et en-têtes de sécurité : note A+. Onglet Scan
  après la capture, et capture du rapport HTML du même scan. Fichiers renommés
  (`docs/*-scan-v123.png`, `docs/*-rapport-v123.png`) pour que GitHub ne montre plus l'ancienne image en cache.

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
