#!/usr/bin/env bash
# Installs NetShot (Python version) on Linux: virtual environment, Playwright, Chromium.
#
# Creates .venv in the application folder (the system Python is not touched), installs
# requirements.txt, downloads Chromium for Playwright, then checks that everything imports.
# Running it again updates the installation. Chromium goes to ~/.cache/ms-playwright.
#
#   ./install.sh                         install or update
#   ./install.sh --deps                  also install Chromium's system libraries (sudo)
#   ./install.sh --proxy http://proxy.company.local:8080
#   ./install.sh --recreate              delete .venv and start again
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"
MIN_MAJOR=3
MIN_MINOR=9
DEPS=0
RECREATE=0

step() { printf '\n\033[36m==> %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31mERREUR : %s\033[0m\n' "$1" >&2; exit 1; }
warn() { printf '\033[33mATTENTION : %s\033[0m\n' "$1" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --deps) DEPS=1 ;;
        --recreate) RECREATE=1 ;;
        --proxy) [ $# -ge 2 ] || fail "--proxy demande une URL"; export HTTPS_PROXY="$2" HTTP_PROXY="$2"; shift ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "option inconnue : $1 (voir --help)" ;;
    esac
    shift
done
[ -n "${HTTPS_PROXY:-}" ] && echo "Proxy : $HTTPS_PROXY"

# --- 1. Python ------------------------------------------------------------------------
step "Recherche de Python $MIN_MAJOR.$MIN_MINOR ou plus récent"
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= ($MIN_MAJOR, $MIN_MINOR) else 1)" 2>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done
[ -n "$PYTHON" ] || fail "Python $MIN_MAJOR.$MIN_MINOR+ introuvable. Debian/Ubuntu : sudo apt install python3 python3-venv python3-tk"
echo "$("$PYTHON" --version) ($(command -v "$PYTHON"))"

# Debian/Ubuntu split venv and tkinter into separate packages
"$PYTHON" -c "import ensurepip, venv" 2>/dev/null ||
    fail "module venv absent. Debian/Ubuntu : sudo apt install python3-venv (Fedora : inclus dans python3)"
TK_OK=1
"$PYTHON" -c "import tkinter" 2>/dev/null || TK_OK=0

# --- 2. Virtual environment -----------------------------------------------------------------
if [ "$RECREATE" = 1 ] && [ -d .venv ]; then
    step "Suppression de l'ancien environnement .venv"
    rm -rf .venv
fi
if [ ! -x .venv/bin/python ]; then
    step "Création de l'environnement virtuel .venv"
    "$PYTHON" -m venv .venv
else
    step "Environnement .venv existant : mise à jour"
fi
VPY=.venv/bin/python

# --- 3. Python packages ----------------------------------------------------------------------
step "Installation des dépendances (requirements.txt)"
"$VPY" -m pip install --disable-pip-version-check --upgrade pip
"$VPY" -m pip install --disable-pip-version-check -r requirements.txt

# --- 4. Chromium for Playwright ----------------------------------------------------------------
step "Téléchargement de Chromium pour Playwright (environ 150 Mo, une seule fois)"
if [ "$DEPS" = 1 ]; then
    # --with-deps installs the system libraries Chromium needs (apt/dnf, asks for sudo)
    "$VPY" -m playwright install --with-deps chromium
else
    "$VPY" -m playwright install chromium
fi

# --- 5. Checks ---------------------------------------------------------------------------------
step "Vérification"
"$VPY" -c "import playwright.async_api, core.scan; print('imports OK')"
"$VPY" netshot.py --list-ua >/dev/null
# Chromium starts only if its system libraries are present: try it once
if ! "$VPY" - <<'EOF'
import asyncio, sys
from playwright.async_api import async_playwright
async def main():
    async with async_playwright() as pw:
        b = await pw.chromium.launch(headless=True)
        await b.close()
try:
    asyncio.run(main())
except Exception as exc:
    print(str(exc).splitlines()[0], file=sys.stderr)
    sys.exit(1)
EOF
then
    warn "Chromium ne démarre pas (bibliothèques système manquantes ?). Relancer avec : ./install.sh --deps"
fi

# Small launchers so the app runs with the environment without activating it
cat > netshot.sh <<'EOF'
#!/usr/bin/env bash
DIR="$(dirname "$(readlink -f "$0")")"
exec "$DIR/.venv/bin/python" "$DIR/netshot.py" "$@"
EOF
cat > netshot_gui.sh <<'EOF'
#!/usr/bin/env bash
DIR="$(dirname "$(readlink -f "$0")")"
exec "$DIR/.venv/bin/python" "$DIR/netshot_gui.py" "$@"
EOF
chmod +x netshot.sh netshot_gui.sh

printf '\n\033[32mInstallation terminée.\033[0m\n'
echo "  Ligne de commande   : ./netshot.sh 192.168.1.0/24   (ou ./netshot.sh --help)"
if [ "$TK_OK" = 1 ]; then
    echo "  Interface graphique : ./netshot_gui.sh"
else
    warn "tkinter absent : l'interface graphique ne démarrera pas. Debian/Ubuntu : sudo apt install python3-tk, puis ./install.sh --recreate"
fi
