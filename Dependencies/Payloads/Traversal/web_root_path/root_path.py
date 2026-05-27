path_to_home = [
    # ===============================
    # 1. HISTORIQUES DE COMMANDES
    # ===============================
    ".bash_history",        # Historique des commandes bash
    ".zsh_history",         # Historique pour Zsh
    ".mysql_history",       # Commandes MySQL (souvent avec mots de passe !)
    ".psql_history",        # Commandes PostgreSQL
    ".sqlite_history",      # Commandes SQLite
    ".php_history",         # Historique des commandes PHP CLI

    # ===============================
    # 2. CLES SSH & ACCES REMOTE
    # ===============================
    ".ssh/authorized_keys", # Clés autorisées SSH
    ".ssh/id_rsa",          # Clé privée SSH
    ".ssh/id_rsa.pub",      # Clé publique SSH
    ".ssh/config",          # Config SSH
    ".ssh/known_hosts",     # Machines déjà connectées

    # ===============================
    # 3. CONFIGURATION DU SHELL
    # ===============================
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".bash_logout",
    ".zshrc",
    ".cshrc",
    ".kshrc",
    ".login",
    ".logout",

    # ===============================
    # 4. CONFIGURATION D'APPLICATIONS
    # ===============================
    ".gitconfig",           # Config Git
    ".git-credentials",     # Identifiants Git (tokens souvent en clair)
    ".docker/config.json",  # Tokens Docker Hub / Registry
    ".npmrc",               # Tokens NPM
    ".composer/auth.json",  # Tokens Composer
    ".aws/credentials",     # Credentials AWS
    ".gcloud/credentials.db", # GCP Tokens

    # ===============================
    # 5. FICHIERS DE BASE DE DONNÉES LOCAUX
    # ===============================
    "db.sqlite3",
    "database.sqlite",
    ".local/share/db.sqlite3",
    ".config/dbeaver-data-sources.xml", # Config DBeaver avec credentials
    ".config/pgadmin/pgadmin4.db",     # PostgreSQL pgAdmin config

    # ===============================
    # 6. FICHIERS DE NAVIGATEURS (SESSIONS, TOKENS)
    # ===============================
    ".mozilla/firefox/profiles.ini",
    ".config/google-chrome/Default/Login Data",
    ".config/google-chrome/Default/Cookies",

    # ===============================
    # 7. HISTORIQUES ET JOURNAUX
    # ===============================
    ".viminfo",             # Historique vim (souvent chemins de fichiers sensibles)
    ".lesshst",             # Historique de less
    ".python_history",      # Historique Python REPL
    ".wget-hsts",           # Historique wget
    ".curlrc",              # Config curl (parfois avec tokens)

    # ===============================
    # 8. CLÉS GPG
    # ===============================
    ".gnupg/pubring.kbx",   # Clés publiques GPG
    ".gnupg/secring.gpg",   # Clés privées GPG
    ".gnupg/private-keys-v1.d/",

    # ===============================
    # 9. AUTRES
    # ===============================
    ".netrc",               # Identifiants pour FTP, HTTP, etc.
    ".config/Code/User/settings.json", # Config VS Code
    ".config/Code/User/keybindings.json",
    ".config/slack/",       # Tokens Slack
    ".local/share/keyrings/", # GNOME Keyring (tokens, mdp chiffrés)


    # Shell / historique
    ".zprofile",
    ".bash_logout",
    ".zlogout",
    ".history",

    # SSH
    ".ssh/id_dsa",
    ".ssh/id_ecdsa",
    ".ssh/id_ed25519",

    # Environnements / secrets
    ".env",
    ".gnupg/trustdb.gpg",

    # Dépendances / configs dev
    ".yarnrc",
    ".composer/config.json",
    ".pip/pip.conf",

    # Applications / navigateurs
    ".mozilla/firefox/profiles.ini",
    ".config/google-chrome/Default/Preferences",
    ".config/google-chrome/Default/Login Data",

    # Logs / caches
    ".cache/",
    ".local/share/",
    ".config/",
    ".node_repl_history",

    # Fichiers de sauvegarde ou temporaires
    ".backup"    
]
