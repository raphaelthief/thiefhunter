windows_traversals_base = [
    # Configuration système de base
    "C:\\windows\\win.ini",                    # Fichier historique toujours présent
    "C:\\windows\\system.ini",                  # Vieux fichier config Windows
    "C:\\windows\\system32\\drivers\\etc\\hosts",  # Fichier hosts local
    "C:\\windows\\system32\\drivers\\etc\\networks",
    "C:\\windows\\system32\\drivers\\etc\\protocol",
    "C:\\windows\\system32\\drivers\\etc\\services",

    # SAM et registre (attention, nécessite souvent des privilèges)
    "C:\\windows\\system32\\config\\SAM",         # Comptes locaux
    "C:\\windows\\system32\\config\\SYSTEM",      # Informations système
    "C:\\windows\\system32\\config\\SECURITY",    # Infos de sécurité
    "C:\\windows\\system32\\config\\SOFTWARE",    # Logiciels installés
    "C:\\windows\\system32\\config\\DEFAULT",     # Paramètres par défaut

    # Journaux d'événements
    "C:\\windows\\system32\\winevt\\Logs\\System.evtx",
    "C:\\windows\\system32\\winevt\\Logs\\Security.evtx",
    "C:\\windows\\system32\\winevt\\Logs\\Application.evtx",

    # Fichiers de configuration IIS (serveur web)
    "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex230101.log",  # Exemple log IIS
    "C:\\inetpub\\wwwroot\\web.config",                    # Config du site IIS
    "C:\\windows\\system32\\inetsrv\\config\\applicationHost.config"  # Config globale IIS
]