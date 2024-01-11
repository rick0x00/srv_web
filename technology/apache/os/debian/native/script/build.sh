#!/usr/bin/env bash

# ============================================================ #
# Tool Created date: 08 jan 2024                               #
# Tool Created by: Henrique Silva (rick.0x00@gmail.com)        #
# Tool Name: Apache Install                                    #
# Description: My simple script to provision Apache Server     #
# License: software = MIT License                              #
# Remote repository 1: https://github.com/rick0x00/srv_web     #
# Remote repository 2: https://gitlab.com/rick0x00/srv_web     #
# ============================================================ #
# base content:
#   
# ============================================================ #
# start root user checking
if [ $(id -u) -ne 0 ]; then
    echo "Please use root user to run the script."
    exit 1
fi
# end root user checking
# ============================================================ #
# start set variables

DATE_NOW="$(date +Y%Ym%md%d-H%HM%MS%S)" # extracting date and time now

### apache vars
site_name="apache"
site_path="/var/www/html"
site_subdomain="apache"
site_root_domain="local"
site_ssl_enabled="false"

os_distribution="Debian"
os_version=("11" "bullseye")

webserver_engine="apache"

port_http[0]="80" # http number Port
port_http[1]="tcp" # tcp protocol Port 

port_https[0]="443" # https number Port
port_https[1]="tcp" # tcp protocol Port 

build_path="/usr/local/src"
workdir="/var/www/"
persistence_volumes=("/var/www/" "/var/log/")
expose_ports="${port_http[0]}/${port_http[1]} ${port_https[0]}/${port_https[1]}"
# end set variables
# ============================================================ #
# start definition functions
# ============================== #
# start complement functions

function remove_space_from_beginning_of_line {
    #correct execution
    #remove_space_from_beginning_of_line "<number of spaces>" "<file to remove spaces>"

    # Remove a white apace from beginning of line
    #sed -i 's/^[[:space:]]\+//' "$1"
    #sed -i 's/^[[:blank:]]\+//' "$1"
    #sed -i 's/^ \+//' "$1"

    # check if 2 arguments exist
    if [ $# -eq 2 ]; then
        #echo "correct quantity of args"
        local spaces="${1}"
        local file="${2}"
    else
        #echo "incorrect quantity of args"
        local spaces="4"
        local file="${1}"
    fi 
    sed -i "s/^[[:space:]]\{${spaces}\}//" "${file}"
}

function massager_sharp() {
    line_divisor="###########################################################################################"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

function massager_line() {
    line_divisor="-------------------------------------------------------------------------------------------"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

function massager_plus() {
    line_divisor="++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "${line_divisor}"
    echo "$*"
    echo "${line_divisor}"
}

# end complement functions
# ============================== #
# start main functions

function pre_install_server () {
    massager_line "Pre install server step"

    function install_generic_tools() {
        # update repository
        apt update

        #### start generic tools
        # install basic network tools
        apt install -y net-tools iproute2 traceroute iputils-ping mtr
        # install advanced network tools
        apt install -y tcpdump nmap netcat
        # install DNS tools
        apt install -y dnsutils
        # install process inspector
        apt install -y procps htop
        # install text editors
        apt install -y nano vim 
        # install web-content downloader tools
        apt install -y wget curl
        # install uncompression tools
        apt install -y unzip tar
        # install file explorer with CLI
        apt install -y mc
        # install task scheduler 
        apt install -y cron
        # install log register 
        apt install -y rsyslog
        #### stop generic tools
    }

    function install_dependencies () {
        echo "step not necessary"
        exit 1;
    }

    function install_complements () {
        echo "step not necessary"
        exit 1;
    }

    install_generic_tools
    #install_dependencies;
    #install_complements;
}

##########################
## install steps

function install_apache () {
    # installing Apache
    massager_plus "Installing Apache"

    function install_from_source () {
        echo "step not configured"
        exit 1;
    }

    function install_from_apt () {
        apt install -y apache2 apache2-utils apache2-doc
    }

    ## Installing apache From Source ##
    #install_from_source

    ## Installing apache From APT (Debian package manager) ##
    install_from_apt
}
#############################

function install_server () {
    massager_line "Install server step"

    ##  apache
    install_apache
}

#############################
## start/stop steps ##

function start_apache () {
    # starting apache
    massager_plus "Starting Apache"

    #service apache2 start
    #systemctl start apache
    /etc/init.d/apache2 start

    # Daemon running on foreground mode
    #apachectl -D FOREGROUND
}

function stop_apache () {
    # stopping apache
    massager_plus "Stopping Apache"

    #service apache2 stop
    #systemctl stop apache
    /etc/init.d/apache2 stop

    # ensuring it will be stopped
    # for Daemon running on foreground mode
    killall apache2
}
################################

function start_server () {
    massager_line "Starting server step"
    # Starting Service

    # starting apache
    start_apache
}

function stop_server () {
    massager_line "Stopping server step"

    # stopping server
    stop_apache
}

################################
## configuration steps ##
function configure_apache() {
    # Configuring Apache
    massager_plus "Configuring Apache"

    local site_name="${site_name:-debian}"
    local site_path="${site_path:-'/var/www/html'}"
    local site_subdomain="${site_subdomain:-debian}"
    local site_root_domain="${site_root_domain:-local}"
    local site_ssl_enabled="${site_ssl_enabled:-false}"

    function configure_apache_security() {
        # Configuring Apache Security
        massager_plus "Configuring Apache Security"

        # disable apache directory listing
        cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bkp_${DATE_NOW} 
        sed -i "/Options/s/Indexes FollowSymLinks/FollowSymLinks/" /etc/apache2/apache2.conf

        # disable apache server banner
        cp /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-enabled/security.conf.bkp_${DATE_NOW} 
        sed -i "/ServerTokens/s/OS/Prod/" /etc/apache2/conf-enabled/security.conf
        sed -i "/ServerSignature/s/On/Off/" /etc/apache2/conf-enabled/security.conf

        # strict HTTP Options ????????


        # disable default apache site
        a2dissite 000-default.conf

        # enable SSL module to Apache
        a2enmod ssl

        # Creating my personalized configurations of SSL sites
        echo '
        # disable old insecure protocols
        SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
        
        # Enhance cypher suites
        SSLHonorCipherOrder on
        SSLCipherSuite          ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS
        
        # Disable SSL compression
        SSLCompression off

        # Enable HTTP Strict Transport Security (HSTS)
        SSLOptions +StrictRequire
        ' > /etc/apache2/ssl_options-sites.conf
        remove_space_from_beginning_of_line "8" "/etc/apache2/ssl_options-sites.conf"

    }

    function configure_apache_site() {
        # Configuring Apache Site
        massager_plus "Configuring Apache Site"
        # setting Apache Site

        #site_name="debian"
        #site_path="/var/www/html"
        #site_subdomain="debian"
        #site_root_domain="local"
        #site_ssl_enabled="false"

        
        # setting apache server to listening on specified ports
        sed -i "/Listen 80/s/80/${port_http[0]}/" /etc/apache2/ports.conf
        sed -i "/Listen 443/s/443/${port_https[0]}/" /etc/apache2/ports.conf

        # correct sample file to apache sites
        echo "
        <VirtualHost *:site_http_port>
            ServerName site_subdomain.site_root_domain
            ServerAdmin sysadmin@site_root_domain

            #DocumentRoot site_path

            ## Redirecting to SSL site
            #Redirect / https://site_subdomain.site_root_domain:site_https_port/

            ErrorLog ${APACHE_LOG_DIR}/error.log
            CustomLog ${APACHE_LOG_DIR}/access.log combined

        </VirtualHost>

        <VirtualHost *:site_https_port>
            ServerName site_subdomain.site_root_domain
            ServerAdmin sysadmin@site_root_domain

            DocumentRoot site_path

            ##### Redirecting subpath to another site
            ####Redirect 301 /xpto_subbpath https://another_site.local

            #SSLEngine on
            #SSLCertificateFile      /etc/letsencrypt/live/site_root_domain/cert.pem
            #SSLCertificateKeyFile   /etc/letsencrypt/live/site_root_domain/privkey.pem
            #SSLCertificateChainFile /etc/letsencrypt/live/site_root_domain/chain.pem
            #Include /etc/apache2/ssl_options-sites.conf

            ErrorLog ${APACHE_LOG_DIR}/error.log
            CustomLog ${APACHE_LOG_DIR}/access.log combined

        </VirtualHost>
        " >  /etc/apache2/sites-available/site_sample.conf

        remove_space_from_beginning_of_line "8" "/etc/apache2/sites-available/site_sample.conf"

        # configure site
        cp "/etc/apache2/sites-available/site_sample.conf" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_http_port/${port_http[0]}/" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_https_port/${port_https[0]}/" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s|site_path|${site_path}|" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_subdomain/${site_subdomain}/" "/etc/apache2/sites-available/${site_name}.conf"
        sed -i "s/site_root_domain/${site_root_domain}/" "/etc/apache2/sites-available/${site_name}.conf"

        if [ "${site_ssl_enabled}" == "true" ] || [ "${site_ssl_enabled}" == "yes" ]; then
            # SSL Enabled on site
            # Enable SSL page
            # enabling http page redirect for https page
            sed -i "/#Redirect/s/#Redirect/Redirect/" "/etc/apache2/sites-available/${site_name}.conf"
            # Configuring SSL options on page
            sed -i "/SSL/s/#//" "/etc/apache2/sites-available/${site_name}.conf"
            sed -i "/Include/s/#//" "/etc/apache2/sites-available/${site_name}.conf"
        else
            # SSL Disabled on site
            # enabling http page work
            sed -i "/DocumentRoot/s/#//" "/etc/apache2/sites-available/${site_name}.conf"
        fi

        # enabling site
        a2ensite ${site_name}.conf

        # adjusting site path permissions, owner and group
        find ${site_path} -type d -exec chmod 755 {} +
        find ${site_path} -type f -exec chmod 644 {} +
        chown www-data:www-data -R ${site_path}
    }

    # configuring security on Apache
    configure_apache_security

    # setting apache site
    configure_apache_site
}

################################

function configure_server () {
    # configure server
    massager_line "Configure server"

    # configure apache 
    configure_apache
}

################################
## check steps ##

function check_configs_apache() {
    # Check config of apache
    massager_plus "Check config of apache"

    apachectl configtest
}

#####################

function check_configs () {
    massager_line "Check Configs server"

    # check if the configuration file is ok.
    check_configs_apache

}

################################
## test steps ##

function test_apache () {
    # Testing Apache
    massager_plus "Testing of Apache"


    # is running ????
    #service apache2 status
    #systemctl status  --no-pager -l apache2
    /etc/init.d/apache2 status
    ps -ef --forest | grep apache

    # is listening ?
    ss -pultan | grep :${port_http[0]}
    ss -pultan | grep :${port_https[0]}

    # is creating logs ????
    tail /var/log/apache2/*

    # Validating...

    ## scanning apache ports using NETCAT
    nc -zv localhost ${port_http[0]}
    nc -zv localhost ${port_https[0]}
    #root@wordpress:~# nc -zv localhost 80
    #Connection to localhost (::1) 80 port [tcp/http] succeeded!

    ## scanning apache ports using NMAP
    nmap -A localhost -sT -p ${port_http[0]} 
    nmap -A localhost -sT -p ${port_https[0]} 
	#root@apache:/vagrant# nmap -A localhost -sT -p 80
	#Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-11 00:25 UTC
	#Nmap scan report for localhost (127.0.0.1)
	#Host is up (0.000091s latency).
	#Other addresses for localhost (not scanned): ::1

	#PORT   STATE SERVICE VERSION
	#80/tcp open  http    Apache httpd
	#|_http-server-header: Apache
	#|_http-title: Apache2 Debian Default Page: It works
	#Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	#Device type: general purpose
	#Running: Linux 2.6.X
	#OS CPE: cpe:/o:linux:linux_kernel:2.6.32
	#OS details: Linux 2.6.32
	#Network Distance: 0 hops

	#OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	#Nmap done: 1 IP address (1 host up) scanned in 8.87 seconds
	#root@apache:/vagrant#


    ## simulating web requests using CURL
    curl --head http://localhost
    #root@apache:/vagrant# curl --head http://localhost
	#HTTP/1.1 200 OK
	#Date: Thu, 11 Jan 2024 00:27:56 GMT
	#Server: Apache
	#Last-Modified: Thu, 11 Jan 2024 00:16:54 GMT
	#ETag: "29cd-60ea07700808b"
	#Accept-Ranges: bytes
	#Content-Length: 10701
	#Vary: Accept-Encoding
	#Content-Type: text/html
	#
	#root@apache:/vagrant# 

    curl -v http://localhost | head
    #root@apache:/vagrant# curl -v http://localhost | head
    #  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
    #                                 Dload  Upload   Total   Spent    Left  Speed
    #  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying ::1:80...
    #* Connected to localhost (::1) port 80 (#0)
    #> GET / HTTP/1.1
    #> Host: localhost
    #> User-Agent: curl/7.74.0
    #> Accept: */*
    #> 
    #* Mark bundle as not supporting multiuse
    #< HTTP/1.1 200 OK
    #< Date: Thu, 11 Jan 2024 00:30:12 GMT
    #< Server: Apache
    #< Last-Modified: Thu, 11 Jan 2024 00:16:54 GMT
    #< ETag: "29cd-60ea07700808b"
    #< Accept-Ranges: bytes
    #< Content-Length: 10701
    #< Vary: Accept-Encoding
    #< Content-Type: text/html
    #< 
    #{ [10701 bytes data]
    #1
    #<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    #<html xmlns="http://www.w3.org/1999/xhtml">
    #  <head>
    #    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    #    <title>Apache2 Debian Default Page: It works</title>
    #    <style type="text/css" media="screen">
    #  * {
    #    margin: 0px 0px 0px 0px;
    #    padding: 0px 0px 0px 0px;
    #00 10701  100 10701    0     0   870k      0 --:--:-- --:--:-- --:--:--  870k
    #* Connection #0 to host localhost left intact
    #(23) Failed writing body
    #root@apache:/vagrant# 
    #

}

################################

function test_server () {
    massager_line "Testing server"

    # testing apache
    test_apache

}

################################

# end main functions
# ============================== #

# end definition functions
# ============================================================ #
# start argument reading

# end argument reading
# ============================================================ #
# start main executions of code
massager_sharp "Starting apache installation script"
pre_install_server;
install_server;
stop_server;
configure_server;
check_configs;
start_server;
test_server;
massager_sharp "Finished apache installation script"


