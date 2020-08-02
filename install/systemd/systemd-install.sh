#!/bin/sh
# Copyright (c) 2019 Polyverse Corporation

zerotect_binary="zerotect"
zerotect_remote_location="https://github.com/polyverse/zerotect/releases/latest/download"
zerotect_local_location="/usr/local/bin"

tomldir="/etc/zerotect"
tomlfile="zerotect.toml"

systemd_unit_dir="/etc/systemd/system"
systemd_unit_file="zerotect.service"

print_usage() {
    printf "\n"
    printf "Usage:\n"
    printf "  $0 <polycorder auth key> [node id] | uninstall\n"
    printf "\n"
    printf "<polycorder auth key> : The polycorder auth key allows zerotect to send detected events to Polycorder,\n"
    printf "                        the hosted analytics platform available in the Polyverse Account dashboard.\n"
    printf "[node id]             : An optional node identifier/discriminator which would allow analytics to\n"
    printf "                        differentiate this particular node's events.\n"
    printf "uninstall             : When used as the single argument, removes zerotect from this system.\n"
}

is_systemd() {
    printf "Checking whether this host was inited by systemd...\n"
    printf "Checking if /proc/1/comm is systemd (a reliable way)\n"
    proc1=$(cat /proc/1/comm)
    if [ "$proc1" = "systemd" ]; then
        printf "It is systemd\n"
    else
        printf "It is $proc1 (not systemd)\n"
        printf "No other methods for detection currently supported.\n"
        printf "\n"
        printf "If you believe you are running systemd, but this script is mistaken, please\n"
        printf "contact us at support@polyverse.com to bring it to our notice.\n"
        printf "\n"
        return 1
    fi

    printf "Ensuring systemd unit file directory ($systemd_unit_dir) exists...\n"
    if [ ! -d "$systemd_unit_dir" ]; then
        printf "The directory $systemd_unit_dir is required to configure the zerotect service.\n"
        printf "This script does not support any non-standard configurations and behaviors of systemd.\n"
        return 1
    fi

    return 0
}

download_latest_zerotect() {

    #make sure local location exists
    if [ ! -d "$zerotect_local_location" ]; then
        printf "$zerotect_local_location does not exist. Creating it...\n"
        mkdir -p -m 755 $zerotect_local_location
    fi

    printf "Downloading the latest $zerotect_binary from $zerotect_location, and saving into $zerotect_local_location\n"
    type wget 2>&1 1>/dev/null
    if [ "$?" = "0" ]; then
        printf "Using wget to download zerotect...\n"
        wget -q -O "$zerotect_local_location/$zerotect_binary" "$zerotect_remote_location/$zerotect_binary"
    else
        type curl 2>&1 1>/dev/null
        if [ "$?" = "0" ]; then
            printf "Using curl to download zerotect...\n"
            output=$(curl -L -o "$zerotect_local_location/$zerotect_binary" "$zerotect_remote_location/$zerotect_binary" 2>&1)
            possible_too_many_requests=$(echo "$output" | grep "429 too many requests")
            if [[ "$possible_too_many_requests" != "" ]]; then
                echo "Upstream said we made too many requests. Sleeping for 10 seconds..."
                sleep 10
                echo "Retrying recursively..."
                download_latest_zerotect
            fi
        else
            printf "Neither curl nor wget found on the system. Unable to download zerotect binary.\n"
            exit 1
        fi
    fi

    printf "Making zerotect executable...\n"
    chmod 755 "$zerotect_local_location/$zerotect_binary"
}

create_zerotect_conf() {
    authey="$1"
    nodeid="$2"

    printf "Creating zerotect configuration file at $tomldir/$tomlfile\n"
    if [ ! -d "$tomldir" ]; then
        mkdir -p -m 755 "$tomldir"
    fi

    printf "Sending events to polycorder with authkey: $authkey\n"
    tomlcontents=$(printf "[auto_configure]")
    tomlcontents=$(printf "${tomlcontents}\nexception_trace = true")
    tomlcontents=$(printf "${tomlcontents}\nfatal_signals = true")
    tomlcontents=$(printf "${tomlcontents}\nklog_include_timestamp = true")
    tomlcontents=$(printf "${tomlcontents}\n ")
    tomlcontents=$(printf "${tomlcontents}\n[monitor_config]")
    tomlcontents=$(printf "${tomlcontents}\ngobble_old_events = false")
    tomlcontents=$(printf "${tomlcontents}\n ")
    tomlcontents=$(printf "${tomlcontents}\n[polycorder_config]")
    tomlcontents=$(printf "${tomlcontents}\nauth_key = '$authkey'")

    if [ "$nodeid" != "" ]; then
        printf "Assigning events to nodeid: $nodeid\n"
        tomlcontents=$(printf "${tomlcontents}\nnode_id = '$nodeid'")
    else
        printf "Not assigning events to any nodeid.\n"
    fi
    tomlcontents=$(printf "${tomlcontents}\n ")

    printf "Final configuration file contents are:\n$tomlcontents\n"
    printf "$tomlcontents" > $tomldir/$tomlfile
    chmod 644 $tomldir/$tomlfile
}

create_systemd_unit_file() {
    ## Trailing newlines are removed: https://unix.stackexchange.com/questions/446992/when-printing-a-variable-that-contains-newlines-why-is-the-last-newline-strippe
    systemd_unit=$(printf "[Unit]")
    systemd_unit=$(printf "${systemd_unit}\nDescription=The polyverse monitoring agent for monitoring zero-day attack attempts")
    systemd_unit=$(printf "${systemd_unit}\nRequires=network-online.target")
    systemd_unit=$(printf "${systemd_unit}\nAfter=network-online.target")
    systemd_unit=$(printf "${systemd_unit}\n ")
    systemd_unit=$(printf "${systemd_unit}\n[Service]")
    systemd_unit=$(printf "${systemd_unit}\nExecStart=$zerotect_local_location/$zerotect_binary --configfile $tomldir/$tomlfile")
    systemd_unit=$(printf "${systemd_unit}\n ")
    systemd_unit=$(printf "${systemd_unit}\n[Install]")
    systemd_unit=$(printf "${systemd_unit}\nWantedBy=multi-user.target")
    systemd_unit=$(printf "${systemd_unit}\nWantedBy=graphical.target")
    systemd_unit=$(printf "${systemd_unit}\n ")

    printf "Writing $systemd_unit_dir/$systemd_unit_file file with contents:\n"
    printf "$systemd_unit\n"

    printf "$systemd_unit" > $systemd_unit_dir/$systemd_unit_file

    printf "Enable zerotect monitor starting at bootup\n"
    systemctl enable zerotect

    printf "Starting zerotect now\n"
    systemctl start zerotect
}

ensure_zerotect_running() {
    pid=$(pgrep zerotect)
    if [ -z "$pid" ]; then
        printf "zerotect is not running in the background. Something went wrong.\n"
        printf "Service status:\m"
        systemctl status zerotect
        exit 1
    else
        printf "zerotect successfully installed and running in the background.\n"
    fi
}

uninstall() {
    if [ -f "$systemd_unit_dir/$systemd_unit_file" ]; then
        printf "Found zerotect service unit: $systemd_unit_dir/$systemd_unit_file. Removing it (after stopping service).\n"
        systemctl stop zerotect
        systemctl disable zerotect
        rm $systemd_unit_dir/$systemd_unit_file
    fi

    if [ -f "$zerotect_local_location/$zerotect_binary" ]; then
        printf "Found zerotect binary: $zerotect_local_location/$zerotect_binary. Removing it.\n"
        rm $zerotect_local_location/$zerotect_binary
    fi

    if [ -f "$tomldir/$tomlfile" ]; then
        printf "Found toml configuration file: $tomldir/$tomlfile. Removing it.\n"
        rm $tomldir/$tomlfile
        printf "Removing directory $tomldir\n"
        rmdir $tomldir
    fi
}

printf "zerotect installer for systemd\n"

# Ensuring we are root
if [ "$EUID" != "0" ] && [ "$USER" != "root" ]; then
   printf "This script must be run as root because it needs to reliably detect the init system,\n"
   printf "and be able to install the zerotect service if systemd is found.\n"
   exit 1
fi

is_systemd
if [ "$?" != "0" ]; then
    printf "This script only works on systems inited by systemd (https://systemd.io).\n"
    exit 1
fi

#Validating parameters
if [ "$#" -lt 1 ]; then
    printf "Please specify at least one argument (the polycorder auth key)\n"
    print_usage
    exit 1
fi

if [ "$1" = "uninstall" ]; then
    if [ "$#" -gt 1 ]; then
        printf "When 'uninstall' is specified, it must be the sole argument.\n"
        print_usage
        exit 1
    fi
    uninstall
    exit 0
fi

if [ "$#" -gt 2 ]; then
    printf "Please specify at most two arguments (the polycorder auth key, and the node id)\n"
    print_usage
    exit 1
fi

authkey="$1"
nodeid="$2"


download_latest_zerotect

create_zerotect_conf "$authkey" "$nodeid"

create_systemd_unit_file

ensure_zerotect_running