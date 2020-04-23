#!/bin/sh
# Copyright (c) 2019 Polyverse Corporation

polytect_binary="polytect"
polytect_remote_location="https://github.com/polyverse/polytect/releases/latest/download"
polytect_local_location="/usr/local/bin"

tomldir="/etc/polytect"
tomlfile="polytect.toml"

systemd_unit_dir="/etc/systemd/system"
systemd_unit_file="polytect.service"

print_usage() {
    echo "Usage:"
    echo "  $0 <polycorder auth key> [node id] | uninstall"
    echo ""
    echo "<polycorder auth key> : The polycorder auth key allows polytect to send detected events to Polycorder,"
    echo "                        the hosted analytics platform available in the Polyverse Account dashboard."
    echo "[node id]             : An optional node identifier/discriminator which would allow analytics to"
    echo "                        differentiate this particular node's events."
    echo "uninstall             : When used as the single argument, removes polytect from this system."
}

is_systemd() {
    echo "Checking if systemd unit file directory exists..."
    if [ ! -d "$systemd_unit_dir" ]; then
        echo "The directory $systemd_unit_dir is required to configure the polytect service."
        echo "This script does not support any non-standard configurations and behaviors of systemd."
        exit 1
    fi

    echo "Checking whether this host was inited by systemd..."
    echo "Checking if /proc/1/comm is systemd (a reliable way)"
    proc1=$(cat /proc/1/comm)
    if [ "$proc1" = "systemd" ]; then
        echo "It is systemd"
        return 0
    else
        echo "It is $proc1 (not systemd)"
    fi
    echo "No other methods for detection currently supported."
    echo ""
    echo "If you believe you are running systemd, but this script is mistaken, please"
    echo "contact us at support@polyverse.com to bring it to our notice."
    echo ""
    return 1
}

download_latest_polytect() {

    #make sure local location exists
    if [ ! -d "$polytect_local_location" ]; then
        echo "$polytect_local_location does not exist. Creating it..."
        mkdir -p -m 755 $polytect_local_location
    fi

    echo "Downloading the latest $polytect_binary from $polytect_location, and saving into $polytect_local_location"
    type wget 2>&1 1>/dev/null
    if [ "$?" = "0" ]; then
        echo "Using wget to download polytect..."
        wget -O "$polytect_local_location/$polytect_binary" "$polytect_remote_location/$polytect_binary"
    else
        type curl 2>&1 1>/dev/null
        if [ "$?" = "0" ]; then
            echo "Using curl to download polytect..."
            curl -L -o "$polytect_local_location/$polytect_binary" "$polytect_remote_location/$polytect_binary"
        else
            echo "Neither curl nor wget found on the system. Unable to download polytect binary."
            exit 1
        fi
    fi

    echo "Making polytect executable..."
    chmod 755 "$polytect_local_location/$polytect_binary"
}

create_polytect_conf() {
    authey="$1"
    nodeid="$2"

    echo "Creating polytect configuration file at $tomldir/$tomlfile"
    if [ ! -d "$tomldir" ]; then
        mkdir -p -m 755 "$tomldir"
    fi

    echo "Sending events to polycorder with authkey: $authkey"
    tomlcontents="$tomlcontents\n[auto_configure]"
    tomlcontents="$tomlcontents\nexception_trace = true"
    tomlcontents="$tomlcontents\nfatal_signals = true"
    tomlcontents="$tomlcontents\n"
    tomlcontents="$tomlcontents\n[polycorder_config]"
    tomlcontents="$tomlcontents\nauth_key = '$authkey'"

    if [ "$nodeid" != "" ]; then
        echo "Assigning events to nodeid: $nodeid"
        tomlcontents="$tomlcontents\nnode_id = '$nodeid'"
    echo
        echo "Not assigning events to any nodeid."
    fi
    tomlcontents="$tomlcontents\n"

    echo "Final configuration file contents are:\n$tomlcontents"
    echo $tomlcontents > $tomldir/$tomlfile
    chmod 644 $tomldir/$tomlfile
}

create_systemd_unit_file() {
    systemd_unit="[Unit]"
    systemd_unit="$systemd_unit\nDescription=The polyverse monitoring agent for monitoring zero-day attack attempts"
    systemd_unit="$systemd_unit\nRequires=network-online.target"
    systemd_unit="$systemd_unit\nAfter=network-online.target"
    systemd_unit="$systemd_unit\n"
    systemd_unit="$systemd_unit\n[Service]"
    systemd_unit="$systemd_unit\nExecStart=/usr/local/bin/polytect --configfile $tomldir/$tomlfile"
    systemd_unit="$systemd_unit\n"

    echo "Writing $systemd_unit_dir/$systemd_unit_file file with contents:"
    echo "$systemd_unit"

    echo "$systemd_unit" > $systemd_unit_dir/$systemd_unit_file

    echo "Enable polytect monitor starting at bootup"
    systemctl enable polytect

    echo "Starting polytect now"
    systemctl start polytect
}

uninstall() {
    if [ -f "$systemd_unit_dir/$systemd_unit_file" ]; then
        echo "Found polytect service unit: $systemd_unit_dir/$systemd_unit_file. Removing it (after stopping service)."
        systemctl stop polytect
        systemctl disable polytect
        rm $systemd_unit_dir/$systemd_unit_file
    fi

    if [ -f "$polytect_local_location/$polytect_binary" ]; then
        echo "Found polytect binary: $polytect_local_location/$polytect_binary. Removing it."
        rm $polytect_local_location/$polytect_binary
    fi

    if [ -f "$tomldir/$tomlfile" ]; then
        echo "Found toml configuration file: $tomldir/$tomlfile. Removing it."
        rm $tomldir/$tomlfile
        echo "Removing directory $tomldir"
        rmdir $tomldir
    fi
}

echo "Polytect installer for systemd"

#Validating parameters
if [ "$#" -lt 1 ]; then
    echo "Please specify at least one argument (the polycorder auth key)"
    print_usage
    exit 1
fi

if [ "$1" = "uninstall" ]; then
    if [ "$#" -gt 1 ]; then
        echo "When 'uninstall' is specified, it must be the sole argument."
        print_usage
        exit 1
    fi
    uninstall
    exit 0
fi

if [ "$#" -gt 2 ]; then
    echo "Please specify at most two arguments (the polycorder auth key, and the node id)"
    print_usage
    exit 1
fi

authkey="$1"
nodeid="$2"

# Ensuring we are root
if [ "$EUID" != "0" ] && [ "$USER" != "root" ]; then
   echo "This script must be run as root because it needs to reliably detect the init system,"
   echo "and be able to install the polytect service if systemd is found."
   exit 1
fi

is_systemd
if [ "$?" != "0" ]; then
    echo "This script only works on systems inited by systemd (https://systemd.io)."
    exit 1
fi

download_latest_polytect

create_polytect_conf "$authkey" "$nodeid"

create_systemd_unit_file

echo "Polytect successfully installed and running in the background."
