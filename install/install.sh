#!/bin/sh
# Copyright (c) 2019 Polyverse Corporation

remote_scripts_location="https://github.com/polyverse/polytect/releases/latest/download"

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
    systemd_unit_dir="/etc/systemd/system"
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

call_script() {
    script_name="$1"
    shift 1

    echo "Delegating to script $script_name based on detected init system."
    echo "Looking for $script_name in current directory (if you downloaded the entire Github release)"
    if [ -f "./$script_name" ]; then
        if [ ! -x "./$script_name" ]; then
            echo ""
            echo "The script $script_name exists locally, but is not marked executable."
            echo "You may either run it yourself, or must mark it executable if you wish"
            echo "this triage script to call it for you."
            echo ""
            echo "You can do this by running:"
            echo "sudo chmod a+x $script_name"
            echo ""
            return 1
        fi

        ./$script_name "$@"
        return $?
    fi

    remote_location="$remote_scripts_location/$script_name"
    echo "No local script found. Looking at remote location: $remote_location"
    type wget 2>&1 1>/dev/null
    if [ "$?" = "0" ]; then
        echo "Using wget to download $script_name (and execute it)..."
        wget -q -O -  "$remote_location" | sh -s "$@"
        return $?
    else
        type curl 2>&1 1>/dev/null
        if [ "$?" = "0" ]; then
            echo "Using curl to download $script_name (and execute it)..."
            curl -L "$remote_location" | sh -s "$@"
            return $?
        else
            echo "Neither curl nor wget found on the system. Unable to pull remote script: $remote_location"
            return 1
        fi
    fi

    echo "Should never reach this point"
    return 1
}

echo "Polytect installer"
echo ""
echo "This script detects your init system and triages to the appropriate sub-script"
echo "for that init system."
echo ""

# Ensuring we are root
if [ "$EUID" != "0" ] && [ "$USER" != "root" ]; then
   echo "This script must be run as root because it needs to reliably detect the init system,"
   echo "and be able to install the polytect service using the appropriate install script."
   exit 1
fi

is_systemd
if [ "$?" = "0" ]; then
    echo "Detect init system: systemd (https://systemd.io)."
    echo "Sending this to the systemd script..."
    call_script "systemd-install.sh" "$@"
    exit $?
fi

echo "No more init systems supported. Polytect does not have a recipe for your system."