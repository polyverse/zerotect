#!/bin/sh
# Copyright (c) 2019 Polyverse Corporation

remote_scripts_location="https://github.com/polyverse/zerotect/releases/latest/download"

print_usage() {
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
        return 1
    fi

    return 0
}

is_openrc() {
    printf "Checking whether this host was inited by OpenRC...\n"
    printf "Checking if /run/openrc/softlevel is exists and is readable (a reliable way)...\n"
    if [ -r /run/openrc/softlevel ]; then
        printf "It is OpenRC\n"
    else
        printf "Not inited by OpenRC (file /run/openrc/softlevel doesn't exist or is not readable)\n"
        return 1
    fi

    return 0
}

is_upstart() {
    printf "Checking whether this host was inited by upstart...\n"
    printf "Checking if /sbin/init version tells us it's upstart...\n"
    initver=$(/sbin/init --version 2>&1)
    case "$initver" in
        *upstart*)
            printf "It is upstart\n"
        ;;
        *)
            printf "Not inited by Upstart (file '/sbin/init --version' didn't report upstart)\n"
            return 1
        ;;
    esac

    return 0
}


call_script() {
    script_name="$1"
    shift 1

    printf "Delegating to script $script_name based on detected init system.\n"
    printf "Looking for $script_name in current directory (if you downloaded the entire Github release)\n"
    if [ -f "./$script_name" ]; then
        if [ ! -x "./$script_name" ]; then
            printf "\n"
            printf "The script $script_name exists locally, but is not marked executable.\n"
            printf "You may either run it yourself, or must mark it executable if you wish\n"
            printf "this triage script to call it for you.\n"
            printf "\n"
            printf "You can do this by running:\n"
            printf "sudo chmod a+x $script_name\n"
            printf "\n"
            return 1
        fi

        ./$script_name "$@"
        return $?
    fi

    remote_location="$remote_scripts_location/$script_name"
    printf "No local script found. Looking at remote location: $remote_location\n"
    type wget 2>&1 1>/dev/null
    if [ "$?" = "0" ]; then
        printf "Using wget to download $script_name (and execute it)...\n"
        wget -q -O -  "$remote_location" | sh -s "$@"
        return $?
    else
        type curl 2>&1 1>/dev/null
        if [ "$?" = "0" ]; then
            printf "Using curl to download $script_name (and execute it)...\n"
            curl -s -L "$remote_location" | sh -s "$@"
            return $?
        else
            printf "Neither curl nor wget found on the system. Unable to pull remote script: $remote_location\n"
            return 1
        fi
    fi

    printf "Should never reach this point\n"
    return 1
}

printf "Zerotect installer\n"
printf "\n"
printf "This script detects your init system and triages to the appropriate sub-script\n"
printf "for that init system.\n"
printf "\n"

# Ensuring we are root
if [ "$EUID" != "0" ] && [ "$USER" != "root" ]; then
   printf "This script must be run as root because it needs to reliably detect the init system,\n"
   printf "and be able to install the zerotect service using the appropriate install script.\n"
   exit 1
fi

is_systemd
if [ "$?" = "0" ]; then
    printf "Detect init system: systemd (https://systemd.io).\n"
    printf "Sending this to the systemd script...\n"
    call_script "systemd-install.sh" "$@"
    exit $?
fi

is_openrc
if [ "$?" = "0" ]; then
    printf "Detect init system: OpenRC (https://wiki.gentoo.org/wiki/Project:OpenRC).\n"
    printf "Sending this to the OpenRC script...\n"
    call_script "openrc-install.sh" "$@"
    exit $?
fi

is_upstart
if [ "$?" = "0" ]; then
    printf "Detect init system: upstart (http://upstart.ubuntu.com/).\n"
    printf "Sending this to the upstart script...\n"
    call_script "upstart-install.sh" "$@"
    exit $?
fi

printf "No more init systems supported. Zerotect does not have a recipe for your system.\n"