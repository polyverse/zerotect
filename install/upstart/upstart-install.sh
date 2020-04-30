#!/bin/sh
# Copyright (c) 2019 Polyverse Corporation

polytect_binary="polytect"
polytect_remote_location="https://github.com/polyverse/polytect/releases/latest/download"
polytect_local_location="/usr/local/bin"

tomldir="/etc/polytect"
tomlfile="polytect.toml"

upstart_job_dir="/etc/init"
upstart_job_file="polytect.conf"

print_usage() {
    printf "\n"
    printf "Usage:\n"
    printf "  $0 <polycorder auth key> [node id] | uninstall\n"
    printf "\n"
    printf "<polycorder auth key> : The polycorder auth key allows polytect to send detected events to Polycorder,\n"
    printf "                        the hosted analytics platform available in the Polyverse Account dashboard.\n"
    printf "[node id]             : An optional node identifier/discriminator which would allow analytics to\n"
    printf "                        differentiate this particular node's events.\n"
    printf "uninstall             : When used as the single argument, removes polytect from this system.\n"
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
            printf "No other methods for detection currently supported.\n"
            printf "\n"
            printf "If you believe you are running upstart, but this script is mistaken, please\n"
            printf "contact us at support@polyverse.com to bring it to our notice.\n"
            printf "\n"
            return 1
        ;;
    esac

    printf "Ensuring upstart job file directory ($upstart_job_dir) exists...\n"
    if [ ! -d "$upstart_job_dir" ]; then
        printf "The directory $upstart_job_dir is required to configure the polytect service.\n"
        printf "This script does not support any non-standard configurations and behaviors of upstart.\n"
        return 1
    fi

    return 0
}

download_latest_polytect() {

    #make sure local location exists
    if [ ! -d "$polytect_local_location" ]; then
        printf "$polytect_local_location does not exist. Creating it...\n"
        mkdir -p -m 755 $polytect_local_location
    fi

    printf "Downloading the latest $polytect_binary from $polytect_location, and saving into $polytect_local_location\n"
    type wget 2>&1 1>/dev/null
    if [ "$?" = "0" ]; then
        printf "Using wget to download polytect...\n"
        wget -q -O "$polytect_local_location/$polytect_binary" "$polytect_remote_location/$polytect_binary"
    else
        type curl 2>&1 1>/dev/null
        if [ "$?" = "0" ]; then
            printf "Using curl to download polytect...\n"
            curl -s -L -o "$polytect_local_location/$polytect_binary" "$polytect_remote_location/$polytect_binary"
        else
            printf "Neither curl nor wget found on the system. Unable to download polytect binary.\n"
            exit 1
        fi
    fi

    printf "Making polytect executable...\n"
    chmod 755 "$polytect_local_location/$polytect_binary"
}

create_polytect_conf() {
    authey="$1"
    nodeid="$2"

    printf "Creating polytect configuration file at $tomldir/$tomlfile\n"
    if [ ! -d "$tomldir" ]; then
        mkdir -p -m 755 "$tomldir"
    fi

    printf "Sending events to polycorder with authkey: $authkey\n"
    tomlcontents=$(printf "[auto_configure]")
    tomlcontents=$(printf "${tomlcontents}\nexception_trace = true")
    tomlcontents=$(printf "${tomlcontents}\nfatal_signals = true")
    tomlcontents=$(printf "${tomlcontents}\nklog_include_timestamp = true")
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

create_upstart_job_file() {
    ## Trailing newlines are removed: https://unix.stackexchange.com/questions/446992/when-printing-a-variable-that-contains-newlines-why-is-the-last-newline-strippe
    upstart_job=$(printf "${upstart_job}\ndescription \"The polyverse monitoring agent for monitoring zero-day attack attempts\"")
    upstart_job=$(printf "${upstart_job}\n ")
    upstart_job=$(printf "${upstart_job}\nrespawn")
    upstart_job=$(printf "${upstart_job}\nrespawn limit unlimited")
    upstart_job=$(printf "${upstart_job}\n ")
    upstart_job=$(printf "${upstart_job}\nstart on runlevel [2345]")
    upstart_job=$(printf "${upstart_job}\nstop on runlevel [016]")
    upstart_job=$(printf "${upstart_job}\n ")
    upstart_job=$(printf "${upstart_job}\nexec $polytect_local_location/$polytect_binary --configfile $tomldir/$tomlfile")
    upstart_job=$(printf "${upstart_job}\n ")

    printf "Writing $upstart_job_dir/$upstart_job_file file with contents:\n"
    printf "$upstart_job\n"

    printf "$upstart_job" > $upstart_job_dir/$upstart_job_file

    printf "Enable polytect monitor starting at bootup\n"
    initctl reload-configuration

    printf "Starting polytect now\n"
    initctl start polytect
}

uninstall() {
    if [ -f "$upstart_job_dir/$upstart_job_file" ]; then
        printf "Found polytect job file: $upstart_job_dir/$upstart_job_file. Removing it (after stopping service).\n"
        initctl stop polytect
        rm $upstart_job_dir/$upstart_job_file
        initctl reload-configuration
    fi

    if [ -f "$polytect_local_location/$polytect_binary" ]; then
        printf "Found polytect binary: $polytect_local_location/$polytect_binary. Removing it.\n"
        rm $polytect_local_location/$polytect_binary
    fi

    if [ -f "$tomldir/$tomlfile" ]; then
        printf "Found toml configuration file: $tomldir/$tomlfile. Removing it.\n"
        rm $tomldir/$tomlfile
        printf "Removing directory $tomldir\n"
        rmdir $tomldir
    fi
}

printf "Polytect installer for systemd\n"

# Ensuring we are root
if [ "$EUID" != "0" ] && [ "$USER" != "root" ]; then
   printf "This script must be run as root because it needs to reliably detect the init system,\n"
   printf "and be able to install the polytect service if systemd is found.\n"
   exit 1
fi

is_upstart
if [ "$?" != "0" ]; then
    printf "This script only works on systems inited by upstart (http://upstart.ubuntu.com).\n"
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


download_latest_polytect

create_polytect_conf "$authkey" "$nodeid"

create_upstart_job_file

pid=$(pgrep polytect)
if [ -z "$pid" ]; then
    printf "Polytect is not running in the background. Something went wrong.\n"
else
    printf "Polytect successfully installed and running in the background.\n"
fi
