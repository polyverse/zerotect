#!/bin/sh
# Copyright (c) 2019 Polyverse Corporation

zerotect_binary="zerotect"
zerotect_remote_location="https://github.com/polyverse/zerotect/releases/latest/download"
zerotect_local_location="/usr/local/bin"

tomldir="/etc/zerotect"
tomlfile="zerotect.toml"

openrc_init_dir="/etc/init.d"
openrc_init_file="zerotect"

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

is_openrc() {
    printf "Checking whether this host was inited by OpenRC...\n"
    printf "Checking if /run/openrc/softlevel is exists and is readable (a reliable way)...\n"
    if [ -r /run/openrc/softlevel ]; then
        printf "It is OpenRC\n"
    else
        printf "Not inited by OpenRC (file /run/openrc/softlevel doesn't exist or is not readable)\n"
        printf "No other methods for detection currently supported.\n"
        printf "\n"
        printf "If you believe you are running OpenRC, but this script is mistaken, please\n"
        printf "contact us at support@polyverse.com to bring it to our notice.\n"
        printf "\n"
        return 1
    fi

    printf "Ensuring OpenRC init file directory ($openrc_init_dir) exists...\n"
    if [ ! -d "$openrc_init_dir" ]; then
        printf "The directory $openrc_init_dir is required to configure the zerotect service.\n"
        printf "This script does not support any non-standard configurations and behaviors of OpenRC.\n"
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
            curl -s -L -o "$zerotect_local_location/$zerotect_binary" "$zerotect_remote_location/$zerotect_binary"
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

create_openrc_init_file() {
    ## See: https://github.com/OpenRC/openrc/blob/master/service-script-guide.md
    ## Trailing newlines are removed: https://unix.stackexchange.com/questions/446992/when-printing-a-variable-that-contains-newlines-why-is-the-last-newline-strippe
    openrc_init=$(printf "#!/sbin/openrc-run")
    openrc_init=$(printf "${openrc_init}\n ")
    openrc_init=$(printf "${openrc_init}\ncommand=\"$zerotect_local_location/$zerotect_binary\"")
    openrc_init=$(printf "${openrc_init}\ncommand_args=\"--configfile=$tomldir/$tomlfile\"")
    # But what if the daemon isn't so well behaved? What if it doesn't know how to background
    # itself or create a pidfile? If it can do neither, then use,
    openrc_init=$(printf "${openrc_init}\ncommand_background=true")
    openrc_init=$(printf "${openrc_init}\npidfile=\"/run/$zerotect_binary.pid\"")
    openrc_init=$(printf "${openrc_init}\n ")
    # Depend on network being up
    openrc_init=$(printf "${openrc_init}\n ")
    openrc_init=$(printf "${openrc_init}\ndepend() {")
    openrc_init=$(printf "${openrc_init}\n    need net")
    openrc_init=$(printf "${openrc_init}\n}")
    openrc_init=$(printf "${openrc_init}\n ")

    printf "Writing $openrc_init_dir/$openrc_init_file file with contents:\n"
    printf "$openrc_init\n"

    printf "$openrc_init" > $openrc_init_dir/$openrc_init_file

    printf "Making zerotect init file executable\n"
    chmod a+x $openrc_init_dir/$openrc_init_file

    printf "Enable zerotect monitor starting at bootup\n"
    # Add to 'default' runlevel
    rc-update add zerotect default

    printf "Starting zerotect now\n"
    rc-service zerotect start
}

ensure_zerotect_running() {
    pid=$(pgrep zerotect)
    if [ -z "$pid" ]; then
        printf "zerotect is not running in the background. Something went wrong.\n"
        printf "Service status:\m"
        rc-service zerotect status
        exit 1
    else
        printf "zerotect successfully installed and running in the background.\n"
    fi
}

uninstall() {
    if [ -f "$openrc_init_dir/$openrc_init_file" ]; then
        printf "Found zerotect init file: $openrc_init_dir/$openrc_init_file. Removing it (after stopping service).\n"
        rc-service zerotect stop
        rc-update del zerotect default
        rm $openrc_init_dir/$openrc_init_file
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

printf "Zerotect installer for OpenRC\n"

# Ensuring we are root
if [ "$EUID" != "0" ] && [ "$USER" != "root" ]; then
   printf "This script must be run as root because it needs to reliably detect the init system,\n"
   printf "and be able to install the zerotect service if OpenRC is found.\n"
   exit 1
fi

is_openrc
if [ "$?" != "0" ]; then
    printf "This script only works on systems inited by OpenRC (https://wiki.gentoo.org/wiki/Project:OpenRC).\n"
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

create_openrc_init_file

ensure_zerotect_running
