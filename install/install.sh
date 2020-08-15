#!/bin/sh
# Copyright (c) 2020 Polyverse Corporation


# *******************************************************************************************************************
# Init-system agonistic functions and variables
# *******************************************************************************************************************

default_log_file="/var/log/zerotect.toml"

zerotect_binary="zerotect"
zerotect_remote_location="https://github.com/polyverse/zerotect/releases/latest/download"
zerotect_local_location="/usr/local/bin"

tomldir="/etc/zerotect"
tomlfile="zerotect.toml"

ensure_root() {

    # Ensuring we are root
    if [ "$EUID" = "0" ]; then
        # try the EUID method
        return 0
    elif [ "$EUID" = "" ] && [ "$(id -u)" = "0" ]; then
        # Sometimes EUID is not 0 (and not set), then use the older method
        return 0
    fi

    return 1
}

download_latest_zerotect() {

    #make sure local location exists
    if [ ! -d "$zerotect_local_location" ]; then
        printf " |--> $zerotect_local_location does not exist. Creating it...\n"
        mkdir -p -m 755 $zerotect_local_location
    fi

    printf " |--> Downloading the latest $zerotect_binary from $zerotect_remote_location, and saving into $zerotect_local_location\n"
    type wget 2>/dev/null 1>/dev/null
    if [ "$?" = "0" ]; then
        printf "   |--> Using wget to download zerotect...\n"
        wget -q -O "$zerotect_local_location/$zerotect_binary" "$zerotect_remote_location/$zerotect_binary"
    else
        type curl 2>/dev/null 1>/dev/null
        if [ "$?" = "0" ]; then
            printf "   |--> Using curl to download zerotect...\n"
            curl -s -L -o "$zerotect_local_location/$zerotect_binary" "$zerotect_remote_location/$zerotect_binary"
        else
            printf "   |--> Neither curl nor wget found on the system. Unable to download zerotect binary.\n"
            exit 1
        fi
    fi

    printf " |--> Making zerotect executable...\n"
    chmod 755 "$zerotect_local_location/$zerotect_binary"
}

create_zerotect_conf() {

    POLYCORDER_AUTH_KEY="$1"
    POLYCORDER_NODE_ID="$2"
    LOG_FILE_PATH="$3"
    SYSLOG_DEFAULT="$4"

    printf " |--> Creating zerotect configuration\n"
    if [ ! -d "$tomldir" ]; then
        mkdir -p -m 755 "$tomldir"
    fi

        if [ "$POLYCORDER_AUTH_KEY" = "" ] && [ "$LOG_FILE_PATH" = "" ] && [ "$SYSLOG_DEFAULT" = "" ]; then
        LOG_FILE_PATH="$default_log_file"
        printf "   |--> NOTE: No parameters provided, so defaulting to a log file at: $LOG_FILE_PATH\n"
    fi

    tomlcontents=$(printf "[auto_configure]")
    tomlcontents=$(printf "${tomlcontents}\nexception_trace = true")
    tomlcontents=$(printf "${tomlcontents}\nfatal_signals = true")
    tomlcontents=$(printf "${tomlcontents}\nklog_include_timestamp = true")
    tomlcontents=$(printf "${tomlcontents}\n ")
    tomlcontents=$(printf "${tomlcontents}\n[monitor]")
    tomlcontents=$(printf "${tomlcontents}\ngobble_old_events = false")
    tomlcontents=$(printf "${tomlcontents}\n ")

    if [ "$POLYCORDER_AUTH_KEY" != "" ]; then
        printf "   |--> Sending events to polycorder with authkey: $POLYCORDER_AUTH_KEY\n"
        tomlcontents=$(printf "${tomlcontents}\n[polycorder]")
        tomlcontents=$(printf "${tomlcontents}\nauth_key = '$POLYCORDER_AUTH_KEY'")
        if [ "$POLYCORDER_NODE_ID" != "" ]; then
            printf "   |--> Assigning polycorder events to nodeid: $POLYCORDER_NODE_ID\n"
            tomlcontents=$(printf "${tomlcontents}\nnode_id = '$POLYCORDER_NODE_ID'")
        fi
    fi

    if [ "$SYSLOG_DEFAULT" != "" ]; then
        printf "   |--> Sending events to syslog (in JSON format)\n"
        tomlcontents=$(printf "${tomlcontents}\n[syslog]")
        tomlcontents=$(printf "${tomlcontents}\ndestination = 'default'")
        tomlcontents=$(printf "${tomlcontents}\nformat = 'JSON'")
    fi

    if [ "$LOG_FILE_PATH" != "" ]; then
        printf "   |--> Sending events to log file (in JSON format)\n"
        tomlcontents=$(printf "${tomlcontents}\n[logfile]")
        tomlcontents=$(printf "${tomlcontents}\nfilepath = '/var/log/zerotect.log'")
        tomlcontents=$(printf "${tomlcontents}\nformat = 'JSON'")
    fi

    tomlcontents=$(printf "${tomlcontents}\n ")

    #printf "Final configuration file contents are:\n$tomlcontents\n"
    printf "$tomlcontents" > $tomldir/$tomlfile
    chmod 644 $tomldir/$tomlfile
    printf "   |--> Written configuration file to $tomldir/$tomlfile\n"
}

ensure_zerotect_running() {
    expected="$1"
    init_status="$2"

    pid=$(pgrep zerotect)
    if [ -z "$pid" ]; then
        printf " |--> zerotect is not running in the background.\n"
    else
        printf " |--> zerotect is running in the background.\n"
    fi

    if ([ -z "$pid" ] && [ "$expected" = "yes" ]) || ([ ! -z "$pid" ] && [ "$expected" = "no" ]); then
        printf "That was unexpected. Service status:\n"
        $init_status
        exit 1
    fi
}

# *******************************************************************************************************************
# Upstart-specific functions and variables
# *******************************************************************************************************************

upstart_job_dir="/etc/init"
upstart_job_file="zerotect.conf"

is_upstart() {
    printf " |--> looking for upstart... "
    initver=$(/sbin/init --version 2>&1)
    case "$initver" in
        *upstart*)
            printf "found.\n"
        ;;
        *)
            printf "not found.\n"
            return 1
        ;;
    esac

    printf "   |--> Ensuring ($upstart_job_dir) exists..."
    if [ -d "$upstart_job_dir" ]; then
        printf "yes.\n"
    else
        printf "no.\n"
        printf "        The directory $upstart_job_dir is required to configure the zerotect service.\n"
        printf "        This script does not support any non-standard configurations and behaviors of upstart.\n"
        return 2
    fi

    return 0
}


upstart_create_job_file() {
    ## Trailing newlines are removed: https://unix.stackexchange.com/questions/446992/when-printing-a-variable-that-contains-newlines-why-is-the-last-newline-strippe
    upstart_job=$(printf "${upstart_job}\ndescription \"The polyverse monitoring agent for monitoring zero-day attack attempts\"")
    upstart_job=$(printf "${upstart_job}\n ")
    upstart_job=$(printf "${upstart_job}\nrespawn")
    upstart_job=$(printf "${upstart_job}\nrespawn limit unlimited")
    upstart_job=$(printf "${upstart_job}\n ")
    upstart_job=$(printf "${upstart_job}\nstart on runlevel [2345]")
    upstart_job=$(printf "${upstart_job}\nstop on runlevel [016]")
    upstart_job=$(printf "${upstart_job}\n ")
    upstart_job=$(printf "${upstart_job}\nexec $zerotect_local_location/$zerotect_binary --configfile $tomldir/$tomlfile")
    upstart_job=$(printf "${upstart_job}\n ")

    printf " |--> Writing $upstart_job_dir/$upstart_job_file file.\n"
    printf "$upstart_job" > $upstart_job_dir/$upstart_job_file

    printf " |--> Ensuring zerotect starts at system start\n"
    initctl reload-configuration

    printf " |--> Starting zerotect now\n"
    initctl start zerotect
}

upstart_status() {
    initctl status zerotect
}

upstart_uninstall() {
    if [ -f "$upstart_job_dir/$upstart_job_file" ]; then
        printf " |--> Found zerotect job file: $upstart_job_dir/$upstart_job_file. Removing it (after stopping service).\n"
        initctl stop zerotect
        rm $upstart_job_dir/$upstart_job_file
        initctl reload-configuration
    fi

    if [ -f "$zerotect_local_location/$zerotect_binary" ]; then
        printf " |--> Found zerotect binary: $zerotect_local_location/$zerotect_binary. Removing it.\n"
        rm $zerotect_local_location/$zerotect_binary
    fi

    if [ -f "$tomldir/$tomlfile" ]; then
        printf " |--> Found toml configuration file: $tomldir/$tomlfile. Removing it.\n"
        rm $tomldir/$tomlfile
        printf "   |--> Removing directory $tomldir\n"
        rmdir $tomldir
    fi
}

# *******************************************************************************************************************
# Systemd-specific functions and variables
# *******************************************************************************************************************

systemd_unit_dir="/etc/systemd/system"
systemd_unit_file="zerotect.service"

is_systemd() {
    printf " |--> looking for systemd... "
    proc1=$(cat /proc/1/comm)
    if [ "$proc1" = "systemd" ]; then
        printf "found.\n"
    else
        printf "not found.\n"
        return 1
    fi

    printf "   |--> Ensuring ($systemd_unit_dir) exists..."
    if [ -d "$systemd_unit_dir" ]; then
        printf "yes.\n"
    else
        printf "no.\n"
        printf "        The directory $systemd_unit_dir is required to configure the zerotect service.\n"
        printf "        This script does not support any non-standard configurations and behaviors of systemd.\n"
        return 2
    fi
    return 0
}


systemd_create_unit_file() {
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

    printf " |--> Writing $systemd_unit_dir/$systemd_unit_file file.\n"
    printf "$systemd_unit" > $systemd_unit_dir/$systemd_unit_file

    printf " |--> Ensuring zerotect starts at system start\n"
    systemctl enable zerotect

    printf " |--> Starting zerotect now\n"
    systemctl start zerotect
}

systemd_status() {
    systemctl status zerotect
}

systemd_uninstall() {
    if [ -f "$systemd_unit_dir/$systemd_unit_file" ]; then
        printf " |--> Found zerotect service unit: $systemd_unit_dir/$systemd_unit_file. Removing it (after stopping service).\n"
        systemctl stop zerotect
        systemctl disable zerotect
        rm $systemd_unit_dir/$systemd_unit_file
    fi

    if [ -f "$zerotect_local_location/$zerotect_binary" ]; then
        printf " |--> Found zerotect binary: $zerotect_local_location/$zerotect_binary. Removing it.\n"
        rm $zerotect_local_location/$zerotect_binary
    fi

    if [ -f "$tomldir/$tomlfile" ]; then
        printf " |--> Found toml configuration file: $tomldir/$tomlfile. Removing it.\n"
        rm $tomldir/$tomlfile
        printf "   |--> Removing directory $tomldir\n"
        rmdir $tomldir
    fi
}

# *******************************************************************************************************************
# OpenRC-specific functions and variables
# *******************************************************************************************************************

openrc_init_dir="/etc/init.d"
openrc_init_file="zerotect"

is_openrc() {
    printf " |--> looking for OpenRC... "
    proc1=$(cat /proc/1/comm)
    if [ -r /run/openrc/softlevel ]; then
        printf "found.\n"
    else
        printf "not found.\n"
        return 1
    fi

    printf "   |--> Ensuring ($openrc_init_dir) exists..."
    if [ -d "$openrc_init_dir" ]; then
        printf "yes.\n"
    else
        printf "no.\n"
        printf "        The directory $openrc_init_dir is required to configure the zerotect service.\n"
        printf "        This script does not support any non-standard configurations and behaviors of OpenRC.\n"
        return 2
    fi
    return 0
}

openrc_create_init_file() {
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

    printf " |--> Writing $openrc_init_dir/$openrc_init_file file.\n"
    printf "$openrc_init" > $openrc_init_dir/$openrc_init_file

    printf " |--> Making zerotect init file executable (required for OpenRC)\n"
    chmod a+x $openrc_init_dir/$openrc_init_file

    printf " |--> Ensuring zerotect starts at system start\n"
    # Add to 'default' runlevel
    rc-update add zerotect default

    printf " |--> Starting zerotect now\n"
    rc-service zerotect start
}

openrc_status() {
    rc-service zerotect status
}

openrc_uninstall() {
    if [ -f "$openrc_init_dir/$openrc_init_file" ]; then
        printf " |--> Found zerotect init file: $openrc_init_dir/$openrc_init_file. Removing it (after stopping service).\n"
        rc-service zerotect stop
        rc-update del zerotect default
        rm $openrc_init_dir/$openrc_init_file
    fi

    if [ -f "$zerotect_local_location/$zerotect_binary" ]; then
        printf " |--> Found zerotect binary: $zerotect_local_location/$zerotect_binary. Removing it.\n"
        rm $zerotect_local_location/$zerotect_binary
    fi

    if [ -f "$tomldir/$tomlfile" ]; then
        printf " |--> Found toml configuration file: $tomldir/$tomlfile. Removing it.\n"
        rm $tomldir/$tomlfile
        printf "   |--> Removing directory $tomldir\n"
        rmdir $tomldir
    fi
}



# *******************************************************************************************************************
# Usage
# *******************************************************************************************************************

print_usage() {
    printf "\n"
    printf "Usage:\n"
    printf "  $0 [arguments]\n"
    printf "\n"
    printf " -p|--polycorder <polycorder auth key> : The polycorder auth key allows zerotect to send detected events to Polycorder,\n"
    printf "                                        the hosted analytics platform available in the Polyverse Account dashboard.\n"
    printf " -n|--polycorder-node-id <node id>     : An optional node identifier/discriminator which would allow analytics to\n"
    printf "                                        differentiate this particular node's events. (requires polycorder auth key.)\n"
    printf " -l|--log-file <path>                  : Writes zerotect logs to file provided at path.\n"
    printf " -s|--syslog                           : Sends zerotect logs to syslog at standard Unix sockets, i.e. /dev/log and\n"
    printf "                                        /var/run/syslog in that order, TCP port (601) or UDP port (514).\n"
    printf " --uninstall                           : Removes zerotect from this system.\n"
    printf "\n NOTE: If no arguments are provided, '--log-file /var/log/zerotect.log' is assumed.\n"
}

# *******************************************************************************************************************
# Not functions... this is main execution thread...
# *******************************************************************************************************************

printf "\n"

# parse arguments....
# copied from: https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p|--polycorder)
      POLYCORDER_AUTH_KEY=$2
      shift 2
      ;;
    -n|--polycorder-node-id)
      POLYCORDER_NODE_ID=$2
      shift 2
      ;;
    -l|--log-file)
      LOG_FILE_PATH=$2
      shift 2
      ;;
    -s|--syslog)
      SYSLOG_DEFAULT=true
      shift
      ;;
    -h|--help)
      printf "\n"
      printf "Configures and installs Zerotect as a daemon on this host based on the init system running on it. This script does not\n"
      printf "provide all possible configuration options, and instead provides a smooth, opinionated set of defaults. To configure\n"
      printf "zerotect with a finer granularity, you may either modify the file located at: $tomldir/$tomlfile,\n"
      printf "or download and run the zerotect executable manually.\n"
      print_usage
      exit 1
      shift
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    -*|--*=) # unsupported flags
      printf "Error: Unsupported flag $1\n" >&2
      print_usage
      exit 1
      ;;
    *) # preserve positional arguments
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done # set positional arguments in their proper place
eval set -- "$PARAMS"

printf "\n"
printf "Zerotect installer\n\n"
printf "==> Step 1/6:  Ensuring we're running as root..."
# ensure we're running as root
ensure_root
if [ "$?" = "0" ]; then
    printf "yes.\n"
else
    printf "no.\n"
    printf "      This script must be run as root because it needs to reliably detect the init system,\n"
    printf "      and be able to install the zerotect service using the appropriate install script.\n"
    exit 1
fi

printf "==> Step 2/6:  Detecting Init System...\n"

# Set the helper functions based on which init system we detect
is_systemd
if [ "$?" = "0" ]; then
    create_init_file="systemd_create_unit_file"
    init_status="systemd_status"
    uninstall="systemd_uninstall"
else
    is_openrc
    if [ "$?" = "0" ]; then
        create_init_file="openrc_create_init_file"
        init_status="openrc_status"
        uninstall="openrc_uninstall"
    else
        is_upstart
        if [ "$?" = "0" ]; then
            create_init_file="upstart_create_job_file"
            init_status="upstart_status"
            uninstall="upstart_uninstall"
        else
            printf " |--> No more init systems supported. Zerotect does not have a recipe for your system.\n"
            exit 0
        fi
    fi
fi

if [ "$UNINSTALL" != "" ]; then
    printf "==> Step 4/6: No step for when uninstalling.\n"
    printf "==> Step 5/6: Uninstalling zerotect...\n"
    $uninstall
    printf "==> Step 6/6: Ensure zerotect is not running...\n"
    ensure_zerotect_running "no" $init_status
else
    printf "==> Step 3/6: Downloading zerotect binary...\n"
    download_latest_zerotect

    printf "==> Step 4/6: Creating zerotect configuration file...\n"
    create_zerotect_conf "$POLYCORDER_AUTH_KEY" "$POLYCORDER_NODE_ID" "$LOG_FILE_PATH" "$SYSLOG_DEFAULT"

    printf "==> Step 5/6: Adding zerotect to init system...\n"
    $create_init_file

    printf "==> Step 6/6: Ensure zerotect is running...\n"
    ensure_zerotect_running "yes" $init_status
fi
