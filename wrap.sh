#!/bin/bash

#First part checks to make sure we have a host or any variable given.  If not, help options are displayed.
if [ -z "$1" ]; then
    echo "[*] Nmap wrapper (outputs as -oN wrap_dir/wrapper_nmap by default)"
    echo "[*] Usage: $0 <target> [options]"
    echo "options:"
    echo "--help                          Show Brief Help"
    echo "-p [args], --port [args]        Select port range - EX: $0 127.0.0.1 -p 0-65535"
    echo "-f [args], --full [args]        All port scan (cannot be used with -f)"
    echo "--sweep                         Runs a ping sweep on a target, will ignore all other arguments."
    echo "-mon [args], --monitor [args]   TCPDump your nmap scan.  Must choose an interface - EX: $0 127.0.0.1 -mon eth0"
    echo "-c=[args], --custom=[args]      Additional custom commands - EX: $0 127.0.0.1 -f --custom='-oA filename -T5'"
    echo "--nverb [args]                  Sets Nmap verbosity level - EX: $0 127.0.0.1 -vv"
    echo "-v                              Set verbosity for debugging."
    echo "--version                       Check current version level."
    echo "--update                        Update mapwrap."
    exit 0
fi

#We set our functions up here
#Checks for updates
checkupdate () {
git=$(curl --silent https://github.com/waldo-irc/mapwrap/blob/master/wrap.sh | grep 'VERSION=' | cut -d">" -f2 | cut -d"<" -f1 | cut -d"=" -f 2)
if [ "$git" == "$VERSION" ]; then
     echo "[*] Current version is latest."
else
     echo "[****] Update Available"
     update="1"
fi
}
#this function simply runs NSE scripts against a target.  $1 is the target $2 is the ip $3 is what to grep for in the log.
nserun () {
if grep -i "$3" wrap_dir/wrapper_nmap --quiet; then
    echo "[*] Port $2 open, $2?"
    read -p "Run a full $1 NSE vuln scan? [y/N]" CONTINUE;
    if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
        for a in $(locate nmap/scripts/$1 | cut -d"/" -f6 | grep "vuln" | cut -d"." -f1 | sort -r); do
            nmap -p$2 -script $a "$HOST" --open > wrap_dir/$a.txt
            echo "[-] Running $a"
            wait
            if grep -q "VULNERABLE" wrap_dir/$a.txt; then
                echo "[!!] $HOST Seems Vulnerable to $a!"
            fi
        done
    fi
    read -p "Choose NSE scripts to run against $1? [y/N]" CONTINUE;
    if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
        locate nmap/scripts/$1 | cut -d"/" -f6 | cut -d"." -f1 | sort -r
        read -p "Choose NSE scripts to run.  Seperate each script with a space - EX: http-auth http-brute: "  SCRIPTS;
        read -p "Run with $SCRIPTS? [y/N]" CONTINUE;
        if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
            SCRIPTS=($SCRIPTS)
            for a in "${SCRIPTS[@]}"; do
                nmap -p$2 -script $a "$HOST" --open > wrap_dir/$a.txt
                echo "[-] Running $a"
                wait
                if grep -q "VULNERABLE" wrap_dir/$a.txt; then
                    echo "[!!] $HOST Seems Vulnerable to $a!"
                fi
            done
        fi
    fi
fi
}
#similar to above but doesnt only search for vuln nses (SSH for example has 3 nses but none are for vulns)
nseruntwo () {
if grep -i "$3" wrap_dir/wrapper_nmap --quiet; then
    echo "[*] Port $2 open, $2?"
    read -p "Run a full $1 NSE vuln scan? [y/N]" CONTINUE;
    if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
        for a in $(locate nmap/scripts/$1 | cut -d"/" -f6 | cut -d"." -f1 | sort -r); do
            nmap -p$2 -script $a "$HOST" --open > wrap_dir/$a.txt
            echo "[-] Running $a"
            wait
            if grep -q "VULNERABLE" wrap_dir/$a.txt; then
                echo "[!!] $HOST Seems Vulnerable to $a!"
            fi
        done
    fi
    read -p "Choose NSE scripts to run against $1? [y/N]" CONTINUE;
    if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
        locate nmap/scripts/$1 | cut -d"/" -f6 | cut -d"." -f1 | sort -r
        read -p "Choose NSE scripts to run.  Seperate each script with a space - EX: http-auth http-brute: "  SCRIPTS;
        read -p "Run with $SCRIPTS? [y/N]" CONTINUE;
        if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
            SCRIPTS=($SCRIPTS)
            for a in "${SCRIPTS[@]}"; do
                nmap -p$2 -script $a "$HOST" --open > wrap_dir/$a.txt
                echo "[-] Running $a"
                wait
                if grep -q "VULNERABLE" wrap_dir/$a.txt; then
                    echo "[!!] $HOST Seems Vulnerable to $a!"
                fi
            done
        fi
    fi
fi
}

#Check for a directory and create it if it doesn't exist (will store logs in here)
if [ -d wrap_dir ]; then
    :
else
    echo "[*] wrap_dir Directory Does Not Exist, creating it now."
    mkdir wrap_dir
fi

#Set some basic defaul settings/vars
ABSOLUTE_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
VERSION=1.0.1
HOST=$1
DEFAULTOUT="-oN wrap_dir/wrapper_nmap"
echo "" > wrap_dir/wrapper_packets

#Dependency check
INSTALLED=$(which nmap)
if [ -z "$INSTALLED" ]; then
    echo "[X] Install Nmap first buddy."
    cat << "EndOfMessage"

        ╭╯╭╯╭╯
    █▓▓▓▓▓█═╮
    █▓▓▓▓▓█▏︱
    █▓▓▓▓▓█═╯
    ◥█████◤

Here's some coffee to help you wake up.
EndOfMessage
    exit 0
fi

#Verbosity should be our first arg, this is done so it always runs first.
for arg in "$@"; do
    case $arg in
        -v)
        set -x
        ;;
        --version)
        echo "Current version of $0 is: $VERSION"
        exit 0
        ;;
        --update)
        echo "[*] $0 Version $VERSION"
        echo "[*] Updating $0"
        checkupdate
        echo "$git Git Version"
        echo "$VERSION Installed Version"
        if [ "$update" != "1" ]; then
            exit 0;
        else
            echo "[*] Needs an update!"
            read -p "[*] Update script? Y/n: " CONDITION;
            if [ "$CONDITION" == "Y" ] || [ "$CONDITION" == "y" ] || [ -z "$CONDITION" ]; then
                git clone https://github.com/waldo-irc/mapwrap.git
                echo "[*] Installing to $ABSOLUTE_PATH"
                mv mapwrap/wrap.sh $ABSOLUTE_PATH
                echo "[*] Cleaning up"
                wait
                rm -R mapwrap
                echo "[*] Installed Version updated to $git"
            else
                echo "[*] Exiting, not updating from $VERSION"
            fi
        fi
        exit 0
        ;;
    esac
done

#Alternative arguments without required attributes.
for arg in "$@"; do
    case $arg in
    --sweep)
        echo "Host to scan is $HOST."
        read -p "Continue? [y/N]" CONTINUE;
        if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
            nmap -sn $HOST
        else
            echo "Exiting..."
            exit 0
        fi
        exit 0
        ;;
        -f|--full) PORT="-p-"
        ;;
        -c=*|--custom=*)
        CUSTOM="${arg#*=}"
        ;;
        -h|--help)
        echo "[*] Nmap wrapper (outputs as -oN wrap_dir/wrapper_nmap by default)"
        echo "[*] Usage: $0 <target> [options]"
        echo "options:"
        echo "--help                          Show Brief Help"
        echo "-p [args], --port [args]        Select port range - EX: $0 127.0.0.1 -p 0-65535"
        echo "-f [args], --full [args]        All port scan (cannot be used with -f)"
        echo "--sweep                         Runs a ping sweep on a target, will ignore all other arguments."
        echo "-mon [args], --monitor [args]   TCPDump your nmap scan.  Must choose an interface - EX: $0 127.0.0.1 -mon eth0"
        echo "-c=[args], --custom=[args]      Additional custom commands - EX: $0 127.0.0.1 -f --custom='-oA filename -T5'"
        echo "--nverb [args]                  Sets Nmap verbosity level - EX: $0 127.0.0.1 -vv"
        echo "-v                              Set verbosity for debugging."
        echo "--version                       Check current version level."
        echo "--update                        Update mapwrap."
        exit 0
        ;;
    esac
done

#Checks to ensure we aren't re-using arguments
if [[ $CUSTOM == *"-p"* ]]; then
    echo "Can't use -p as a custom argument, already runs within the wrapper."
    exit 0
elif [[ $CUSTOM == *"--reason"* ]]; then
    echo "Can't use --reason as a custom argument, already runs within the wrapper."
    exit 0
elif [[ $CUSTOM == *"--open"* ]]; then
    echo "Can't use --open as a custom argument, already runs within the wrapper."
    exit 0
elif [[ $CUSTOM == *"-sS"* ]]; then
    echo "Can't use -sS as a custom argument, already runs within the wrapper."
    exit 0
elif [[ $CUSTOM == *"-nv"* ]]; then
    echo "Can't use -nv as a custom argument, already runs within the wrapper."
    exit 0
elif [[ $CUSTOM == *"-v"* ]]; then
    echo "Can't use -v as a custom argument, already runs within the wrapper."
    exit 0
fi

#Here we do a check to see if -oA is used, in which case we will drop our -oN.  In other cases such as -oX the -oN will remain for convenience.
if [[ $CUSTOM == *"-oA"*  ]]; then
    unset DEFAULTOUT
fi

#Regex check to insure IP is stored properly and it is an IP.
if ! [[ "$HOST" =~ ^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$ ]]; then
    echo "[X] Host '$HOST' is not a valid IP"
    exit 0
fi

#We start setting up final arguments here
while [[ $# -gt 1 ]]
do
key="$1"

case $key in
    -mon|--monitor)
    INTERFACE="$2"
    shift # past argument
    ;;
    --nverb)
    VERBOSITY="-n$2"
    if [ ${#VERBOSITY} -gt 5 ]; then
        echo "Up to 3 v's max for verbosity level."
        exit 0
    elif [ $2 == "v" ] || [ $2 == "vv" ] || [ $2 == "vvv" ]; then
        :
    else
        echo "v is for verbosity, not $2."
        exit 0
    fi
    shift # past argument
    ;;
    -p|--port)
    if [ "$PORT" == "-p-" ]; then
        echo "Already running full port scan, can't run with -p as well."
        exit 0
    fi
    PORT="$2"
    PORT="-p$PORT "
    shift # past argument
    ;;
    #Have to re-state these or itll throw errors for the help
    -f|--full|-h|--help|-c=*|--custom=*|-v|--sweep)
    :
    ;;
    -*)
    echo "[*] Nmap wrapper (outputs as -oN wrap_dir/wrapper_nmap by default)"
    echo "[*] Usage: $0 <target> [options]"
    echo "options:"
    echo "--help                          Show Brief Help"
    echo "-p [args], --port [args]        Select port range - EX: $0 127.0.0.1 -p 0-65535"
    echo "-f [args], --full [args]        All port scan (cannot be used with -f)"
    echo "--sweep                         Runs a ping sweep on a target, will ignore all other arguments."
    echo "-mon [args], --monitor [args]   TCPDump your nmap scan.  Must choose an interface - EX: $0 127.0.0.1 -mon eth0"
    echo "-c=[args], --custom=[args]      Additional custom commands - EX: $0 127.0.0.1 -f --custom='-oA filename -T5'"
    echo "--nverb [args]                  Sets Nmap verbosity level - EX: $0 127.0.0.1 -vv"
    echo "-v                              Set verbosity for debugging."
    echo "--version                       Check current version level."
    echo "--update                        Update mapwrap."
    exit 0
    #Everything else that isn't an argument, throw help and exit 0
    ;;
esac
shift # past argument or value
done

#Echoing our settings and asking for confirmation
echo "Running the NMap Wrapper with following settings:"
echo "Your custom commands are $CUSTOM"
echo "nmap ${PORT} ${HOST} --open --reason ${VERBOSITY} ${CUSTOM} ${DEFAULTOUT}"
read -p "Continue?: [y/N]" CONTINUE;
if [ "$CONTINUE" == "Y" ] || [ "$CONTINUE" == "y" ]; then
    if [ -z "$INTERFACE" ]; then
        STARTSECONDS=$(date +%s)
        nmap -sS $PORT "$HOST" --open --reason $VERBOSITY $CUSTOM $DEFAULTOUT
        ENDSECONDS=$(date +%s)
    else
        xterm -hold -e "tcpdump host $HOST -i $INTERFACE -XX | tee wrap_dir/wrapper_packets" &
        X="3"
        while [ "$X" -ge 1 ]; do
            echo "In $X seconds starting scan."
            sleep 1
            let X--
        done
        STARTSECONDS=$(date +%s)
        nmap -sS $PORT "$HOST" --open --reason $VERBOSITY $CUSTOM $DEFAULTOUT
        ENDSECONDS=$(date +%s)
    fi
else
    echo "Exiting...."
    exit 0
fi

#Finished output
echo ""
echo "[!!!!] Done running scan!"
echo "[!!!!] Check 'wrap_dir/wrapper_nmap' file for scan results."

#Additional output based on monitor argument
if [ -z "$INTERFACE" ]; then
    :
else
    Y=0
    while read line; do
        if [[ $line == *"length"* ]]; then
            let Y++;
        fi
    done < wrap_dir/wrapper_packets
    echo "[!!!!] Check 'wrap_dir/wrapper_packets' file for packets."
    echo "$Y Packets sent and read over TCPDump."
fi

#Output time it took to complete
echo "[%%] Scan was over a period of $(( $ENDSECONDS - $STARTSECONDS  )) second(s)"

#Grep interesting ports
if [ "$DEFAULTOUT" == "-oN wrap_dir/wrapper_nmap" ]; then
    echo ''
    echo "[!!] INTERESTING PORTS TO CHECK"
    nseruntwo ftp 21 21/tcp
    nseruntwo ssh 22 22/tcp
    nserun dns 53 53/tcp
    nserun http 80 80/tcp
    nserun nbt 139 139/tcp
    nserun smb 445 445/tcp
    nserun http 8080 8080/tcp
fi

#END
echo "[!!!!] Done, check 'wrap_dir' directory for NSE scan results."
