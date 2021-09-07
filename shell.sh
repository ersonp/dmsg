#!/usr/bin/env bash

function helpFunction() {
    echo ""
    echo "Use: $0 -n (max 212)"
    echo "use -n for number of clients"
    exit 1 # Exit script after printing help
}

function makeConfigs() {
    n=$1

    if [ -z "$n" ]
    then
        echo "-n cannot be empty";
        helpFunction
    fi

    if [ $n -gt 212 ]
    then
        echo "-n cannot be more than 212";
        helpFunction
    fi
    
    while [ $n -gt 0 ]
    do 
        # Generate config
        ./bin/dmsgpty-host confgen config$n.json --cliaddr /tmp/dmsgpty$n.sock --dmsgdisc http://localhost:9090 --unsafe
        # increment the value
        n=`expr $n - 1`
    done
}

function startClients() {
    n=$1
    while [ $n -gt 0 ]
    do 
        # Start pty in xterm
        xterm -hold -title "App $n" -e "./bin/dmsgpty-host -c ./config$n.json"&
        n=`expr $n - 1`
    done
}

while getopts "n:" opt
do
    case "$opt" in
        n ) numb="$OPTARG" 
            makeConfigs $numb
            startClients $numb;;
        ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
    esac
done

if [[ $# -ne 3 ]]; then
  helpFunction
  exit 0
fi