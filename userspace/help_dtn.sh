#!/bin/bash
# Author: Italo Valcy
# Modified: David Miranda

INTERVAL="0.010"  # update interval in seconds

if [ -z "$1" ]; then
	echo
	echo usage: $0 [network-interface]
	echo
	echo e.g. $0 eth0
	echo
	exit
fi

IF=$1

while true
do
	R1=`cat /sys/class/net/$IF/statistics/rx_bytes`
	sleep $INTERVAL
done
