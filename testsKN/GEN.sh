#!/bin/bash

if [ "$4" == "6" ]; then
  DEVICE="tun0"
  IP=6
else
  DEVICE="enx94bdbe1d7d5c"
  IP=4
fi

sudo resolvectl flush-caches
tcpdump -c 14 -i "$DEVICE" -w "$1" 'port 53' &
echo "Capturing DNS packets..."
bash "$2" "$IP" > "$3"
sleep 3