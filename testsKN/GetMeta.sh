#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <file.pcap>"
  exit 1
fi

tshark -r "$1" -Y "dns" -T fields \
    -e frame.time_epoch \
    -e ipv6.src \
    -e ip.src \
    -e ipv6.dst \
    -e ip.dst \
    -e ip.version \
    -e udp.srcport \
    -e udp.dstport \
    -e dns.id \
    -e dns.flags.response \
    -e dns.flags.opcode \
    -e dns.flags.authoritative \
    -e dns.flags.truncated \
    -e dns.flags.recdesired \
    -e dns.flags.recavail \
    -e dns.flags.authenticated \
    -e dns.flags.checkdisable \
    -e dns.flags.rcode \
    -e dns.count.queries \
    -e dns.count.answers \
    -e dns.count.auth_rr \
    -e dns.count.add_rr \
    -E separator='|' | while IFS= read -r line; do
  line=$(echo "$line" | sed 's/True/1/g' | sed 's/False/0/g' | sed 's/||/|0|/g' | sed 's/|$/|0/' | sed 's/||/|0|/g')
  IFS='|' read -ra arr <<< "$line"

  if [ "$2" == "-v" ]; then
    echo "Timestamp: $(date -d @"${arr[0]}" '+%Y-%m-%d %H:%M:%S')"
    if [ "${arr[5]}" == "6" ]; then
      echo "SrcIP: ${arr[1]}"
      echo "DstIP: ${arr[3]}"
    elif [ "${arr[5]}" == "4" ]; then
      echo "SrcIP: ${arr[2]}"
      echo "DstIP: ${arr[4]}"
    fi
    echo "SrcPort: UDP/${arr[6]}"
    echo "DstPort: UDP/${arr[7]}"
    echo "Identifier: 0x$(echo "${arr[8]}" | sed 's/^0x0*//' | tr 'a-f' 'A-F')"
    echo "Flags: QR=${arr[9]}, OPCODE=${arr[10]}, AA=${arr[11]}, TC=${arr[12]}, RD=${arr[13]}, RA=${arr[14]}, AD=${arr[15]}, CD=${arr[16]}, RCODE=${arr[17]}"
  else
    if [ "${arr[5]}" == "6" ]; then
      echo "$(date -d @"${arr[0]}" '+%Y-%m-%d %H:%M:%S') ${arr[1]} -> ${arr[3]} ($( [ "${arr[9]}" -eq 0 ] && echo "Q" || echo "R" ) ${arr[18]}/${arr[19]}/${arr[20]}/${arr[21]})"
    elif [ "${arr[5]}" == "4" ]; then
      echo "$(date -d @"${arr[0]}" '+%Y-%m-%d %H:%M:%S') ${arr[2]} -> ${arr[4]} ($( [ "${arr[9]}" -eq 0 ] && echo "Q" || echo "R" ) ${arr[18]}/${arr[19]}/${arr[20]}/${arr[21]})"
    fi
  fi
done
