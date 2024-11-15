#!/bin/bash

PARAMS="+nocmd +nocomments +nostats"
DOMAIN="google.com"
ATipv6="@2001:4860:4860::8888"
{
if [ "$1" == "6" ]; then
  dig $PARAMS "$DOMAIN" -6 A $ATipv6
  dig $PARAMS "$DOMAIN" -6 AAAA $ATipv6
  dig $PARAMS "$DOMAIN" -6 NS $ATipv6
  dig $PARAMS "$DOMAIN" -6 MX $ATipv6
  dig $PARAMS "$DOMAIN" -6 SOA $ATipv6
  dig $PARAMS "$DOMAIN" -6 CNAME $ATipv6
  dig $PARAMS "_xmpp-server._tcp.google.com" -6 SRV $ATipv6
else
  dig $PARAMS "$DOMAIN" -4 A
  dig $PARAMS "$DOMAIN" -4 AAAA
  dig $PARAMS "$DOMAIN" -4 NS
  dig $PARAMS "$DOMAIN" -4 MX
  dig $PARAMS "$DOMAIN" -4 SOA
  dig $PARAMS "$DOMAIN" -4 CNAME
  dig $PARAMS "_http._tcp.mxtoolbox.com" -4 SRV
fi

} | sed 's/;//g' | sed 's/[[:space:]]\+/ /g' | uniq
