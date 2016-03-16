#!/bin/env bash

############################################################################
# script to quickly copy VPN files into /etc/openvpn and enable systemd
# service; to avoid NetworkManager shortcoming w/autoconnect
#  and Gnome-keyring.
############################################################################

USAGE="Usage: `basename $0` <dirWithVPNconfFiles>"

if [[ -z $1 ]]
then
  echo $USAGE
fi

syswideconfig=/etc/openvpn
[ -d "$syswideconfig" ] || echo "Is openvpn installed on your system?"  # check vpn installed

exit

