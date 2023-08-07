#!/bin/bash
if [ -z "$1" ]
then
	echo "Adds Pin libraries to /etc/ld.so.conf.d/pin.conf"
	echo "Usage: sudo ./pinconfig.sh /path/to/pin/directory"
	echo ""
	echo "Eg.: sudo ./pinconfig.sh /home/username/pin-3.0-76991-gcc-linux"
else
	PIN_DIR="$1"
	PIN_CONF="/etc/ld.so.conf.d/pin.conf"
	echo "Adding Pin libraries to /etc/ld.so.conf.d/pin.conf"
	echo "$1/ia32/runtime/pincrt" > "$PIN_CONF"
	echo "$1/extras/xed-ia32/lib/" >> "$PIN_CONF"
	echo "$1/extras/xed-intel64/lib/" >> "$PIN_CONF"
	echo "$1/ia32/lib-ext/" >> "$PIN_CONF"
	echo "$1/intel64/lib-ext/" >> "$PIN_CONF"
	ldconfig
fi
