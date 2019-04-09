#!/bin/bash
#
# Copyright (c) 2018 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

output=$(sudo xl list)
echo $output
if [ -n "$output" ]
then
	echo "$output"
else
	echo "command failed: xen is not installed"
	echo "installing xen..."
	interfaces=$(ip -o link show | grep -v LOOPBACK | awk -F': ' '{print $2}')
	echo $interfaces
	counter=0
	for interfaceName in $interfaces
	do
	    #echo $interfaceName
		if [ $counter -eq 0 ]
		then
			interface1=$interfaceName
			echo "interface1 $interface1"
		else
			interface2=$interfaceName
			echo "interface2 $interface2"
		fi
		counter=$((counter+1))
	done
	sudo apt-get install xen-hypervisor-amd64 -y
	sudo apt-get install bridge-utils -y
	sudo apt-get install ssh -y
	/bin/echo -e "auto lo $interface1 $interface2 xenbr0 \n">>~/network_conf_shell
	/bin/echo -e "iface lo inet loopback \n">>~/network_conf_shell
	/bin/echo -e "iface xenbr0 inet dhcp">>~/network_conf_shell
	/bin/echo -e "\tbridge_ports $interface1">>~/network_conf_shell
	/bin/echo -e "\tbridge_stp off">>~/network_conf_shell
	/bin/echo -e "\tbridge_fd 0">>~/network_conf_shell
	/bin/echo -e "\tbridge_maxwait 0 \n">>~/network_conf_shell
	/bin/echo -e "iface $interface1 inet manual \n">>~/network_conf_shell
	/bin/echo -e "iface $interface2 inet dhcp">>~/network_conf_shell
	sudo mv ~/network_conf_shell /etc/network/interfaces
	sudo ifdown $interface2 && sudo ifup $interface2
	while true; do
		read -p "Do you want to reboot (y/n)?" yn
		case $yn in
      			[Yy]* ) sudo reboot; break;;
      			[Nn]* ) exit;;
      			* )
    		esac
  	done
fi
