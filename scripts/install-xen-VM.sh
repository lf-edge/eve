#!/bin/bash
output=$(sudo xl list)
echo $output
if [ -n "$output" ]
then
	echo "$output"
else
	echo "command failed: xen is not installed"
	echo "installing xen..."
	sudo apt-get install xen-hypervisor-amd64 -y
	sudo apt-get install bridge-utils -y
	sudo apt-get install ssh -y
	echo -e "auto lo enp0s3 xenbr0 enp0s8 \n">>~/network_conf_shell
	echo -e "iface lo inet loopback \n">>~/network_conf_shell
	echo -e "iface xenbr0 inet dhcp">>~/network_conf_shell
	echo -e "\tbridge_ports enp0s3">>~/network_conf_shell
	echo -e "\tbridge_stp off">>~/network_conf_shell
	echo -e "\tbridge_fd 0">>~/network_conf_shell
	echo -e "\tbridge_maxwait 0 \n">>~/network_conf_shell
	echo -e "iface enp0s3 inet manual \n">>~/network_conf_shell
	echo -e "iface enp0s8 inet dhcp">>~/network_conf_shell
	sudo mv ~/network_conf_shell /etc/network/interfaces
	sudo ifdown enp0s8 && sudo ifup enp0s8
	sudo reboot
fi
