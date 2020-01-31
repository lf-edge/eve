#!/bin/sh

./monitor-rsyslog.sh &

while true; do /usr/bin/logread -F -socket /run/memlogdq.sock | logger ; done
