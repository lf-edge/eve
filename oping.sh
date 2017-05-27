#!/bin/bash
# Wrapper around ping6 which sets the source address to be our eid
LISPDIR=/usr/local/bin/lisp
eid=`grep "eid-prefix = fd" $LISPDIR/lisp.config | awk '{print $3}' | awk -F/ '{print $1}'`
echo ping6 -s $eid $@
ping6 -s $eid $@
