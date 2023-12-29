#!/bin/sh
while :; do echo $(date +%Y-%m-%dT%H:%M:%S) $(systemctl show --property=MemoryCurrent nginx); sleep 0.99; done
