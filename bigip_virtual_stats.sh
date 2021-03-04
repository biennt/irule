#!/bin/bash

virtuallist=`tmsh show ltm virtual | grep 'Ltm::Virtual Server:' | cut -d ':' -f 4`
for virtualname in $virtuallist; do
  statfile="/tmp/$virtualname"
  tmsh show ltm virtual $virtualname > $statfile
  cpuusage=`cat /tmp/vs_https | grep 'Last 5 Seconds' | tr -s ' ' | cut -d ' ' -f 3`
  echo "$virtualname - $cpuusage"
done
