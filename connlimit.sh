#!/bin/bash
maxcon=500
tmsh show sys connection cs-server-addr 10.32.72.158 cs-server-port 443 | cut -d':' -f1 > /tmp/connlimit.txt
sort -u /tmp/connlimit.txt > /tmp/sorted_connlimit.txt
list=`cat /tmp/sorted_connlimit.txt`
for item in $list; do
 totalcon=`grep $item /tmp/connlimit.txt | wc -l`
 if [ $totalcon -gt $maxcon ]; then
  echo "$item $totalcon" 
  tmsh delete sys connection cs-client-addr $item
 fi
done
