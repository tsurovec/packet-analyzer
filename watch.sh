#!/usr/bin/bash

LAST=0
inotifywait -m -e close_write,close -q . | while read -r directory events filename; do
    if [ "$filename" == "main.c" ]; then
	CURRENT=$(date +'%s')
	if [ $CURRENT -gt $((LAST + 2)) ]; then
	    echo "$(date +'%H:%M:%S') Recompiling"
	    gcc main.c -o pa.out && cat ssl-handshake.txt | ./pa.out
	    LAST=$CURRENT

#	else
	    #echo "$(date +'%H:%M:%S') No recompilation"
	fi
	   
	
	
    fi
done

