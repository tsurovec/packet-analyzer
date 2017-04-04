#!/bin/bash

LAST=0
inotifywait -m -e close_write,close -q . | while read -r directory events filename; do
    if [ "$filename" == "main.go" ]; then
	CURRENT=$(date +'%s')
	if [ $CURRENT -gt $((LAST + 2)) ]; then
	    clear
	    echo "$(date +'%H:%M:%S') Recompiling"
	    go build -o pa main.go && cat ssl-handshake-head50.txt | ./pa
	    #cargo build && cat ssl-handshake-head50.txt | cargo run
	    #	    gcc main.c -o pa.out && cat ssl-handshake.txt | ./pa.out
	    LAST=$CURRENT

#	else
	    #echo "$(date +'%H:%M:%S') No recompilation"
	fi
	   
	
	
    fi
done

