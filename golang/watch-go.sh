#!/usr/bin/bash

LAST=0
inotifywait -m -e close_write,close -q . | while read -r directory events filename; do
    if [ "$filename" == "main.go" ]; then
	CURRENT=$(date +'%s')
	if [ $CURRENT -gt $((LAST + 2)) ]; then
	    clear
	    echo "$(date +'%H:%M:%S') Recompiling"
	    go build -o pa && cat ssl-handshake-head30.txt | ./pa
	    LAST=$CURRENT
	fi
    fi
done

