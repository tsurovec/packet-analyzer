#!/usr/bin/bash

LAST=0
inotifywait -m -e close_write,close -q src | while read -r directory events filename; do
    if [ "$filename" == "main.rs" ]; then
	CURRENT=$(date +'%s')
	if [ $CURRENT -gt $((LAST + 2)) ]; then
	    clear
	    echo "$(date +'%H:%M:%S') Recompiling"
#	    rustc main.rs && cat ssl-handshake-head30.txt | ./main
	    cargo build && cat ssl-handshake-head30.txt | cargo run
	    #	    gcc main.c -o pa.out && cat ssl-handshake.txt | ./pa.out
	    LAST=$CURRENT

#	else
	    #echo "$(date +'%H:%M:%S') No recompilation"
	fi
	   
	
	
    fi
done

