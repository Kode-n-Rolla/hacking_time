#!/bin/bash

for url in $(cat path/to/js_files.txt); do
	echo "[+] Scanning $url"
	secretfinder -i "$url" -e -o cli >> sf_result.txt
	sleep 1
done
