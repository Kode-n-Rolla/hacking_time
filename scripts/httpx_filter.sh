#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: ./httpx_filter.sh [file_to_filter] [dir_to_save]"
    exit 1
fi

if [[ -d "$dir_to_save" ]]; then
    echo "Directory $dir_to_save already exists. Choose another name or delete it."
    exit 1
fi


input_file=$1
dir_to_save=$2

mkdir $dir_to_save

while read -r line; do
    clean_line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')      # If httpx run with -nc (-no-color)
    code=$(echo "$clean_line" | awk '{print $2}' | tr -d '[]')  # Then use $line

    case "$code" in
        2??)
            echo "$clean_line" >> "$dir_to_save/200s.txt"
            ;;
        3??)
            echo "$clean_line" >> "$dir_to_save/300s.txt"
            ;;
        403)
            echo "$clean_line" >> "$dir_to_save/403.txt"
            ;;
        404)
            echo "$clean_line" >> "$dir_to_save/404.txt"
            ;;
        *)
            echo "$clean_line" >> "$dir_to_save/others.txt"
            ;;
    esac
done < $input_file

echo "Filtering is done!"
