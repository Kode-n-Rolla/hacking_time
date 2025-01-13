while read line; do
    file=$(echo "$line" | awk '{print $NF}')
    timestamp=$(stat -c '%y' "$file" | cut -d'.' -f1)
    touch -d "$timestamp" "$file"
done < /tmp/log_timestamps.txt
