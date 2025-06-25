#!/bin/bash

# Path to date command
dt="/usr/bin/date"

# Log file path
log_file="/tmp/ram_usage_log.txt"

# Get the current timestamp
start_time=$($dt +%s)

# Duration of the recording (20 minutes in seconds)
end_time=$((start_time + 1200))

# Loop until 20 minutes have passed
while [ $($dt +%s) -lt $end_time ]; do
    # Get the current timestamp for this reading
    timestamp=$($dt)

    # Read the total, free, and available memory from /proc/meminfo
    total_memory=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    free_memory=$(grep MemFree /proc/meminfo | awk '{print $2}')
    available_memory=$(grep MemAvailable /proc/meminfo | awk '{print $2}')

    # Convert values from kB to MB for easier readability
    total_memory_mb=$((total_memory / 1024))
    free_memory_mb=$((free_memory / 1024))
    available_memory_mb=$((available_memory / 1024))

    # Log the memory usage with the timestamp
    echo "$timestamp - Total Memory: ${total_memory_mb}MB, Free Memory: ${free_memory_mb}MB, Available Memory: ${available_memory_mb}MB" >> $log_file

    # Sleep for 200ms before the next reading
    sleep 0.2
done

echo "RAM usage recording completed."
