#!/bin/bash
#This script is designed to monitor and log system RAM usage at regular intervals. It captures the total memory, free memory, and available memory on the system by reading the /proc/meminfo file. 
#The script runs in a loop for 20 minutes, recording memory statistics every 200 milliseconds. 
#Each reading is timestamped and appended to a log file located at /root/logs/ram_usage_log.txt. 
#The memory values are converted from kilobytes (kB) to megabytes (MB) for easier readability. 
#After the 20-minute duration, the script terminates, signaling the completion of the data collection process.
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
