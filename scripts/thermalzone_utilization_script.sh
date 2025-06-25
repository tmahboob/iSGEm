#!/bin/bash

# Path to date command
dt="/usr/bin/date"

# Log file path
log_file="/tmp/cpu_temp_log.txt"

# Get the current timestamp
start_time=$($dt +%s)

# Duration of the recording (20 minutes in seconds)
end_time=$((start_time + 1200))

# Loop until 20 minutes have passed
while [ $($dt +%s) -lt $end_time ]; do
    # Get the current timestamp for this reading
    timestamp=$($dt)

    # Directory where temperatures are stored
    thermal_dir="/sys/class/thermal"

    # Loop through each thermal zone (CPU temperature sensors)
    for thermal_zone in $(ls $thermal_dir); do
        # Check if the thermal_zone contains a temp file
        if [ -f "$thermal_dir/$thermal_zone/temp" ]; then
            # Read the temperature (in millidegrees)
            temp=$(cat "$thermal_dir/$thermal_zone/temp")

            # Convert to Celsius (millidegrees / 1000)
            temp_celsius=$((temp / 1000))

            # Log the temperature with the timestamp
            echo "$timestamp - $thermal_zone - Temperature: $temp_celsius°C" >> $log_file
        fi
    done

    # Sleep for 200ms before the next reading
    sleep 0.2
done

echo "Temperature recording completed."
