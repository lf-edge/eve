#!/bin/sh

# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

set -x
set -e

# The paths here should correspond to the paths in the src/monitor/config.h
MEMORY_MONITOR_HANDLER_LOG_FILE="memory-monitor-handler.log"
EVENT_LOG_FILE="events.log"
PSI_FILE="psi.txt"

MAX_OUTPUT_SIZE_MB=100 # 100 MB
MAX_OUTPUT_SIZE_KB=$((MAX_OUTPUT_SIZE_MB * 1024))

tar_old_output() {
  # Tar directory with previous output to save space, but keep the latest output as is for easy access
  # It's necessary as one output directory takes around 15 Mb. In archive, it's compressed to 1-2 Mb.
  for dir in */; do
    if [ "$dir" != "$timestamp/" ]; then
      #Remove / from the end of the directory name
      tar_name=${dir%/}
      find "$dir" -type f -print0 | tar -czf "$tar_name.tar.gz" --files-from=-
      rm -rf "$dir"
    fi
  done
}

cleanup() {
  # Disable the script debug messages, so that the caller of the script can print the
  # last lines of the log file that most likely contain the error message
  set +x

  cd output
  tar_old_output
  # Clean up the temporary file
  rm "$sorted_eve_processes"
  rm "$sorted_pillar_processes"

  # Remove old archives, do not keep more than 100 MB of archives
  total_size=$(du -s | awk '{print $1}') # Size in KB
  # Subtract the size of the handler log file and convert it to KB
  total_size=$((total_size - $(stat -c %s "$MEMORY_MONITOR_HANDLER_LOG_FILE") / 1024))
  # Subtract the size of the psi.txt file (if it exists) as it size is regulated by the PSICollector
  if [ -f "$PSI_FILE" ]; then
    total_size=$((total_size - $(stat -c %s "$PSI_FILE") / 1024))
  fi
  while [ "$total_size" -gt "$MAX_OUTPUT_SIZE_KB" ]; do
    found_archives=$(find . -type f -name "*.tar.gz" -print | sort -n)
    if [ -z "$found_archives" ]; then
      break
    fi
    oldest_archive=$(echo "$found_archives" | head -n 1)
    rm "$oldest_archive"
    # Remove the first line from the events.log file: it contains the oldest event info
    sed -i '1d' "$EVENT_LOG_FILE"
    total_size=$(du -s | awk '{print $1}')
    total_size=$((total_size - $(stat -c %s "$MEMORY_MONITOR_HANDLER_LOG_FILE") / 1024))
  done
}

# Trap the cleanup function
trap cleanup EXIT

# Define the function to recursively process each cgroup
find_pids_of_cgroup() {
    path=$1
    tempfile=$2

    # Get the PIDs of the cgroup
    pids=$(cat "$path"/cgroup.procs)
    for pid in $pids; do
        echo "$pid" >> "$tempfile"
    done

    # Recurse into subdirectories
    for subdir in "$path"/*/; do
        if [ -d "$subdir" ]; then
            find_pids_of_cgroup "$subdir" "$tempfile"
        fi
    done
}

# Remove duplicates and sort the PIDs by RSS usage
normalize_pids() {
    processes_file=$1
    sorted_processes_file=$2
    sort -u "$processes_file" -o "$processes_file"
    while read -r pid; do
      # Check if the process still exists, skip if it does not
      if ! ps -p "$pid" -o pid=,rss= ; then
        continue
      fi
    done < "$processes_file" | sort -k2,2 -n -r | awk '{print $1}' > "$sorted_processes_file"
}

print_process_gone() {
  detailed=$1
  if [ "$detailed" -eq 1 ]; then
    echo "  process is gone during the handling, ignore it" >> "$output_file"
    echo "" >> "$output_file"
  fi
}

show_pid_mem_usage() {
  cgroup_name=$1
  processes_file=$2
  output_file=$3
  detailed=${4:-0}

  total_rss=0

  echo "Memory usage for the cgroup $cgroup_name" > "$output_file"
  echo "Started at: $(date +%T)" >> "$output_file"

  usage_in_bytes=$(cat /sys/fs/cgroup/memory/"$cgroup_name"/memory.usage_in_bytes)
  cache_in_bytes=$(grep 'total_cache' /sys/fs/cgroup/memory/"$cgroup_name"/memory.stat | awk '{print $2}')
  usage_in_KB=$((usage_in_bytes / 1024))
  cache_in_KB=$((cache_in_bytes / 1024))

  echo "Total usage according to cgroup: $usage_in_KB KB, cache: $cache_in_KB KB" >> "$output_file"
  echo "" >> "$output_file"

  while read -r pid; do
    # If the PID does not exist, skip
    if [ ! -d /proc/"$pid" ]; then
      # Process is gone
      continue
    fi
    if ! name=$(ps -p "$pid" -o cmd=) ; then
      # Process is gone. We have not yet printed any information about the process
      # so we can skip it without any explicit message in the output
      continue
    fi
    if [ "$detailed" -eq 1 ]; then
      echo "Process $name PID: $pid" >> "$output_file"
      # Since now we have printed the process header in the detailed view, hence
      # if the process is gone later, we should reflect that in the output
    fi
    # Get the memory usage according to ps
    if ! ps_rss=$(ps -p "$pid" -o rss= | tr -d ' ') ; then
      # Process is gone
      print_process_gone "$detailed"
      continue
    fi
    # Read the smaps file line by line
    rss_pid=0
    tmp_smaps=$(mktemp)
    if ! cat /proc/"$pid"/smaps > "$tmp_smaps" ; then
      # Process is gone
      rm "$tmp_smaps"
      print_process_gone "$detailed"
      continue
    fi
    while read -r line; do
      # Check for lines containing 'Pss:'
      # shellcheck disable=SC3010 # we use the busybox version of sh, which does support the [[ operator
      if [[ "$line" == Pss:* ]]; then
        rss=$(echo "$line" | awk '{print $2}')
        rss_pid=$((rss_pid + rss))
        # We assume the name is already obtained from the previous line
        # If the name is not available, use default value
        if [ -z "$current_name" ]; then
          current_name="some memory region"
        fi
        if [ "$detailed" -eq 1 ]; then
          echo "  $current_name: $rss KB" >> "$output_file"
        fi
      elif [[ "$line" =~ ^[0-9a-fA-F]+-[0-9a-fA-F]+ ]]; then
        current_name=$(echo "$line" | awk '{print $6}') # The name is the 6th field
      fi
    done < "$tmp_smaps"
    rm "$tmp_smaps"
    if [ -n "$rss_pid" ]; then
        echo "Total RSS for $name: $rss_pid KB, (according to ps: $ps_rss KB)" >> "$output_file"
        total_rss=$((total_rss + rss_pid))
        if [ "$detailed" -eq 1 ]; then
          echo "" >> "$output_file"
        fi
    fi
  done < "$processes_file"

  { echo "" ; echo "Total RSS according to smaps: $total_rss KB"; } >> "$output_file"

  echo "Finished at $(date +%T)" >> "$output_file"
}

# Start from the root of your target memory cgroup
cgroup_eve="/sys/fs/cgroup/memory/eve"
cgroup_pillar="/sys/fs/cgroup/memory/eve/services/pillar"

# Create a temporary file to hold all encountered PIDs
eve_processes=$(mktemp)
pillar_processes=$(mktemp)
sorted_eve_processes=$(mktemp)
sorted_pillar_processes=$(mktemp)

# Create the output directory if necessary
current_output_dir=$1
# Get the timestamp from the directory name (it's the last part of the path)
timestamp=$(basename "$current_output_dir")
mkdir -p "$current_output_dir"

# Process the cgroup and its subgroups
find_pids_of_cgroup "$cgroup_eve" "$eve_processes"
normalize_pids "$eve_processes" "$sorted_eve_processes"
rm "$eve_processes"

find_pids_of_cgroup "$cgroup_pillar" "$pillar_processes"
normalize_pids "$pillar_processes" "$sorted_pillar_processes"
rm "$pillar_processes"

# Trigger a heap dump
# TODO How to deal with the older eve versions that do not support the debug command?
eve http-debug

# ==== Handle the Pillar memory usage ====

show_pid_mem_usage "eve/services/pillar" "$sorted_pillar_processes" "$current_output_dir/memstat_pillar.out"

# ==== Handle the EVE memory usage ====

show_pid_mem_usage "eve" "$sorted_eve_processes" "$current_output_dir/memstat_eve.out" 1

# ==== Dump memory allocation sites for Pillar ====

eve dump-memory
logread | grep logMemAllocationSites > "$current_output_dir/allocations_pillar.out" || :

# ==== Trigger a heap dump for Pillar ====

curl --retry-all-errors --retry 5 -m 5 "http://127.1:6543/debug/pprof/heap?debug=1" > "$current_output_dir/heap_pillar.out"

eve http-debug stop

# ==== Create a symlink to the current zedbox ====

ln -s /containers/services/pillar/rootfs/opt/zededa/bin/zedbox "$current_output_dir/zedbox"

# cleanup function will be called here automatically
