#!/bin/bash

# Function to display help message
show_help() {
  echo "Usage: $0 [options] <script-file>"
  echo ""
  echo "Options:"
  echo "  -m  Mount the home directory volume into the container."
  echo "  -h  Display this help message."
}

# Function to remove the Docker container
cleanup() {
  if [ -z "$CONTAINER" ]; then
    return
  fi
  echo "Removing the container..."
  docker rm -f "$CONTAINER"
  echo "Done."
}

# Register the cleanup function to be called on EXIT
trap cleanup EXIT

# Parse options
while getopts ":mh" opt; do
  case $opt in
    m)
      MOUNT_VOLUME=true
      ;;
    h)
      show_help
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      show_help
      exit 1
      ;;
  esac
done

# Remove options from positional parameters
shift $((OPTIND-1))

# Source .env file for environment variables
source .env

# Check for required environment variables
if [ -z "$SERVER" ] || [ -z "$USER" ] || [ -z "$TOKEN" ]; then
  echo "Set the SERVER, USER, and TOKEN variables in the .env file."
  exit 1
fi

# Check for script file argument
if [ $# -lt 1 ]; then
  echo "Usage: $0 [-m] <script-file> [script-args...]"
  exit 1
fi
SCRIPT_FILE=$1

# Capture the remaining positional arguments
shift  # Remove the script file name from the positional parameters
SCRIPT_ARGS="$@"

# Check if the script file exists
if [ ! -f "$SCRIPT_FILE" ]; then
  echo "The script file $SCRIPT_FILE does not exist."
  exit 1
fi

IMAGE="zededa/zcli-dev:latest"

echo "Creating and running a new container..."
# The command is inspired by runzcli.sh from the zcli repo)
TZ=$(readlink /etc/localtime | sed 's,/var/db/timezone/zoneinfo/,,')
VOLUME_OPTION=""
if [ "$MOUNT_VOLUME" = "true" ]; then
  VOLUME_OPTION="-v ${HOME}:/home/zcli"
fi
CONTAINER=$(docker run -id --network="host" $VOLUME_OPTION -e TZ="$TZ" "$IMAGE")

# Wait for the container to be running
while [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != "true" ]; do
  if [ "$(docker inspect -f '{{.State.Status}}' "$CONTAINER")" == "exited" ]; then
    echo "The container exited."
    exit 1
  fi
  echo "Waiting for container to start..."
  sleep 1
done

# Configure zcli and login
D="docker exec $CONTAINER"
$D zcli configure -T "$TOKEN" --user="$USER" --server="$SERVER" --output=json
$D zcli login

# Read the entire script into a variable
SCRIPT_CONTENT=$(<"$SCRIPT_FILE")

# Replace all occurrences of 'zcli' with '$D zcli'
MODIFIED_SCRIPT=$(echo "$SCRIPT_CONTENT" | sed "s/\bzcli /$D zcli /g")

# Create a temporary file to hold the modified script
TEMP_SCRIPT=$(mktemp)

# Write the modified script to the temporary file
echo "$MODIFIED_SCRIPT" > "$TEMP_SCRIPT"

# Set the positional parameters to SCRIPT_ARGS
set -- $SCRIPT_ARGS

# Source the temporary script to execute it in the current shell context
source "$TEMP_SCRIPT"

# Remove the temporary file
rm -f "$TEMP_SCRIPT"
