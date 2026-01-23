#!/bin/bash

WORKING_DIRECTORY=$(dirname $(realpath $0))
if [ $? -ne 0 ]; then
   WORKING_DIRECTORY=$(pwd)
fi

LOCK_FILE="${WORKING_DIRECTORY}/my_script.lck"
MAX_WAIT=5
RETRY_COUNT=1

(
   # Attempt to obtain lock, wait for a maximum of 5 seconds
   if flock -w $MAX_WAIT 9; then
      echo "[Info] Successfully obtained lock: $$ at $(date)"
      
      # Critical zone code
      echo "Entering the critical zone: $$ at $(date)"
      sleep 3
      echo "Leaving the critical zone: $$ at $(date)"
   else
      echo "After waiting for ${MAX_WAIT} seconds, the lock still cannot be obtained, exit: $$ at $(date)"
      exit 1
   fi
    
) 9>"$LOCK_FILE"