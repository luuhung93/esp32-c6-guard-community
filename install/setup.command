#!/bin/sh
cd -- "$(dirname -- "$0")" || exit 1
python3 setup.py "$@"
status=$?
printf "Press Enter to close..."
read -r reply
exit "$status"
