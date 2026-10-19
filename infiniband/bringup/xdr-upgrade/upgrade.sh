#!/bin/bash
# Compatibility entry only: the fixed sibling Python entry owns orchestration.
set -euo pipefail
script_path=${BASH_SOURCE[0]}
case "$script_path" in
    */*) script_directory=${script_path%/*} ;;
    *) script_directory=. ;;
esac
script_directory=$(cd -- "$script_directory" && pwd)
exec python3 -B "$script_directory/upgrade.py" "$@"
