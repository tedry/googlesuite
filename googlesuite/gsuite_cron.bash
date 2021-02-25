#!/bin/bash

script_directory=$(realpath $(dirname "${BASH_SOURCE}"))
build_directory=$(realpath "${script_directory}/..")

set -e -x

mkdir -p "${script_directory}/data"
cd "${script_directory}/data"

flock --verbose --wait 10 "${script_directory}/data/cron_lock.txt" "${script_directory}/gsuite_query.bash"
"${script_directory}/gsuite_load.bash"

exit 0
