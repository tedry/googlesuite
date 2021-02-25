#!/bin/bash

script_directory=$(realpath $(dirname "${BASH_SOURCE}"))
build_directory=$(realpath "${script_directory}/..")

if [[ -z ${VIRTUAL_ENV} ]]; then
    source "/usr/local/company/venv/bin/activate"
fi
eval $("${build_directory}/bin/db_environment.py" --export)
export PREFIX="GSUITE"

set -e -x

mkdir -p "${script_directory}/data"
cd "${script_directory}/data"

export PREFIX="DB"
"${build_directory}/bin/db_load.py" --upsert --table vulnerability admin.out login.out drive.out groups.out mobile.out tokens.out
