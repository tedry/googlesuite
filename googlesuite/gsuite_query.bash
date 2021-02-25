#!/bin/bash

script_directory=$(realpath $(realpath "${BASH_SOURCE}"))
build_directory=$(realpath "${script_directory}/..")

if [[ -z ${VIRTUAL_ENV} ]]; then
    source "/usr/local/companys/venv/bin/activate"
fi
eval $("${build_directory}/bin/db_environment.py" --export)
export PREFIX="GSUITE"

set -e -x

mkdir -p "${script_directory}/data"
cd "${script_directory}/data"

"${script_directory}/g_suite_connector.py" --verbose

