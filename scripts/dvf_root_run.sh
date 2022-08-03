SCRIPT_PATH="${BASH_SOURCE:-$0}"
ABS_DIRECTORY="$(dirname "${SCRIPT_PATH}")"

(${ABS_DIRECTORY}/../target/debug/dvf_root_node 35.88.15.244 9005 > boot_node_output 2>&1 &)

## TODO: The enr should be output to a config file (instead of console) so that others can read.
