SCRIPT_PATH="${BASH_SOURCE:-$0}"
ABS_DIRECTORY="$(dirname "${SCRIPT_PATH}")"

(${ABS_DIRECTORY}/../target/release/dvf validator_client \
    --debug-level info \
    --network ropsten \
    --ip 35.88.15.244 \
    --base-port 25000 \
    --boot-enr enr:-IS4QNyznRo6EasKc-YC_u7A_tJN3EmFM-GppAvaR33tanOSfNo0XZYh3vTyFtW_LhhKnI0i2kzeCSP8BBoZIwg0ihIBgmlkgnY0gmlwhCNYD_SJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCIy0 > dvf_output 2>&1 &)
