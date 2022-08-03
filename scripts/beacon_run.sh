SCRIPT_PATH="${BASH_SOURCE:-$0}"
ABS_DIRECTORY="$(dirname "${SCRIPT_PATH}")"

(${ABS_DIRECTORY}/../lighthouse/target/release/lighthouse bn \
    --network ropsten \
    --datadir /var/lib/lighthouse \
    --staking \
    --http-allow-sync-stalled \
    --merge \
    --execution-endpoints http://127.0.0.1:8551 \
    --metrics \
    --validator-monitor-auto \
    --jwt-secrets="/var/lib/goethereum/jwtsecret" \
    --terminal-total-difficulty-override 50000000000000000 > bn_output 2>&1 &)
