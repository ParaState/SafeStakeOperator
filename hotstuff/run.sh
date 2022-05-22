RUST_LOG=info cargo run --bin node run --keys=node_0.json --tx_address=127.0.0.1:25000 --mempool_address=127.0.0.1:25100 --consensus_address=127.0.0.1:25200 --dvfcore_address=127.0.0.1:25300 --store=db_0 --committee=committee.json

RUST_LOG=info cargo run --bin node run --keys=node_1.json --tx_address=127.0.0.1:25001 --mempool_address=127.0.0.1:25101 --consensus_address=127.0.0.1:25201 --dvfcore_address=127.0.0.1:25301 --store=db_1 --committee=committee.json

RUST_LOG=info cargo run --bin node run --keys=node_2.json --tx_address=127.0.0.1:25002 --mempool_address=127.0.0.1:25102 --consensus_address=127.0.0.1:25202 --dvfcore_address=127.0.0.1:25302 --store=db_2 --committee=committee.json

RUST_LOG=info cargo run --bin node run --keys=node_3.json --tx_address=127.0.0.1:25003 --mempool_address=127.0.0.1:25103 --consensus_address=127.0.0.1:25203 --dvfcore_address=127.0.0.1:25303 --store=db_3 --committee=committee.json

RUST_LOG=info cargo run --bin node run --keys=node_0.json --store=db_0 --committee=committee.json
RUST_LOG=info cargo run --bin node run --keys=node_1.json --store=db_1 --committee=committee.json
RUST_LOG=info cargo run --bin node run --keys=node_2.json --store=db_2 --committee=committee.json
RUST_LOG=info cargo run --bin node run --keys=node_3.json --store=db_3 --committee=committee.json