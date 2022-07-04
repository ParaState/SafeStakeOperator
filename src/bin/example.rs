#![recursion_limit = "256"]

use environment::{EnvironmentBuilder, LoggerConfig};
use dvf::simulator::validator_files::ValidatorFiles;
use dvf::simulator::{testing_client_config, testing_validator_config};
use dvf::simulator::{
    local_network::{LocalNetwork},
    checks
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::cmp::max;
use futures::prelude::*;
use rayon::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::sleep;
use types::{Epoch, MainnetEthSpec, EthSpec};
use beacon_node::{ClientGenesis};
use env_logger::Env;

pub fn simple_integration_example() -> Result<(), String> {
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();

    let node_count = 3; 
    let validators_per_node = 5; 
    let speed_up_factor = 3;
    let continue_after_checks = false;

    println!("Beacon Chain Simulator:");
    println!(" nodes:{}", node_count);
    println!(" validators_per_node:{}", validators_per_node);
    println!(" continue_after_checks:{}", continue_after_checks);

    // Generate the directories and keystores required for the validator clients.
    let validator_files = (0..node_count)
        .into_par_iter()
        .map(|i| {
            println!(
                "Generating keystores for validator {} of {}",
                i + 1,
                node_count
            );

            let indices =
                (i * validators_per_node..(i + 1) * validators_per_node).collect::<Vec<_>>();
            ValidatorFiles::with_keystores(&indices).unwrap()
        })
        .collect::<Vec<_>>();

    let log_level = "debug";
    let log_format = None;

    let mut env = EnvironmentBuilder::mainnet()
        .initialize_logger(LoggerConfig {
            path: None,
            debug_level: log_level,
            logfile_debug_level: "debug",
            log_format,
            max_log_size: 0,
            max_log_number: 0,
            compression: false,
        })?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    let spec = &mut env.eth2_config.spec;

    let total_validator_count = validators_per_node * node_count;

    spec.seconds_per_slot /= speed_up_factor;
    spec.seconds_per_slot = max(1, spec.seconds_per_slot);
    spec.eth1_follow_distance = 16;
    spec.genesis_delay = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = total_validator_count as u64;
    spec.seconds_per_eth1_block = 1;

    let genesis_delay = Duration::from_secs(5);
    let genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "should get system time")?
        + genesis_delay;

    let slot_duration = Duration::from_secs(spec.seconds_per_slot);

    let context = env.core_context();

    let mut beacon_config = testing_client_config();

    beacon_config.genesis = ClientGenesis::Interop {
        validator_count: total_validator_count,
        genesis_time: genesis_time.as_secs(),
    };
    beacon_config.dummy_eth1_backend = true;
    beacon_config.sync_eth1_chain = true;

    beacon_config.network.enr_address = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let main_future = async {
        let network = LocalNetwork::new(context.clone(), beacon_config.clone()).await?;
        /*
         * One by one, add beacon nodes to the network.
         */

        for _ in 0..node_count - 1 {
            network.add_beacon_node(beacon_config.clone()).await?;
        }

        /*
         * Create a future that will add validator clients to the network. Each validator client is
         * attached to a single corresponding beacon node. Spawn each validator in a new task.
         */
        let executor = context.executor.clone();
        for (i, files) in validator_files.into_iter().enumerate() {
            let network_1 = network.clone();
            executor.spawn(
                async move {
                    println!("Adding validator client {}", i);
                    network_1
                        .add_validator_client(testing_validator_config(), i, files, i % 2 == 0)
                        .await
                        .expect("should add validator");
                },
                "vc",
            );
        }

        let duration_to_genesis = network.duration_to_genesis().await;
        println!("Duration to genesis: {}", duration_to_genesis.as_secs());
        sleep(duration_to_genesis).await;

        let (finalization, block_prod) = futures::join!(
            // Check that the chain finalizes at the first given opportunity.
            checks::verify_first_finalization(network.clone(), slot_duration),
            // Check that a block is produced at every slot.
            checks::verify_full_block_production_up_to(
                network.clone(),
                Epoch::new(1).start_slot(MainnetEthSpec::slots_per_epoch()),
                slot_duration,
            ),
        );
        finalization?;
        block_prod?;

        // The `final_future` either completes immediately or never completes, depending on the value
        // of `continue_after_checks`.

        if continue_after_checks {
            future::pending::<()>().await;
        }
        /*
         * End the simulation by dropping the network. This will kill all running beacon nodes and
         * validator clients.
         */
        println!(
            "Simulation complete. Finished with {} beacon nodes and {} validator clients",
            network.beacon_node_count(),
            network.validator_client_count()
        );

        // Be explicit about dropping the network, as this kills all the nodes. This ensures
        // all the checks have adequate time to pass.
        drop(network);
        Ok::<(), String>(())
    };

    env.runtime().block_on(main_future).unwrap();

    env.fire_signal();
    env.shutdown_on_idle();
    Ok(())
}

fn main() {
    match simple_integration_example() {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => {
            eprintln!("Simulation exited with error: {}", e);
            std::process::exit(1)
        }
    }
}
