pub mod boot_service;
pub mod config;
pub mod proto;
use crate::boot_service::BootService;
use crate::config::Config;
use crate::proto::bootnode_server::BootnodeServer;
use dvf_utils::DEFAULT_BASE_PORT;
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr, EnrPublicKey},
    ConfigBuilder, Discv5, Event, ListenConfig,
};
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use safestake_crypto::secret::{Export, Secret};
use safestake_database::SafeStakeDatabase;
use slog::{info, warn, Logger};
use std::net::{IpAddr, SocketAddr};
use task_executor::TaskExecutor;
use tonic::transport::Server;
use clap::{Arg, ArgAction, Command};
use clap_utils::{get_color_style, FLAG_HEADER};

pub const DISCOVERY_PORT_OFFSET: u16 = 4;

pub fn cli_app() -> Command {
    Command::new("boot_node")
        .visible_aliases(["b"])
        .styles(get_color_style())
        .display_order(0)
        .about(
            "safestake boot node",
        )
        .arg(
            Arg::new("help")
            .long("help")
            .short('h')
            .help("Prints help information")
            .action(ArgAction::HelpLong)
            .display_order(0)
            .help_heading(FLAG_HEADER)
        )
        .arg(
            Arg::new("ip")
                .long("ip")
                .value_name("IP")
                .help("ip"
                )
                .action(ArgAction::Set)
                .display_order(0)
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .help("port"
                )
                .action(ArgAction::Set)
                .display_order(0)
        )
}

pub async fn run(config: Config, executor: &TaskExecutor, log: Logger) {
    if !config.root_dir.exists() {
        std::fs::create_dir_all(&config.root_dir).unwrap();
    }
    let db_path = config.root_dir.join("boot_node.sqlite");
    let db = SafeStakeDatabase::open_or_create(&db_path).unwrap();
    let node_secret_path = config.root_dir.join("node_key.json");

    let secret = if node_secret_path.exists() {
        let secret = Secret::read(&node_secret_path).unwrap();
        info!(log, "read node key"; "operator node public key" => format!("{}", &secret.name));
        secret
    } else {
        let secret = Secret::new();
        secret.write(&node_secret_path).unwrap();
        secret
    };

    let mut secret_key = secret.secret.0[..].to_vec();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key).unwrap();

    // construct a local ENR
    let local_enr = {
        let mut builder = Enr::builder();
        builder.ip(config.ip);
        builder.udp4(config.port);
        builder.build(&enr_key).unwrap()
    };
    info!(
        log,
        "boot node";
        "enr" => format!("{:?}", local_enr.to_base64())
    );
    let c = ConfigBuilder::new(ListenConfig::Ipv4 {
        ip: "0.0.0.0".parse().unwrap(),
        port: config.port,
    })
    .build();

    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, c).unwrap();
    let db_backup = db.clone();
    executor.spawn(
        async move {
            let _ = discv5.start().await;
            let mut event_stream = discv5.event_stream().await.unwrap();
            loop {
                if let Some(event) = event_stream.recv().await {
                    match event {
                        Event::Discovered(enr) => {
                            handle_enr(&secret.name, &db, enr);
                        }
                        Event::SessionEstablished(enr, _) => {
                            handle_enr(&secret.name, &db, enr);
                        }
                        Event::SocketUpdated(_) => {}
                        Event::NodeInserted { .. }  => {}
                        Event::TalkRequest(_) => {} // Ignore all other discv5 server events
                        Event::UnverifiableEnr { enr, socket, .. } => {
                            warn!(
                                log,
                                "unveriable enr";
                                "enr" => %enr,
                                "socket" => %socket
                            );
                        },
                        _ => {}
                    };
                }
            }
        },
        "boot node",
    );
    let boot_service = BootService { db: db_backup };
    let addr = format!("0.0.0.0:{}", config.port).parse().unwrap();
    Server::builder()
        .add_service(BootnodeServer::new(boot_service))
        .serve(addr)
        .await
        .unwrap()
}

pub fn handle_enr(self_public_key: &SecpPublicKey, db: &SafeStakeDatabase, enr: Enr<CombinedKey>) {
    let node_public_key: [u8; 33] = enr.public_key().encode().try_into().unwrap();
    let public_key = SecpPublicKey(node_public_key);
    if public_key == *self_public_key {
        // ignore self operator, the address of self operator in database is always 127.0.0.1:26000
        return;
    }
    let seq = match db.with_transaction(|txn| db.query_operator_seq(txn, &public_key)) {
        Ok(seq) => seq,
        Err(_) => 0,
    };
    if enr.seq() > seq {
        let _ = db.with_transaction(|tx| {
            let ip = enr.ip4().unwrap();
            let port = match enr.udp4() {
                Some(port) => port.checked_sub(DISCOVERY_PORT_OFFSET).unwrap(),
                None => DEFAULT_BASE_PORT,
            };
            let socket_address = SocketAddr::new(IpAddr::V4(ip), port);
            db.upsert_operator_socket_address(tx, &public_key, &socket_address, enr.seq())
        });
    }
}
