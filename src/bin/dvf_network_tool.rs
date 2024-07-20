use hsconfig::Secret;
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr},
    ConfigBuilder, Discv5, ListenConfig,
};
use log::{error, info};
use std::net::IpAddr;
pub const DISCOVERY_PORT_OFFSET: u16 = 4;
pub const DEFAULT_DISCOVERY_PORT: u16 = 26004;

#[tokio::main]
async fn main() {
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();
    log::info!("------dvf_network_tool------");

    let ip = std::env::args()
        .nth(1)
        .expect("ERROR: there is no valid network argument");

    let port: u16 = std::env::args()
        .nth(2)
        .expect("ERROR: there is no valid port argument")
        .parse()
        .unwrap();

    let udp_port = port + DISCOVERY_PORT_OFFSET;
    let ip_addr = IpAddr::V4(ip.parse().unwrap());
    let mut secret = Secret::new();
    let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret.secret.0).unwrap();
    let file = std::fs::File::options()
        .read(true)
        .write(false)
        .create(false)
        .open("boot_config/boot_enrs.yaml")
        .expect(
            format!(
                "Unable to open the boot enrs config file: {:?}",
                "boot_config/boot_enrs.yaml"
            )
            .as_str(),
        );

    let boot_enrs: Vec<Enr<CombinedKey>> =
        serde_yaml::from_reader(file).expect("Unable to parse boot enr");

    let config = ConfigBuilder::new(ListenConfig::Ipv4 {
        ip: "0.0.0.0".parse().unwrap(),
        port: udp_port,
    })
    .build();

    let local_enr = {
        let mut builder = Enr::builder();
        builder.ip(ip_addr);
        if udp_port != DEFAULT_DISCOVERY_PORT {
            builder.udp4(udp_port);
        }
        builder.seq(1);
        builder.build(&enr_key).unwrap()
    };

    let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, config).unwrap();

    for boot_enr in &boot_enrs {
        if let Err(e) = discv5.add_enr(boot_enr.clone()) {
            panic!("Boot ENR was not added: {}", e);
        }
        info!("Added boot enr: {:?}", boot_enr.to_base64());
    }

    
    match discv5.start().await {
        Ok(_) => {
            for boot_enr in &boot_enrs {
                let res = discv5.find_node(boot_enr.node_id()).await;
                match res {
                    Ok(nodes) => {
                        if nodes.len() == 0 {
                            error!("Can't connect to boot node");
                        } else {
                            info!("Successfully connected to boot node, you can run your operator")
                        }
                    }
                    Err(e) => {
                        error!("Can't connect to boot and run query: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            error!("Can't start discv5: {}", e);
        }
    }
    
}
