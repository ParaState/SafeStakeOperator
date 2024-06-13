use clap::{builder::ArgPredicate, Arg, ArgAction, Command};
use clap_utils::{get_color_style, FLAG_HEADER};

pub fn cli_app() -> Command {
    Command::new("validator_client")
        .visible_aliases(["v", "vc", "validator"])
        .styles(get_color_style())
        .display_order(0)
        .about(
            "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",
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
            Arg::new("beacon-nodes")
                .long("beacon-nodes")
                .value_name("NETWORK_ADDRESSES")
                .help("Comma-separated addresses to one or more beacon node HTTP APIs. \
                       Default is http://localhost:5052."
                )
                .action(ArgAction::Set)
                .display_order(0)
        )
        .arg(
            Arg::new("proposer-nodes")
                .long("proposer-nodes")
                .value_name("NETWORK_ADDRESSES")
                .help("Comma-separated addresses to one or more beacon node HTTP APIs. \
                These specify nodes that are used to send beacon block proposals. A failure will revert back to the standard beacon nodes specified in --beacon-nodes."
                )
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("broadcast")
                .long("broadcast")
                .value_name("API_TOPICS")
                .help("Comma-separated list of beacon API topics to broadcast to all beacon nodes. \
                       Possible values are: none, attestations, blocks, subscriptions, \
                       sync-committee. Default (when flag is omitted) is to broadcast \
                       subscriptions only."
                )
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("validators-dir")
                .long("validators-dir")
                .alias("validator-dir")
                .value_name("VALIDATORS_DIR")
                .help(
                    "The directory which contains the validator keystores, deposit data for \
                    each validator along with the common slashing protection database \
                    and the validator_definitions.yml"
                )
                .action(ArgAction::Set)
                .conflicts_with("datadir")
                .display_order(0)
        )
        .arg(
            Arg::new("secrets-dir")
                .long("secrets-dir")
                .value_name("SECRETS_DIRECTORY")
                .help(
                    "The directory which contains the password to unlock the validator \
                    voting keypairs. Each password should be contained in a file where the \
                    name is the 0x-prefixed hex representation of the validators voting public \
                    key. Defaults to ~/.lighthouse/{network}/secrets.",
                )
                .action(ArgAction::Set)
                .conflicts_with("datadir")
                .display_order(0)
        )
        .arg(
            Arg::new("ip")
                .long("ip")
                .value_name("NODE_IP")
                .help(
                    "This node's ip which is used for connections with other nodes"
                )
                .action(ArgAction::Set)
                .display_order(0)
                .required(true)
        )
        .arg(
            Arg::new("id")
            .long("id")
            .value_name("NODE_ID")
            .help(
                "This node's id in smart contract"
            )
            .action(ArgAction::Set)
            .display_order(0)
            .required(true)
        )
        .arg(
            Arg::new("api")
                .long("api")
                .value_name("API")
                .help(
                    "The api where the operator to send performance request"
                )
                .action(ArgAction::Set)
                .display_order(0)
                .required(true)
        )
        .arg(
            Arg::new("base-port")
                .long("base-port")
                .value_name("BASE_PORT")
                .help(
                    "This node's BASE_PORT"
                )
                .action(ArgAction::Set)
                .display_order(0)
                .required(true)
        )
        .arg(
            Arg::new("ws-url")
            .long("ws-url")
            .value_name("WS_URL")
            .help("web socket url of infura to listen contract event")
            .action(ArgAction::Set)
            .display_order(0)
            .required(true)
        )
        .arg(
            Arg::new("registry-contract")
                .long("registry-contract")
                .value_name("REGISTRY_CONTRACT")
                .help(
                    "This is the address of registry contract"
                )
                .action(ArgAction::Set)
                .display_order(0)
                .required(true)
        )
        .arg(
            Arg::new("network-contract")
                .long("network-contract")
                .value_name("NETWORK_CONTRACT")
                .help(
                    "This is the address of network contract"
                )
                .action(ArgAction::Set)
                .display_order(0)
                .required(true)
        )
        .arg(
            Arg::new("init-slashing-protection")
                .long("init-slashing-protection")
                .help(
                    "If present, do not require the slashing protection database to exist before \
                     running. You SHOULD NOT use this flag unless you're certain that a new \
                     slashing protection database is required. Usually, your database \
                     will have been initialized when you imported your validator keys. If you \
                     misplace your database and then run with this flag you risk being slashed."
                )
        )
        .arg(
            Arg::new("disable-auto-discover")
            .long("disable-auto-discover")
            .help(
                "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file."
            )
        )
        .arg(
            Arg::new("use-long-timeouts")
                .long("use-long-timeouts")
                .help("If present, the validator client will use longer timeouts for requests \
                        made to the beacon node. This flag is generally not recommended, \
                        longer timeouts can cause missed duties when fallbacks are used.")
        )
        .arg(
            Arg::new("beacon-nodes-tls-certs")
                .long("beacon-nodes-tls-certs")
                .value_name("CERTIFICATE-FILES")
                .action(ArgAction::Set)
                .help("Comma-separated paths to custom TLS certificates to use when connecting \
                        to a beacon node. These certificates must be in PEM format and are used \
                        in addition to the OS trust store. Commas must only be used as a \
                        delimiter, and must not be part of the certificate path.")
        )
        // This overwrites the graffiti configured in the beacon node.
        .arg(
            Arg::new("graffiti")
                .long("graffiti")
                .help("Specify your custom graffiti to be included in blocks.")
                .value_name("GRAFFITI")
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("graffiti-file")
                .long("graffiti-file")
                .help("Specify a graffiti file to load validator graffitis from.")
                .value_name("GRAFFITI-FILE")
                .action(ArgAction::Set)
                .conflicts_with("graffiti")
        )
        /* REST API related arguments */
        .arg(
            Arg::new("http")
                .long("http")
                .help("Enable the RESTful HTTP API server. Disabled by default.")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .display_order(0),
        )
        /*
         * Note: The HTTP server is **not** encrypted (i.e., not HTTPS) and therefore it is
         * unsafe to publish on a public network.
         *
         * If the `--http-address` flag is used, the `--unencrypted-http-transport` flag
         * must also be used in order to make it clear to the user that this is unsafe.
         */
         .arg(
             Arg::new("http-address")
                 .long("http-address")
                 .value_name("ADDRESS")
                 .help("Set the address for the HTTP address. The HTTP server is not encrypted \
                        and therefore it is unsafe to publish on a public network. When this \
                        flag is used, it additionally requires the explicit use of the \
                        `--unencrypted-http-transport` flag to ensure the user is aware of the \
                        risks involved. For access via the Internet, users should apply \
                        transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.")
                    .requires("unencrypted-http-transport")
                        .display_order(0),
         )
         .arg(
             Arg::new("unencrypted-http-transport")
                 .long("unencrypted-http-transport")
                 .help("This is a safety flag to ensure that the user is aware that the http \
                        transport is unencrypted and using a custom HTTP address is unsafe.")
                 .requires("http-address"),
         )
        .arg(
            Arg::new("http-port")
                .long("http-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value_if("http", ArgPredicate::IsPresent, "5062")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("http-allow-origin")
                .long("http-allow-origin")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062).")
                    .action(ArgAction::Set)
                    .display_order(0),
        )
        /* Prometheus metrics HTTP server related arguments */
        .arg(
            Arg::new("metrics")
                .long("metrics")
                .help("Enable the Prometheus metrics HTTP server. Disabled by default.")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .display_order(0),
        )
        .arg(
            Arg::new("metrics-address")
                .long("metrics-address")
                .requires("metrics")
                .value_name("ADDRESS")
                .help("Set the listen address for the Prometheus metrics HTTP server.")
                .default_value_if("metrics", ArgPredicate::IsPresent, "127.0.0.1")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("metrics-port")
                .long("metrics-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the Prometheus metrics HTTP server.")
                .default_value_if("metrics", ArgPredicate::IsPresent, "5064")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("metrics-allow-origin")
                .long("metrics-allow-origin")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5064).")
                    .action(ArgAction::Set)
                    .display_order(0),
        )
        /*
         * Explorer metrics
         */
         .arg(
            Arg::new("monitoring-endpoint")
                .long("monitoring-endpoint")
                .value_name("ADDRESS")
                .help("Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL.")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("monitoring-endpoint-period")
                .long("monitoring-endpoint-period")
                .value_name("SECONDS")
                .help("Defines how many seconds to wait between each message sent to \
                       the monitoring-endpoint. Default: 60s")
                .requires("monitoring-endpoint")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new("enable-doppelganger-protection")
                .long("enable-doppelganger-protection")
                .value_name("ENABLE_DOPPELGANGER_PROTECTION")
                .help("If this flag is set, Lighthouse will delay startup for three epochs and \
                    monitor for messages on the network by any of the validators managed by this \
                    client. This will result in three (possibly four) epochs worth of missed \
                    attestations. If an attestation is detected during this period, it means it is \
                    very likely that you are running a second validator client with the same keys. \
                    This validator client will immediately shutdown if this is detected in order \
                    to avoid potentially committing a slashable offense. Use this flag in order to \
                    ENABLE this functionality, without this flag Lighthouse will begin attesting \
                    immediately.")
                    .action(ArgAction::SetTrue)
                    .help_heading(FLAG_HEADER)
                    .display_order(0),
        )
        .arg(
            Arg::new("builder-proposals")
                .long("builder-proposals")
                .alias("private-tx-proposals")
                .help("If this flag is set, Lighthouse will query the Beacon Node for only block \
                    headers during proposals and will sign over headers. Useful for outsourcing \
                    execution payload construction during proposals.")
                    .action(ArgAction::SetTrue)
                    .help_heading(FLAG_HEADER)
                    .display_order(0),
        )
        .arg(
            Arg::new("gas-limit")
                .long("gas-limit")
                .value_name("INTEGER")
                .action(ArgAction::Set)
                .help("The gas limit to be used in all builder proposals for all validators managed \
                    by this validator client. Note this will not necessarily be used if the gas limit \
                    set here moves too far from the previous block's gas limit. [default: 30,000,000]")
                    .requires("builder-proposals")
                    .display_order(0),
        )
        .arg(
            Arg::new("validator-registration-batch-size")
                .long("validator-registration-batch-size")
                .value_name("INTEGER")
                .help("Defines the number of validators per \
                    validator/register_validator request sent to the BN. This value \
                    can be reduced to avoid timeouts from builders.")
                .default_value("500")
                .action(ArgAction::Set)
                .display_order(0),
        )
}
