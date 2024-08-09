//! Implementation of the standard remotekey management API.
use crate::validation::account_utils::validator_definitions::{
    SigningDefinition, ValidatorDefinition, Web3SignerDefinition
};
use crate::validation::{initialized_validators::Error, InitializedValidators, ValidatorStore};
use eth2::lighthouse_vc::std_types::{
    DeleteRemotekeyStatus, DeleteRemotekeysRequest, DeleteRemotekeysResponse,
    ImportRemotekeyStatus, ImportRemotekeysRequest, ImportRemotekeysResponse,
    ListRemotekeysResponse, SingleListRemotekeysResponse, Status,
};
use futures::executor::block_on;
use slog::{info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::runtime::Handle;
use types::{EthSpec, PublicKeyBytes};
use url::Url;
use warp::Rejection;
use warp_utils::reject::custom_server_error;

pub fn list<T: SlotClock + 'static, E: EthSpec>(
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ListRemotekeysResponse {
    let initialized_validators_rwlock = validator_store.initialized_validators();
    let initialized_validators = block_on(initialized_validators_rwlock.read());

    let keystores = initialized_validators
        .validator_definitions()
        .iter()
        .filter(|def| def.enabled)
        .filter_map(|def| {
            let validating_pubkey = def.voting_public_key.compress();

            match &def.signing_definition {
                SigningDefinition::LocalKeystore { .. } => None,
                SigningDefinition::Web3Signer(Web3SignerDefinition { url, .. }) => {
                    Some(SingleListRemotekeysResponse {
                        pubkey: validating_pubkey,
                        url: url.clone(),
                        readonly: false,
                    })
                },
                // [Zico]TODO: to be revised
                SigningDefinition::DistributedKeystore { .. } => None,
            }
        })
        .collect::<Vec<_>>();

    ListRemotekeysResponse { data: keystores }
}

pub fn _import<T: SlotClock + 'static, E: EthSpec>(
    request: ImportRemotekeysRequest,
    validator_store: Arc<ValidatorStore<T, E>>,
    task_executor: TaskExecutor,
    log: Logger,
) -> Result<ImportRemotekeysResponse, Rejection> {
    info!(
        log,
        "Importing remotekeys via standard HTTP API";
        "count" => request.remote_keys.len(),
    );
    // Import each remotekey. Some remotekeys may fail to be imported, so we record a status for each.
    let mut statuses = Vec::with_capacity(request.remote_keys.len());

    for remotekey in request.remote_keys {
        let status = if let Some(handle) = task_executor.handle() {
            // Import the keystore.
            match _import_single_remotekey(remotekey.pubkey, remotekey.url, &validator_store, handle)
            {
                Ok(status) => Status::ok(status),
                Err(e) => {
                    warn!(
                        log,
                        "Error importing keystore, skipped";
                        "pubkey" => remotekey.pubkey.to_string(),
                        "error" => ?e,
                    );
                    Status::error(ImportRemotekeyStatus::Error, e)
                }
            }
        } else {
            Status::error(
                ImportRemotekeyStatus::Error,
                "validator client shutdown".into(),
            )
        };
        statuses.push(status);
    }
    Ok(ImportRemotekeysResponse { data: statuses })
}

fn _import_single_remotekey<T: SlotClock + 'static, E: EthSpec>(
    pubkey: PublicKeyBytes,
    url: String,
    validator_store: &ValidatorStore<T, E>,
    handle: Handle,
) -> Result<ImportRemotekeyStatus, String> {
    if let Err(url_err) = Url::parse(&url) {
        return Err(format!("failed to parse remotekey URL: {}", url_err));
    }

    let pubkey = pubkey
        .decompress()
        .map_err(|_| format!("invalid pubkey: {}", pubkey))?;

    if let Some(def) = block_on(validator_store.initialized_validators().read())
        .validator_definitions()
        .iter()
        .find(|def| def.voting_public_key == pubkey)
    {
        if def.signing_definition.is_local_keystore() {
            return Err("Pubkey already present in local keystore.".into());
        } else if def.enabled {
            return Ok(ImportRemotekeyStatus::Duplicate);
        }
    }

    // Remotekeys are stored as web3signers.
    // The remotekey API provides less confgiuration option than the web3signer API.
    let web3signer_validator = ValidatorDefinition {
        enabled: true,
        voting_public_key: pubkey,
        graffiti: None,
        suggested_fee_recipient: None,
        gas_limit: None,
        builder_proposals: None,
        builder_boost_factor: None,
        prefer_builder_proposals: None,
        description: String::from("Added by remotekey API"),
        signing_definition: SigningDefinition::Web3Signer(Web3SignerDefinition {
            url,
            root_certificate_path: None,
            request_timeout_ms: None,
            client_identity_path: None,
            client_identity_password: None,
        }),
    };
    handle
        .block_on(validator_store.add_validator(web3signer_validator))
        .map_err(|e| format!("failed to initialize validator: {:?}", e))?;

    Ok(ImportRemotekeyStatus::Imported)
}

pub fn _delete<T: SlotClock + 'static, E: EthSpec>(
    request: DeleteRemotekeysRequest,
    validator_store: Arc<ValidatorStore<T, E>>,
    task_executor: TaskExecutor,
    log: Logger,
) -> Result<DeleteRemotekeysResponse, Rejection> {
    info!(
        log,
        "Deleting remotekeys via standard HTTP API";
        "count" => request.pubkeys.len(),
    );
    // Remove from initialized validators.
    let initialized_validators_rwlock = validator_store.initialized_validators();
    let mut initialized_validators = block_on(initialized_validators_rwlock.write());

    let statuses = request
        .pubkeys
        .iter()
        .map(|pubkey_bytes| {
            match _delete_single_remotekey(
                pubkey_bytes,
                &mut initialized_validators,
                task_executor.clone(),
            ) {
                Ok(status) => Status::ok(status),
                Err(error) => {
                    warn!(
                        log,
                        "Error deleting keystore";
                        "pubkey" => ?pubkey_bytes,
                        "error" => ?error,
                    );
                    Status::error(DeleteRemotekeyStatus::Error, error)
                }
            }
        })
        .collect::<Vec<_>>();

    // Use `update_validators` to update the key cache. It is safe to let the key cache get a bit out
    // of date as it resets when it can't be decrypted. We update it just a single time to avoid
    // continually resetting it after each key deletion.
    if let Some(handle) = task_executor.handle() {
        handle
            .block_on(initialized_validators.update_validators())
            .map_err(|e| custom_server_error(format!("unable to update key cache: {:?}", e)))?;
    }

    Ok(DeleteRemotekeysResponse { data: statuses })
}

fn _delete_single_remotekey<E: EthSpec>(
    pubkey_bytes: &PublicKeyBytes,
    initialized_validators: &mut InitializedValidators<E>,
    task_executor: TaskExecutor,
) -> Result<DeleteRemotekeyStatus, String> {
    if let Some(handle) = task_executor.handle() {
        let pubkey = pubkey_bytes
            .decompress()
            .map_err(|e| format!("invalid pubkey, {:?}: {:?}", pubkey_bytes, e))?;

        match handle.block_on(initialized_validators.delete_definition_and_keystore(&pubkey)) {
            Ok(_) => Ok(DeleteRemotekeyStatus::Deleted),
            Err(e) => match e {
                Error::ValidatorNotInitialized(_) => Ok(DeleteRemotekeyStatus::NotFound),
                _ => Err(format!("unable to disable and delete: {:?}", e)),
            },
        }
    } else {
        Err("validator client shutdown".into())
    }
}
