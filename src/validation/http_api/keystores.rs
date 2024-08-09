//! Implementation of the standard keystore management API.
use crate::validation::account_utils::ZeroizeString;
use crate::validation::{signing_method::SigningMethod,
    ValidatorStore,
};
use eth2::lighthouse_vc::std_types::{
    ImportKeystoreStatus,
    ImportKeystoresRequest, ImportKeystoresResponse, InterchangeJsonStr, KeystoreJsonStr,
    ListKeystoresResponse, SingleKeystoreResponse, Status,
    };
use eth2_keystore::Keystore;
use futures::executor::block_on;
use slog::{info, warn, Logger};
use slot_clock::SlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::runtime::Handle;
use types::EthSpec;
use validator_dir::Builder as ValidatorDirBuilder;
use warp::Rejection;
use warp_utils::reject::custom_bad_request;

pub fn list<T: SlotClock + 'static, E: EthSpec>(
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ListKeystoresResponse {
    let initialized_validators_rwlock = validator_store.initialized_validators();
    let initialized_validators = block_on(initialized_validators_rwlock.read());

    let keystores = initialized_validators
        .validator_definitions()
        .iter()
        .filter(|def| def.enabled)
        .map(|def| {
            let validating_pubkey = def.voting_public_key.compress();

            let (derivation_path, readonly) = initialized_validators
                .signing_method(&validating_pubkey)
                .map_or((None, None), |signing_method| match *signing_method {
                    SigningMethod::LocalKeystore {
                        ref voting_keystore,
                        ..
                    } => (voting_keystore.path(), None),
                    SigningMethod::Web3Signer { .. } => (None, Some(true)),
                    // [Zico]TODO: to be revised
                    SigningMethod::DistributedKeystore { .. } => (None, Some(true)),
                });

            SingleKeystoreResponse {
                validating_pubkey,
                derivation_path,
                readonly,
            }
        })
        .collect::<Vec<_>>();

    ListKeystoresResponse { data: keystores }
}

pub fn _import<T: SlotClock + 'static, E: EthSpec>(
    request: ImportKeystoresRequest,
    validator_dir: PathBuf,
    validator_store: Arc<ValidatorStore<T, E>>,
    task_executor: TaskExecutor,
    log: Logger,
) -> Result<ImportKeystoresResponse, Rejection> {
    // Check request validity. This is the only cases in which we should return a 4xx code.
    if request.keystores.len() != request.passwords.len() {
        return Err(custom_bad_request(format!(
            "mismatched numbers of keystores ({}) and passwords ({})",
            request.keystores.len(),
            request.passwords.len(),
        )));
    }

    info!(
        log,
        "Importing keystores via standard HTTP API";
        "count" => request.keystores.len(),
    );

    // Import slashing protection data before keystores, so that new keystores don't start signing
    // without it. Do not return early on failure, propagate the failure to each key.
    let slashing_protection_status =
        if let Some(InterchangeJsonStr(slashing_protection)) = request.slashing_protection {
            // Warn for missing slashing protection.
            for KeystoreJsonStr(ref keystore) in &request.keystores {
                if let Some(public_key) = keystore.public_key() {
                    let pubkey_bytes = public_key.compress();
                    if !slashing_protection
                        .data
                        .iter()
                        .any(|data| data.pubkey == pubkey_bytes)
                    {
                        warn!(
                            log,
                            "Slashing protection data not provided";
                            "public_key" => ?public_key,
                        );
                    }
                }
            }

            validator_store.import_slashing_protection(slashing_protection)
        } else {
            warn!(log, "No slashing protection data provided with keystores");
            Ok(())
        };

    // Import each keystore. Some keystores may fail to be imported, so we record a status for each.
    let mut statuses = Vec::with_capacity(request.keystores.len());

    for (KeystoreJsonStr(keystore), password) in request
        .keystores
        .into_iter()
        .zip(request.passwords.into_iter())
    {
        let pubkey_str = keystore.pubkey().to_string();

        let status = if let Err(e) = &slashing_protection_status {
            // Slashing protection import failed, do not attempt to import the key. Record an
            // error status.
            Status::error(
                ImportKeystoreStatus::Error,
                format!("slashing protection import failed: {:?}", e),
            )
        } else if let Some(handle) = task_executor.handle() {
            // Import the keystore.
            match _import_single_keystore(
                keystore,
                password,
                validator_dir.clone(),
                &validator_store,
                handle,
            ) {
                Ok(status) => Status::ok(status),
                Err(e) => {
                    warn!(
                        log,
                        "Error importing keystore, skipped";
                        "pubkey" => pubkey_str,
                        "error" => ?e,
                    );
                    Status::error(ImportKeystoreStatus::Error, e)
                }
            }
        } else {
            Status::error(
                ImportKeystoreStatus::Error,
                "validator client shutdown".into(),
            )
        };
        statuses.push(status);
    }

    Ok(ImportKeystoresResponse { data: statuses })
}

fn _import_single_keystore<T: SlotClock + 'static, E: EthSpec>(
    keystore: Keystore,
    password: ZeroizeString,
    validator_dir_path: PathBuf,
    validator_store: &ValidatorStore<T, E>,
    handle: Handle,
) -> Result<ImportKeystoreStatus, String> {
    // Check if the validator key already exists, erroring if it is a remote signer validator.
    let pubkey = keystore
        .public_key()
        .ok_or_else(|| format!("invalid pubkey: {}", keystore.pubkey()))?;
    if let Some(def) = handle
        .block_on(validator_store.initialized_validators().read())
        .validator_definitions()
        .iter()
        .find(|def| def.voting_public_key == pubkey)
    {
        if !def.signing_definition.is_local_keystore() {
            return Err("cannot import duplicate of existing remote signer validator".into());
        } else if def.enabled {
            return Ok(ImportKeystoreStatus::Duplicate);
        }
    }

    // Check that the password is correct.
    // In future we should re-structure to avoid the double decryption here. It's not as simple
    // as removing this check because `add_validator_keystore` will break if provided with an
    // invalid validator definition (`update_validators` will get stuck trying to decrypt with the
    // wrong password indefinitely).
    keystore
        .decrypt_keypair(password.as_ref())
        .map_err(|e| format!("incorrect password: {:?}", e))?;

    let validator_dir = ValidatorDirBuilder::new(validator_dir_path)
        .voting_keystore(keystore, password.as_ref())
        .store_withdrawal_keystore(false)
        .build()
        .map_err(|e| format!("failed to build validator directory: {:?}", e))?;

    // Drop validator dir so that `add_validator_keystore` can re-lock the keystore.
    let voting_keystore_path = validator_dir.voting_keystore_path();
    drop(validator_dir);

    handle
        .block_on(validator_store.add_validator_keystore(
            voting_keystore_path,
            password,
            true,
            None,
            None,
            None,
            None,
            None,
            None
        ))
        .map_err(|e| format!("failed to initialize validator: {:?}", e))?;

    Ok(ImportKeystoreStatus::Imported)
}