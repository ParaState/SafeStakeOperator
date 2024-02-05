use std::collections::HashMap;
use std::path::Path;

use crate::node::contract::{Initiator, Operator, Validator};
use log::{debug, error};
use rusqlite::{params, Connection, DropBehavior, Result};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use web3::types::Address;

use super::contract::InitiatorStoreRecord;

pub type DbError = rusqlite::Error;
type DbResult<T> = Result<T, DbError>;

pub enum DbCommand {
    InsertOperator(Operator),
    InsertValidator(Validator),
    DeleteOperator(u32),
    // delete operator by id
    DeleteValidator(String),
    // delete validator by pk
    QueryOperatorById(u32, oneshot::Sender<DbResult<Option<Operator>>>),
    // query operator by operator id
    QueryValidatorByPublicKey(String, oneshot::Sender<DbResult<Option<Validator>>>),
    QueryOperatorPublicKeyByIds(Vec<u32>, oneshot::Sender<DbResult<Option<Vec<String>>>>),
    QueryOperatorPublicKeyById(u32, oneshot::Sender<DbResult<Option<String>>>),
    InsertInitiator(Initiator),
    UpdateInitiator(u32, String, String, oneshot::Sender<DbResult<usize>>),
    QueryInitiator(u32, oneshot::Sender<DbResult<Option<Initiator>>>),
    QueryInitiatorReleaterOpPk(u32, oneshot::Sender<DbResult<(Vec<String>, Vec<u32>)>>),
    QueryAllValidatorOwners(oneshot::Sender<DbResult<Vec<Address>>>),
    QueryValidatorByAddress(Address, oneshot::Sender<DbResult<Vec<Validator>>>),
    DisableValidator(String),
    EnableValidator(String),
    ValidatorActive(String, oneshot::Sender<DbResult<bool>>),
    InsertContractCommand(u64, String),
    GetContractCommand(oneshot::Sender<DbResult<(String, u32)>>),
    DeleteContractCommand(u32),
    UpdatetimeContractCommand(u32),
    DeleteInitiator(u32, oneshot::Sender<DbResult<Option<Initiator>>>),
    InsertInitiatorStore(InitiatorStoreRecord),
    QueryInitiatorStore(u32, oneshot::Sender<DbResult<Option<InitiatorStoreRecord>>>),
}

#[derive(Clone)]
pub struct Database {
    channel: Sender<DbCommand>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> DbResult<Self> {
        let mut conn = Connection::open(path)?;

        // public_key is base64 encoded
        // address is in hex
        let create_operators_sql = "CREATE TABLE IF NOT EXISTS operators(
            id INTEGER PRIMARY KEY, 
            name TEXT NOT NULL, 
            address CHARACTER(40) NOT NULL, 
            public_key VARCHAR(100) NOT NULL
        )";

        // public key is in hex
        // address is in hex
        let create_validators_sql = "CREATE TABLE IF NOT EXISTS validators(
            public_key CHARACTER(96) PRIMARY KEY,
            id CHARACTER(32) NOT NULL, 
            owner_address CHARACTER(40) NOT NULL,
            active INTEGER DEFAULT 1 NOT NULL
        )";

        let create_releation_sql = "CREATE TABLE IF NOT EXISTS validator_operators_mapping(
            id INTEGER NOT NULL  PRIMARY KEY AUTOINCREMENT,
            validator_pk CHARACTER(96) NOT NULL, 
            operator_id INTEGER NOT NULL,
            CONSTRAINT validator_select_operators_1 FOREIGN KEY (validator_pk) REFERENCES validators(public_key) ON DELETE CASCADE,
            CONSTRAINT validator_select_operators_2 FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
        )";

        let create_initiator_sql = "CREATE TABLE IF NOT EXISTS initiators(
            id INTEGER NOT NULL PRIMARY KEY,
            address CHARACTER(40) NOT NULL, 
            validator_pk CHARACTER(96),
            minipool_address CHARACTER(40)
        )";

        let create_initiator_releation_sql = "CREATE TABLE IF NOT EXISTS initiator_operators_mapping(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            initiator_id INTEGER NOT NULL,
            operator_id INTEGER NOT NULL,
            CONSTRAINT initiator_select_operators_1 FOREIGN KEY (initiator_id) REFERENCES initiators(id) ON DELETE CASCADE,
            CONSTRAINT initiator_select_operators_2 FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
        )";

        let create_contract_command_sql = "CREATE TABLE IF NOT EXISTS contract_commands(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            validator_or_initiator_id CHARACTER(32) NOT NULL,
            sequence_num INTEGER NOT NULL,
            command VARCHAR NOT NULL,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";

        let create_update_time_trigger_sql = "CREATE TRIGGER IF NOT EXISTS update_time_trigger 
            AFTER UPDATE ON contract_commands 
            for each row
            BEGIN 
            update contract_commands set update_time = CURRENT_TIMESTAMP where id = NEW.id; 
            END;";

        let create_contract_cmd_sequence_sql = "CREATE TABLE IF NOT EXISTS contract_cmd_sequence(
            validator_or_initiator_id CHARACTER(32) NOT NULL PRIMARY KEY,
            sequence_num INTEGER NOT NULL
        )";

        let create_initiator_store_sql = "CREATE TABLE IF NOT EXISTS initiator_store_record(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            initiator_id INTEGER NOT NULL,
            share_bls_sk CHARACTER(64) NOT NULL,
            validator_pk CHARACTER(96) NOT NULL
        )";

        let create_initiator_store_oppk_sql = "CREATE TABLE IF NOT EXISTS initiator_store_record_oppk(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            operator_id INTEGER NOT NULL,
            share_bls_pk CHARACTER(96) NOT NULL,
            record_id INTEGER NOT NULL,
            CONSTRAINT initiator_store_constraint FOREIGN KEY (record_id) REFERENCES initiator_store_record(id) ON DELETE CASCADE
        )";

        conn.execute(create_operators_sql, [])?;
        conn.execute(create_validators_sql, [])?;
        conn.execute(create_releation_sql, [])?;
        conn.execute(create_initiator_sql, [])?;
        conn.execute(create_initiator_releation_sql, [])?;
        conn.execute(create_contract_command_sql, [])?;
        conn.execute(create_contract_cmd_sequence_sql, [])?;
        conn.execute(create_update_time_trigger_sql, [])?;
        conn.execute(create_initiator_store_sql, [])?;
        conn.execute(create_initiator_store_oppk_sql, [])?;
        let (tx, mut rx) = channel(1000);

        tokio::spawn(async move {
            while let Some(db_command) = rx.recv().await {
                match db_command {
                    DbCommand::InsertOperator(operator) => {
                        insert_operator(&conn, operator);
                    }
                    DbCommand::InsertValidator(validator) => insert_validator(&mut conn, validator),
                    DbCommand::DeleteOperator(operator_id) => delete_operator(&conn, operator_id),
                    DbCommand::DeleteValidator(validator_pk) => {
                        delete_validator(&conn, &validator_pk);
                    }
                    DbCommand::QueryOperatorById(operator_id, sender) => {
                        let response = query_operator_by_id(&conn, &operator_id);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryValidatorByPublicKey(validator_pk, sender) => {
                        let response = query_validator_by_public_key(&conn, &validator_pk);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryOperatorPublicKeyByIds(operator_ids, sender) => {
                        let response = query_operators_public_key_by_ids(&conn, operator_ids);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryOperatorPublicKeyById(operator_id, sender) => {
                        let response = query_operator_public_key_by_id(&conn, operator_id);
                        let _ = sender.send(response);
                    }
                    DbCommand::InsertInitiator(initiator) => {
                        insert_initiator(&mut conn, initiator);
                    }
                    DbCommand::UpdateInitiator(id, va_pk, minipool_address, sender) => {
                        let response = update_initiator(&conn, id, va_pk, minipool_address);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryInitiator(id, sender) => {
                        let response = query_initiator(&conn, id);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryInitiatorReleaterOpPk(initiator_id, sender) => {
                        let response = query_initiator_releated_operator_pks(&conn, initiator_id);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryAllValidatorOwners(sender) => {
                        let response = query_all_validator_address(&conn);
                        let _ = sender.send(response);
                    }
                    DbCommand::QueryValidatorByAddress(address, sender) => {
                        let response = query_validator_by_address(&conn, address);
                        let _ = sender.send(response);
                    }
                    DbCommand::EnableValidator(public_key) => {
                        enable_validator(&conn, public_key);
                    }
                    DbCommand::DisableValidator(public_key) => {
                        disable_validator(&conn, public_key);
                    }
                    DbCommand::ValidatorActive(public_key, sender) => {
                        let response = if_validator_active(&conn, public_key);
                        let _ = sender.send(response);
                    }
                    DbCommand::InsertContractCommand(validator_id, command) => {
                        insert_contract_command(&conn, validator_id, command);
                    }
                    DbCommand::GetContractCommand(sender) => {
                        let response = get_contract_command(&conn);
                        let _ = sender.send(response);
                    }
                    DbCommand::DeleteContractCommand(id) => {
                        delete_contract_command(&conn, id);
                    }
                    DbCommand::UpdatetimeContractCommand(id) => {
                        updatetime_contract_command(&conn, id);
                    }
                    DbCommand::DeleteInitiator(id, sender) => {
                        let response = delete_initiator(&conn, id);
                        let _ = sender.send(response);
                    }
                    DbCommand::InsertInitiatorStore(record) => {
                        insert_initiator_store(&mut conn, record);
                    }
                    DbCommand::QueryInitiatorStore(initiator_id, sender) => {
                        let response = query_initiator_store(&mut conn, initiator_id);
                        let _ = sender.send(response);
                    }
                }
            }
        });
        Ok(Self { channel: tx })
    }

    pub async fn insert_operator(&self, operator: Operator) {
        if let Err(e) = self.channel.send(DbCommand::InsertOperator(operator)).await {
            panic!("Failed to send command to store: {}", e);
        }
    }

    pub async fn insert_validator(&self, validator: Validator) {
        if let Err(e) = self
            .channel
            .send(DbCommand::InsertValidator(validator))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
    }

    pub async fn query_operator_by_id(&self, operator_id: u32) -> DbResult<Option<Operator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryOperatorById(operator_id, sender))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query operator command from db")
    }

    pub async fn query_validator_by_public_key(
        &self,
        public_key: String,
    ) -> DbResult<Option<Validator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryValidatorByPublicKey(public_key, sender))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query validator command from db")
    }

    pub async fn query_validator_by_address(&self, address: Address) -> DbResult<Vec<Validator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryValidatorByAddress(address, sender))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query validator command from db")
    }

    pub async fn query_operators_public_key_by_ids(
        &self,
        operator_ids: Vec<u32>,
    ) -> DbResult<Option<Vec<String>>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryOperatorPublicKeyByIds(operator_ids, sender))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query operator command from db")
    }

    pub async fn query_operator_public_key_by_id(
        &self,
        operator_id: u32,
    ) -> DbResult<Option<String>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryOperatorPublicKeyById(operator_id, sender))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query operator pk command from db")
    }

    pub async fn delete_validator(&self, validator_pk: String) {
        if let Err(e) = self
            .channel
            .send(DbCommand::DeleteValidator(validator_pk))
            .await
        {
            panic!("Failed to send command to store: {}", e);
        }
    }

    pub async fn delete_operator(&self, operator_id: u32) {
        if let Err(e) = self
            .channel
            .send(DbCommand::DeleteOperator(operator_id))
            .await
        {
            panic!("Failed to send delete operator command to store: {}", e);
        }
    }

    pub async fn insert_initiator(&self, initiator: Initiator) {
        if let Err(e) = self
            .channel
            .send(DbCommand::InsertInitiator(initiator))
            .await
        {
            panic!("Failed to insert insert initiator command to store: {}", e);
        }
    }

    pub async fn update_initiator(
        &self,
        id: u32,
        va_pk: String,
        minipool_address: String,
    ) -> DbResult<usize> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::UpdateInitiator(
                id,
                va_pk,
                minipool_address,
                sender,
            ))
            .await
        {
            panic!("Failed to send update initiator command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to update initiator command from db")
    }

    pub async fn query_initiator(&self, id: u32) -> DbResult<Option<Initiator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryInitiator(id, sender))
            .await
        {
            panic!("Failed to send query initiator command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query initiator command from db")
    }

    pub async fn query_initiator_releated_op_pks(
        &self,
        id: u32,
    ) -> DbResult<(Vec<String>, Vec<u32>)> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryInitiatorReleaterOpPk(id, sender))
            .await
        {
            panic!("Failed to send query initiator command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query initiator command from db")
    }

    pub async fn query_all_validator_address(&self) -> DbResult<Vec<Address>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryAllValidatorOwners(sender))
            .await
        {
            panic!(
                "Failed to send query validator owners command to store: {}",
                e
            );
        }
        receiver
            .await
            .expect("Failed to receive reply to query initiator command from db")
    }

    pub async fn if_validator_active(&self, public_key: String) -> DbResult<bool> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::ValidatorActive(public_key, sender))
            .await
        {
            panic!(
                "Failed to send query validator owners command to store: {}",
                e
            );
        }
        receiver
            .await
            .expect("Failed to receive reply to query initiator command from db")
    }

    pub async fn disable_validator(&self, public_key: String) {
        if let Err(e) = self
            .channel
            .send(DbCommand::DisableValidator(public_key))
            .await
        {
            panic!("Failed to send disable validator command to store: {}", e);
        }
    }

    pub async fn enable_validator(&self, public_key: String) {
        if let Err(e) = self
            .channel
            .send(DbCommand::EnableValidator(public_key))
            .await
        {
            panic!("Failed to send enable validator command to store: {}", e);
        }
    }

    pub async fn insert_contract_command(&self, validator_or_initiator_id: u64, command: String) {
        if let Err(e) = self
            .channel
            .send(DbCommand::InsertContractCommand(
                validator_or_initiator_id,
                command,
            ))
            .await
        {
            panic!("Failed to send insert validator command to store: {}", e);
        }
    }

    pub async fn get_contract_command(&self) -> DbResult<(String, u32)> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::GetContractCommand(sender))
            .await
        {
            panic!("Failed to send get validator command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to query initiator command from db")
    }

    pub async fn delete_contract_command(&self, id: u32) {
        if let Err(e) = self
            .channel
            .send(DbCommand::DeleteContractCommand(id))
            .await
        {
            panic!("Failed to send insert validator command to store: {}", e);
        }
    }

    pub async fn updatetime_contract_command(&self, id: u32) {
        if let Err(e) = self
            .channel
            .send(DbCommand::DeleteContractCommand(id))
            .await
        {
            panic!("Failed to send insert validator command to store: {}", e);
        }
    }

    pub async fn delete_initiator(&self, id: u32) -> DbResult<Option<Initiator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::DeleteInitiator(id, sender))
            .await
        {
            panic!("Failed to send delete initiator command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to delete initiator command from db")
    }

    pub async fn insert_initiator_store(&self, record: InitiatorStoreRecord) {
        if let Err(e) = self
            .channel
            .send(DbCommand::InsertInitiatorStore(record))
            .await
        {
            panic!(
                "Failed to send insert initiator store command to database: {}",
                e
            );
        }
    }

    pub async fn query_initiator_store(
        &self,
        initiator_id: u32,
    ) -> DbResult<Option<InitiatorStoreRecord>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self
            .channel
            .send(DbCommand::QueryInitiatorStore(initiator_id, sender))
            .await
        {
            panic!(
                "Failed to send query initiator store command to store: {}",
                e
            );
        }
        receiver
            .await
            .expect("Failed to receive reply of query initiator store from db")
    }
}

fn insert_operator(conn: &Connection, operator: Operator) {
    if let Err(e) = conn.execute(
        "INSERT INTO operators(id, name, address, public_key) values (?1, ?2, ?3, ?4)",
        params![
            &operator.id,
            &operator.name,
            format!("{0:0x}", operator.address),
            base64::encode(&operator.public_key)
        ],
    ) {
        debug!("Can't insert into operators, error: {} {:?}", e, operator);
    }
}

fn insert_initiator(conn: &mut Connection, initiator: Initiator) {
    if let Err(e) = conn.execute(
        "INSERT INTO initiators(id, address) values (?1, ?2)",
        params![initiator.id, format!("{0:0x}", initiator.owner_address),],
    ) {
        error!("Can't insert into initiator, error: {} {:?}", e, initiator);
    }
    match conn.transaction() {
        Ok(mut tx) => {
            tx.set_drop_behavior(DropBehavior::Commit);
            for operator_id in &initiator.releated_operators {
                if let Err(e) = &tx.execute("INSERT INTO initiator_operators_mapping(initiator_id, operator_id) values(?1, ?2)", params![initiator.id, operator_id], ) {
                    error!("Can't insert into initiator_operators_mapping, error: {} operator_id {:?} initiator {}", e, operator_id, initiator.id);
                    break;
                }
            }
            if let Err(e) = tx.finish() {
                error!("Can't finish the transaction {}", e);
            }
        }
        Err(e) => {
            error!("Can't create a transaction for database {}", e);
        }
    }
}

// validator_pk is in hex mode
fn update_initiator(
    conn: &Connection,
    id: u32,
    validator_pk: String,
    minipool_address: String,
) -> DbResult<usize> {
    conn.execute(
        "UPDATE initiators SET validator_pk = ?1, minipool_address = ?2 WHERE id = ?3",
        params![validator_pk, minipool_address, id],
    )
}

fn insert_validator(conn: &mut Connection, validator: Validator) {
    match conn.transaction() {
        Ok(mut tx) => {
            tx.set_drop_behavior(DropBehavior::Commit);
            if let Err(e) = &tx.execute(
                "INSERT INTO validators(public_key, id, owner_address) values(?1, ?2, ?3)",
                params![
                    hex::encode(&validator.public_key),
                    validator.id.to_string(),
                    format!("{0:0x}", validator.owner_address)
                ],
            ) {
                error!("Can't insert into validators, error: {} {:?}", e, validator);
                let _ = &tx.set_drop_behavior(DropBehavior::Rollback);
            }

            for operator_id in &validator.releated_operators {
                if let Err(e) = &tx.execute("INSERT INTO validator_operators_mapping(validator_pk, operator_id) values(?1, ?2)", params![hex::encode(&validator.public_key), operator_id]) {
                    error!("Can't insert into validator_operators_mapping, error: {} operator_id {:?}", e, operator_id);
                    let _ = &tx.set_drop_behavior(DropBehavior::Rollback);
                    break;
                }
            }
            if let Err(e) = tx.finish() {
                error!("Can't finish the transaction {}", e);
            }
        }
        Err(e) => {
            error!("Can't create a transaction for database {}", e);
        }
    }
}

fn delete_operator(conn: &Connection, operator_id: u32) {
    if let Err(e) = conn.execute(
        "DELETE FROM operators WHERE operator_id = ?1",
        params![operator_id],
    ) {
        error!(
            "Can't delete from operators {} operator_id {}",
            e, operator_id
        );
    }
}

fn delete_validator(conn: &Connection, validator_pk: &str) {
    if let Err(e) = conn.execute(
        "DELETE FROM validators WHERE public_key = ?1",
        params![validator_pk],
    ) {
        error!(
            "Can't delete from validators {} validator_pk {}",
            e, validator_pk
        );
    }
}

fn query_operator_by_id(conn: &Connection, operator_id: &u32) -> DbResult<Option<Operator>> {
    match conn.prepare("SELECT id, name, address, public_key FROM WHERE id = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([operator_id])?;
            match rows.next()? {
                Some(row) => {
                    let address: String = row.get(2)?;
                    let public_key: String = row.get(3)?;
                    Ok(Some(Operator {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        address: Address::from_slice(&hex::decode(address).unwrap()),
                        public_key: base64::decode(public_key).unwrap().try_into().unwrap(),
                    }))
                }
                None => Ok(None),
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            Err(e)
        }
    }
}

// validator_pk is in hex
fn query_validator_by_public_key(
    conn: &Connection,
    validator_pk: &str,
) -> DbResult<Option<Validator>> {
    // select releated operators
    let mut releated_operators: Vec<u32> = Vec::new();
    match conn.prepare("SELECT operator_id from validator_operators_mapping where public_key = (?)")
    {
        Ok(mut stmt) => {
            let mut rows = stmt.query([validator_pk])?;
            while let Some(row) = rows.next()? {
                releated_operators.push(row.get(0)?);
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    };

    match conn.prepare(
        "SELECT public_key, id, owner_address, active FROM validators where public_key = (?)",
    ) {
        Ok(mut stmt) => {
            let mut rows = stmt.query([validator_pk])?;
            match rows.next()? {
                Some(row) => {
                    let public_key: String = row.get(0)?;
                    let owner_address: String = row.get(2)?;
                    let id: String = row.get(1)?;
                    Ok(Some(Validator {
                        public_key: hex::decode(&public_key).unwrap().try_into().unwrap(),
                        id: id.parse().unwrap(),
                        owner_address: Address::from_slice(&hex::decode(owner_address).unwrap()),
                        releated_operators: releated_operators,
                        active: row.get(3)?,
                    }))
                }
                None => Ok(None),
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            Err(e)
        }
    }
}

fn query_operators_public_key_by_ids(
    conn: &Connection,
    operator_ids: Vec<u32>,
) -> DbResult<Option<Vec<String>>> {
    let mut public_keys: Vec<String> = Vec::new();
    assert_ne!(operator_ids.len(), 0);
    for operator_id in operator_ids {
        match conn.prepare("SELECT public_key from operators where id = (?)") {
            Ok(mut stmt) => {
                let mut rows = stmt.query([operator_id])?;
                match rows.next()? {
                    Some(row) => public_keys.push(row.get(0)?),
                    None => {}
                }
            }
            Err(e) => {
                error!("Can't prepare statement {}", e);
                return Err(e);
            }
        }
    }
    match public_keys.len() {
        0 => Ok(None),
        _ => Ok(Some(public_keys)),
    }
}

fn query_operator_public_key_by_id(
    conn: &Connection,
    operator_id: u32,
) -> DbResult<Option<String>> {
    match conn.prepare("SELECT public_key from operators where id = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([operator_id])?;
            match rows.next()? {
                Some(row) => Ok(Some(row.get(0)?)),
                None => Ok(None),
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    }
}

fn query_initiator(conn: &Connection, id: u32) -> DbResult<Option<Initiator>> {
    match conn.prepare(
        "SELECT id, address, validator_pk, minipool_address from initiators where id = (?)",
    ) {
        Ok(mut stmt) => {
            let mut rows = stmt.query([id])?;
            match rows.next()? {
                Some(row) => {
                    let address: String = row.get(1)?;
                    let validator_pk: String = row.get(2)?;
                    let minipool_address: String = row.get(3)?;
                    let va_pk_option = if validator_pk.len() == 0 {
                        None
                    } else {
                        Some(hex::decode(&validator_pk).unwrap().try_into().unwrap())
                    };
                    let minipool_address_option = if minipool_address.len() == 0 {
                        None
                    } else {
                        Some(Address::from_slice(&hex::decode(minipool_address).unwrap()))
                    };

                    Ok(Some(Initiator {
                        id: row.get(0)?,
                        owner_address: Address::from_slice(&hex::decode(address).unwrap()),
                        releated_operators: vec![],
                        validator_pk: va_pk_option,
                        minipool_address: minipool_address_option,
                    }))
                }
                None => Ok(None),
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    }
}

fn query_initiator_releated_operator_pks(
    conn: &Connection,
    id: u32,
) -> DbResult<(Vec<String>, Vec<u32>)> {
    let mut op_pks = Vec::new();
    let mut op_ids: Vec<u32> = Vec::new();
    match conn.prepare("select public_key, id from operators where id in (select operator_id from initiator_operators_mapping where initiator_id = (?))") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([id])?;
            while let Some(row) = rows.next()? {
                op_pks.push(row.get(0)?);
                op_ids.push(row.get(1)?);
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    };
    Ok((op_pks, op_ids))
}

fn query_all_validator_address(conn: &Connection) -> DbResult<Vec<Address>> {
    let mut owners = Vec::new();
    match conn.prepare("select distinct owner_address from validators") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let address: String = row.get(0)?;
                owners.push(Address::from_slice(&hex::decode(&address).unwrap()));
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    }
    Ok(owners)
}

// only used for stop validator, don't need to query releated operator ids
fn query_validator_by_address(conn: &Connection, address: Address) -> DbResult<Vec<Validator>> {
    let mut validators = Vec::new();
    let address_str = format!("{0:0x}", address);
    match conn.prepare(
        "select public_key, id, owner_address, active from validators where owner_address = (?)",
    ) {
        Ok(mut stmt) => {
            let mut rows = stmt.query([address_str])?;

            while let Some(row) = rows.next()? {
                let public_key: String = row.get(0)?;
                let id: String = row.get(1)?;
                validators.push(Validator {
                    public_key: hex::decode(&public_key).unwrap().try_into().unwrap(),
                    id: id.parse().unwrap(),
                    owner_address: address,
                    releated_operators: vec![],
                    active: row.get(3)?,
                });
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
        }
    }
    Ok(validators)
}

fn disable_validator(conn: &Connection, public_key: String) {
    if let Err(e) = conn.execute(
        "UPDATE validators SET active = 0 WHERE public_key = ?1",
        params![public_key],
    ) {
        error!("Can't update validators {}, error {}", public_key, e);
    }
}

fn enable_validator(conn: &Connection, public_key: String) {
    if let Err(e) = conn.execute(
        "UPDATE validators SET active = 1 WHERE public_key = ?1",
        params![public_key],
    ) {
        error!("Can't update validators {}, error {}", public_key, e);
    }
}

fn if_validator_active(conn: &Connection, public_key: String) -> DbResult<bool> {
    match conn.prepare("select active from validators where public_key = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([public_key]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let active: bool = row.get(0).unwrap();
                return Ok(active);
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
        }
    };
    Ok(true)
}

fn increase_va_sequence(conn: &Connection, validator_or_initiator_id: u64) -> DbResult<u32> {
    let mut sequence_num: u32 = 0;
    match conn.prepare(
        "select sequence_num from contract_cmd_sequence where validator_or_initiator_id = (?)",
    ) {
        Ok(mut stmt) => {
            let mut rows = stmt.query([validator_or_initiator_id.to_string()]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                sequence_num = row.get(0).unwrap();
            }
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
        }
    }
    if sequence_num == 0 {
        if let Err(e) = conn.execute("insert into contract_cmd_sequence(validator_or_initiator_id, sequence_num) values (?1, ?2)", params![validator_or_initiator_id.to_string(), 1]) {
            error!("Can't insert into contract_cmd_sequence, error: {} {}", e, validator_or_initiator_id);
        }
    } else {
        if let Err(e) = conn.execute("update contract_cmd_sequence set sequence_num =?1 where validator_or_initiator_id = ?2", params![sequence_num + 1,validator_or_initiator_id.to_string()]) {
            error!("Can't update contract_cmd_sequence, error: {} {}", e, validator_or_initiator_id);
        }
    }
    Ok(sequence_num + 1)
}

fn delete_contract_command(conn: &Connection, id: u32) {
    if let Err(e) = conn.execute("delete from contract_commands where id = ?1", params![id]) {
        error!("Can't delete contract_commands, error: {} {}", e, id);
    }
}

fn insert_contract_command(conn: &Connection, validator_or_initiator_id: u64, command: String) {
    let sequence_num = increase_va_sequence(conn, validator_or_initiator_id).unwrap();
    if let Err(e) = conn.execute("insert into contract_commands(validator_or_initiator_id, sequence_num, command) values (?1, ?2, ?3)", params![validator_or_initiator_id.to_string(), sequence_num, command]) {
        error!("Can't insert into contract_commands, error: {} {}", e, validator_or_initiator_id);
    }
}

fn get_contract_command(conn: &Connection) -> DbResult<(String, u32)> {
    let mut command: String = String::new();
    let mut id: u32 = 0;
    // select the validator by update_time, and select a command with smallest sequence_num
    match conn.prepare("select id, command from contract_commands where validator_or_initiator_id = (select validator_or_initiator_id from contract_commands order by update_time asc limit 1) order by sequence_num asc limit 1") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                id = row.get(0).unwrap();
                command = row.get(1).unwrap();
                if let Err(e) = conn.execute("update contract_commands set id = ?1 where id = ?1", params![id]) {
                    error!("Can't update contract_commands, error: {} {}", e, id);
                }
            }
        },
        Err(e) => {
            error!("Can't select command {}", e);
        }
    }
    Ok((command, id))
}

fn updatetime_contract_command(conn: &Connection, id: u32) {
    if let Err(e) = conn.execute(
        "update contract_commands set id = ?1 where id = ?1",
        params![id],
    ) {
        error!("Can't update contract_commands, error: {} {}", e, id);
    }
}

fn delete_initiator(conn: &Connection, id: u32) -> DbResult<Option<Initiator>> {
    let initiator = query_initiator(conn, id)?;
    match initiator {
        Some(_) => {
            if let Err(e) = conn.execute("DELETE FROM initiators WHERE id = ?1", params![id]) {
                error!("Can't delete from initiators {} id {}", e, id);
            }
        }
        None => {
            error!("can't find initiator {} when delete it", id)
        }
    }
    Ok(initiator)
}

fn insert_initiator_store(conn: &mut Connection, record: InitiatorStoreRecord) {
    match conn.transaction() {
        Ok(mut tx) => {
            tx.set_drop_behavior(DropBehavior::Commit);
            if let Err(e) = &tx.execute("insert into initiator_store_record(initiator_id, share_bls_sk, validator_pk) values(?1, ?2, ?3)", params![&record.id, hex::encode(&record.share_bls_sk.serialize()), hex::encode(&record.validator_pk.serialize())]) {
                error!("can't  insert initiator store {} {}", record.id, e);
                let _ = &tx.set_drop_behavior(DropBehavior::Rollback);
            }
            let id = tx.last_insert_rowid();
            for (op_id, share_bls_pk) in &record.share_bls_pks {
                if let Err(e) = &tx.execute("insert into initiator_store_record_oppk(operator_id, share_bls_pk, record_id) values (?1, ?2, ?3)", params![op_id, hex::encode(&share_bls_pk.serialize()), id]) {
                    error!("can't  insert initiator store {} {}", record.id, e);
                    let _ = &tx.set_drop_behavior(DropBehavior::Rollback);
                }
            }
            if let Err(e) = tx.finish() {
                error!("Can't finish the transaction {}", e);
            }
        }
        Err(e) => {
            error!("Can't create a transaction for database {}", e);
        }
    }
}

fn query_initiator_store(
    conn: &Connection,
    initiator_id: u32,
) -> DbResult<Option<InitiatorStoreRecord>> {
    match conn.prepare("select A.share_bls_sk, A.validator_pk, B.operator_id, B.share_bls_pk from initiator_store_record as a join initiator_store_record_oppk as b on A.id = B.record_id where A.initiator_id =(?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([initiator_id]).unwrap();
            let mut op_pks: HashMap<u64, bls::PublicKey> = HashMap::new();
            let mut sk: Option<bls::SecretKey> = None;
            let mut va_pk: Option<bls::PublicKey> = None;
            while let Some(row) = rows.next().unwrap() {
                if sk.is_none() {
                    let share_bls_sk: String = row.get(0).unwrap();
                    let share_bls_sk = bls::SecretKey::deserialize(&hex::decode(share_bls_sk).unwrap()).unwrap();
                    sk = Some(share_bls_sk);
                }
                if va_pk.is_none() {
                    let validator_pk: String = row.get(1).unwrap();
                    let validator_pk = bls::PublicKey::deserialize(&hex::decode(validator_pk).unwrap()).unwrap();
                    va_pk = Some(validator_pk);
                }
                let operator_id: u64 = row.get(2).unwrap();
                let share_bls_pk: String = row.get(3).unwrap();
                let op_pk = bls::PublicKey::deserialize(&hex::decode(share_bls_pk).unwrap()).unwrap();
                op_pks.insert(operator_id, op_pk);
            }
            if sk.is_none() {
                return Ok(None);
            }
            Ok(Some(InitiatorStoreRecord { id: initiator_id, share_bls_sk: sk.unwrap(), validator_pk: va_pk.unwrap(), share_bls_pks: op_pks }))
        }
        Err(e) => {
            error!("Can't prepare statement {}", e);
            Err(e)
        }
    }
}

pub fn query_validators_fee_recipient<P: AsRef<Path>>(path: P) -> DbResult<Vec<(String, Address)>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("select public_key, owner_address from validators")?;
    let mut rows = stmt.query([]).unwrap();
    let mut res = Vec::new();
    while let Some(row) = rows.next()? {
        let validator_publickey: String = row.get(0)?;
        let address_str: String = row.get(1)?;
        let address: Address = Address::from_slice(&hex::decode(&address_str).unwrap());
        res.push((validator_publickey, address));
    }
    Ok(res)
}

#[tokio::test]
async fn test_database() {
    use crate::crypto::ThresholdSignature;
    use crate::node::contract::InitiatorStoreRecord;
    use std::collections::HashMap;
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();
    let mut sig = ThresholdSignature::new(3);
    let keys = sig.key_gen(&[1, 2, 3, 4]).unwrap();
    if std::fs::metadata("/tmp/test.db").is_ok() {
        std::fs::remove_file("/tmp/test.db").unwrap();
    }
    let _ = Database::new("/tmp/test.db").unwrap();
    let mut pks = HashMap::new();
    for (id, key_pair) in &keys.1 {
        pks.insert(*id, key_pair.pk.clone());
    }
    let initiator_store = InitiatorStoreRecord {
        id: 1,
        share_bls_sk: keys.0.sk.clone(),
        validator_pk: keys.0.pk.clone(),
        share_bls_pks: pks,
    };
    let mut conn = Connection::open("/tmp/test.db").unwrap();
    insert_initiator_store(&mut conn, initiator_store.clone());
    let record = query_initiator_store(&mut conn, 1).unwrap().unwrap();
    assert_eq!(
        record.share_bls_sk.serialize().as_bytes(),
        initiator_store.share_bls_sk.serialize().as_bytes()
    );
}
