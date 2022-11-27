use rusqlite::{params, Connection, Result, OpenFlags, DropBehavior};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use log::{error};
use crate::node::new_contract::{Operator, Validator};
use web3::types::Address;
use std::path::{Path};
pub type DbError = rusqlite::Error;
type DbResult<T> = Result<T, DbError>;

pub enum DbCommand {
    InsertOperator(Operator),
    InsertValidator(Validator),
    DeleteOperator(u32),    // delete operator by id
    DeleteValidator(String), // delete validator by pk
    QueryOperatorById(u32, oneshot::Sender<DbResult<Option<Operator>>>), // query operator by operator id
    QueryValidatorByPublicKey(String, oneshot::Sender<DbResult<Option<Validator>>>),
    QueryOperatorPublicKeyByIds(Vec<u32>, oneshot::Sender<DbResult<Option<Vec<String>>>>)
}

#[derive(Clone)]
pub struct Database {
    channel: Sender<DbCommand>,
}


impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> DbResult<Self> {
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_CREATE)?;

        // public_key is base64 encoded
        // address is in hex
        let create_operators_sql = "CREATE TABLE IF NOT EXISTS operators(
            id INTEGER PRIMARY KEY, 
            name TEXT NOT NULL, 
            address CHARACTER(40) NOT NULL, 
            publick_key VARCHAR(100) NOT NULL
        )";

        // public key is in hex
        // address is in hex
        let create_validators_sql = "CREATE TABLE IF NOT EXISTS validators(
            public_key CHARACTER(96) PRIMARY KEY,
            id BIGINT NOT NULL, 
            owner_address CHARACTER(40) NOT NULL
        )";

        let create_releation_sql = "CREATE TABLE IF NOT EXISTS validator_operators_mapping(
            id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
            validator_pk CHARACTER(96) NOT NULL, 
            operator_id INTEGER NOT NULL,
            KEY validator_pk(validator_pk),
            KEY operator_id(operator_id),
            CONSTRAINT validator_select_operators_1 FOREIGN KEY (validator_pk) REFERENCES validators(public_key) ON DELETE CASCADE,
            CONSTRAINT validator_select_operators_2 FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
        )";

        conn.execute(create_operators_sql, [],)?;
        conn.execute(create_validators_sql, [],)?;
        conn.execute(create_releation_sql, [],)?;
    
        let (tx, mut rx) = channel(1000);

        tokio::spawn(async move {
            while let Some(db_command) = rx.recv().await {
                match db_command {
                    DbCommand::InsertOperator(operator) => {
                        insert_operator(&conn, operator);
                    },
                    DbCommand::InsertValidator(validator) => {
                        insert_validator(&mut conn, validator)
                    },
                    DbCommand::DeleteOperator(operator_id) => {
                        delete_operator(&conn, operator_id)
                    },
                    DbCommand::DeleteValidator(validator_pk) => {
                        delete_validator(&conn, &validator_pk);
                    },
                    DbCommand::QueryOperatorById(operator_id, sender) => {
                        let response = query_operator_by_id(&conn, &operator_id);
                        let _ = sender.send(response);
                    },
                    DbCommand::QueryValidatorByPublicKey(validator_pk, sender) => {
                        let response = query_validator_by_public_key(&conn, &validator_pk);
                        let _ = sender.send(response);
                    },
                    DbCommand::QueryOperatorPublicKeyByIds(operator_ids, sender) => {
                        let response = query_operators_publick_key_by_ids(&conn, operator_ids);
                        let _ = sender.send(response);
                    }
                }
            }
        });
        Ok(Self { channel: tx})
    }

    pub async fn insert_operator(&self, operator: Operator) {
        if let Err(e) = self.channel.send(DbCommand::InsertOperator(operator)).await {
            panic!("Failed to send Insert operator command to store: {}", e);
        }
    }

    pub async fn insert_validator(&self, validator: Validator) {
        if let Err(e) = self.channel.send(DbCommand::InsertValidator(validator)).await {
            panic!("Failed to send Insert validator command to store: {}", e);
        }
    }

    pub async fn query_operator_by_id(&self, operator_id: u32) -> DbResult<Option<Operator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryOperatorById(operator_id, sender)).await {
            panic!("Failed to send query operator command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query operator command from db")
    }

    pub async fn query_validator_by_public_key(&self, public_key: String) -> DbResult<Option<Validator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryValidatorByPublicKey(public_key, sender)).await {
            panic!("Failed to send query operator command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query operator command from db")
    }

    pub async fn query_operators_publick_key_by_ids(&self, operator_ids: Vec<u32>) -> DbResult<Option<Vec<String>>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryOperatorPublicKeyByIds(operator_ids, sender)).await {
            panic!("Failed to send query operator command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query operator command from db")
    }

    pub async fn delete_validator(&self, validator_pk: String) {
        if let Err(e) = self.channel.send(DbCommand::DeleteValidator(validator_pk)).await {
            panic!("Failed to send query operator command to store: {}", e);
        }
    }

    pub async fn delete_operator(&self, operator_id: u32) {
        if let Err(e) = self.channel.send(DbCommand::DeleteOperator(operator_id)).await {
            panic!("Failed to send query operator command to store: {}", e);
        }
    }

}

fn insert_operator(conn: &Connection, operator: Operator) {
    if let Err(e) = conn.execute("INSERT INTO operators(id, name, address, public_key) values (?1, ?2, ?3, ?4)", params![&operator.id, &operator.name, format!("{0:0x}", operator.address), base64::encode(&operator.public_key)],) {
        error!("Can't insert into operators, error: {} {:?}", e, operator);
    }
}


fn insert_validator(conn: &mut Connection, validator: Validator) {
    if let Err(e) = conn.execute("INSERT INTO validators(public_key, id, owner_address) values(?1, ?2, ?3)", params![hex::encode(&validator.public_key), &validator.id, format!("{0:0x}", validator.owner_address)],) {
        error!("Can't insert into validators, error: {} {:?}", e, validator);
    }

    match conn.transaction() {
        Ok(mut tx) => {
            tx.set_drop_behavior(DropBehavior::Commit);
            for operator_id in &validator.releated_operators {
                if let Err(e) = &tx.execute("INSERT INTO validator_operators_mapping(validator_pk, operator_id) values(?1, ?2)", params![hex::encode(&validator.public_key), operator_id], ) {
                    error!("Can't insert into validator_operators_mapping, error: {} operator_id {:?}", e, operator_id);
                    let _ = &tx.set_drop_behavior(DropBehavior::Rollback);
                    break;
                }
            }
            if let Err(e) = tx.finish() {
                error!("Can't finish the transaction {}", e);
            }
        },
        Err(e) => {
            error!("Can't create a transaction for database {}", e);
        }
    }
}

fn delete_operator(conn: &Connection, operator_id: u32) {
    if let Err(e) = conn.execute("DELETE FROM operators WHERE operator_id = ?1", params![operator_id]) {
        error!("Can't delete from operators {} operator_id {}", e, operator_id);
    }
}

fn delete_validator(conn: &Connection, validator_pk: &str) {
    if let Err(e) = conn.execute("DELETE FROM validators WHERE public_key = ?1", params![validator_pk]) {
        error!("Can't delete from validators {} validator_pk {}", e, validator_pk);
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
                            id : row.get(0)?,
                            name: row.get(1)?,
                            address: Address::from_slice(&hex::decode(address).unwrap()),
                            public_key: base64::decode(public_key).unwrap().try_into().unwrap()
                    }))
                },
                None => { Ok(None) }
            }
        },
        Err(e) => {
            error!("Can't prepare statement {}", e);
            Err(e)
        }
    }
}

// validator_pk is in hex
fn query_validator_by_public_key(conn: &Connection, validator_pk: &str) -> DbResult<Option<Validator>> {
    // select releated operators
    let mut releated_operators: Vec<u32> = Vec::new();
    match conn.prepare("SELECT operator_id from validator_operators_mapping where public_key = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([validator_pk])?;
            while let Some(row) = rows.next()? {
                releated_operators.push(row.get(0)?);
            }
        },
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    };

    match conn.prepare("SELECT public_key, id, owner_address FROM validators where public_key = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([validator_pk])?;
            match rows.next()? {
                Some(row) => {
                    let public_key: String = row.get(0)?;
                    let owner_address: String = row.get(2)?;
                    Ok(Some(Validator{
                        public_key: hex::decode(&public_key).unwrap().try_into().unwrap(),
                        id: row.get(1)?,
                        owner_address: Address::from_slice(&hex::decode(owner_address).unwrap()),
                        releated_operators: releated_operators
                    }))
                },
                None => { Ok(None) }
            }
        },
        Err(e) => {
            error!("Can't prepare statement {}", e);
            Err(e)
        }
    }
}

fn query_operators_publick_key_by_ids(conn: &Connection, operator_ids: Vec<u32>) -> DbResult<Option<Vec<String>>> {
    let mut public_keys: Vec<String> = Vec::new();
    assert_ne!(operator_ids.len(), 0);
    for operator_id in operator_ids {
        match conn.prepare("SELECT public_key from operators where id = (?)") {
            Ok(mut stmt) => {
                let mut rows = stmt.query([operator_id])?;
                match rows.next()? {
                    Some(row) => {
                        public_keys.push(row.get(0)?)
                    },
                    None => {}
                }
            },
            Err(e) => {
                error!("Can't prepare statement {}", e);
                return Err(e);
            }
        }
    };
    match public_keys.len() {
        0 => Ok(None),
        _ => Ok(Some(public_keys))
    }
}