use rusqlite::{params, Connection, Result, OpenFlags, DropBehavior};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use log::{error};
use crate::node::contract::{Operator, Validator, Initializer};
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
    QueryOperatorPublicKeyByIds(Vec<u32>, oneshot::Sender<DbResult<Option<Vec<String>>>>),
    QueryOperatorPublicKeyById(u32, oneshot::Sender<DbResult<Option<String>>>),
    InsertInitializer(Initializer),
    UpdateInitializer(u32, String, String, oneshot::Sender<DbResult<usize>>),
    QueryInitializer(u32, oneshot::Sender<DbResult<Option<Initializer>>>),
    QueryInitializerReleaterOpPk(u32, oneshot::Sender<DbResult<(Vec<String>, Vec<u32>)>>)
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
            id BIGINT NOT NULL, 
            owner_address CHARACTER(40) NOT NULL
        )";

        let create_releation_sql = "CREATE TABLE IF NOT EXISTS validator_operators_mapping(
            id INTEGER NOT NULL  PRIMARY KEY AUTOINCREMENT,
            validator_pk CHARACTER(96) NOT NULL, 
            operator_id INTEGER NOT NULL,
            CONSTRAINT validator_select_operators_1 FOREIGN KEY (validator_pk) REFERENCES validators(public_key) ON DELETE CASCADE,
            CONSTRAINT validator_select_operators_2 FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
        )";

        let create_initializer_sql = "CREATE TABLE IF NOT EXISTS initializers(
            id INTEGER NOT NULL PRIMARY KEY,
            address CHARACTER(40) NOT NULL, 
            validator_pk CHARACTER(96),
            minipool_address CHARACTER(40)
        )";

        let create_initializer_releation_sql = "CREATE TABLE IF NOT EXISTS initializer_operators_mapping(
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            initializer_id INTEGER NOT NULL,
            operator_id INTEGER NOT NULL,
            CONSTRAINT initializer_select_operators_1 FOREIGN KEY (initializer_id) REFERENCES initializers(id) ON DELETE CASCADE,
            CONSTRAINT initializer_select_operators_2 FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
        )";

        conn.execute(create_operators_sql, [],)?;
        conn.execute(create_validators_sql, [],)?;
        conn.execute(create_releation_sql, [],)?;
        conn.execute(create_initializer_sql,[])?;
        conn.execute(create_initializer_releation_sql, [])?;
    
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
                        let response = query_operators_public_key_by_ids(&conn, operator_ids);
                        let _ = sender.send(response);
                    },
                    DbCommand::QueryOperatorPublicKeyById(operator_id, sender) => {
                        let response = query_operator_public_key_by_id(&conn, operator_id);
                        let _ = sender.send(response);
                    }
                    DbCommand::InsertInitializer(initializer) => {
                        insert_initializer(&mut conn, initializer);
                    },
                    DbCommand::UpdateInitializer(id, va_pk, minipool_address, sender) => {
                        let response = update_initializer(&conn, id, va_pk, minipool_address);
                        let _ = sender.send(response);
                    },
                    DbCommand::QueryInitializer(id, sender) => {
                        let response = query_initializer(&conn, id);
                        let _ = sender.send(response);
                    },
                    DbCommand::QueryInitializerReleaterOpPk(initializer_id, sender) => {
                        let response = query_initializer_releated_operator_pks(&conn, initializer_id);
                        let _ = sender.send(response);
                    }
                }
            }
        });
        Ok(Self { channel: tx})
    }

    pub async fn insert_operator(&self, operator: Operator) {
        if let Err(e) = self.channel.send(DbCommand::InsertOperator(operator)).await {
            panic!("Failed to send command to store: {}", e);
        }
    }

    pub async fn insert_validator(&self, validator: Validator) {
        if let Err(e) = self.channel.send(DbCommand::InsertValidator(validator)).await {
            panic!("Failed to send command to store: {}", e);
        }
    }

    pub async fn query_operator_by_id(&self, operator_id: u32) -> DbResult<Option<Operator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryOperatorById(operator_id, sender)).await {
            panic!("Failed to send command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query operator command from db")
    }

    pub async fn query_validator_by_public_key(&self, public_key: String) -> DbResult<Option<Validator>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryValidatorByPublicKey(public_key, sender)).await {
            panic!("Failed to send command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query validator command from db")
    }

    pub async fn query_operators_public_key_by_ids(&self, operator_ids: Vec<u32>) -> DbResult<Option<Vec<String>>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryOperatorPublicKeyByIds(operator_ids, sender)).await {
            panic!("Failed to send command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query operator command from db")
    }

    pub async fn query_operator_public_key_by_id(&self, operator_id: u32) -> DbResult<Option<String>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryOperatorPublicKeyById(operator_id, sender)).await {
            panic!("Failed to send command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query operator pk command from db")
    }

    pub async fn delete_validator(&self, validator_pk: String) {
        if let Err(e) = self.channel.send(DbCommand::DeleteValidator(validator_pk)).await {
            panic!("Failed to send command to store: {}", e);
        }
    }

    pub async fn delete_operator(&self, operator_id: u32) {
        if let Err(e) = self.channel.send(DbCommand::DeleteOperator(operator_id)).await {
            panic!("Failed to send delete operator command to store: {}", e);
        }
    }

    pub async fn insert_initializer(&self, initializer: Initializer) {
        if let Err(e) = self.channel.send(DbCommand::InsertInitializer(initializer)).await {
            panic!("Failed to insert insert initializer command to store: {}", e);
        }
    }

    pub async fn update_initializer(&self, id: u32, va_pk: String, minipool_address: String) -> DbResult<usize> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::UpdateInitializer(id, va_pk, minipool_address, sender)).await {
            panic!("Failed to send update initializer command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to update initializer command from db")
    }

    pub async fn query_initializer(&self, id: u32) -> DbResult<Option<Initializer>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryInitializer(id, sender)).await {
            panic!("Failed to send query initializer command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query initializer command from db")
    }

    pub async fn query_initializer_releated_op_pks(&self, id: u32) -> DbResult<(Vec<String>, Vec<u32>)> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(DbCommand::QueryInitializerReleaterOpPk(id, sender)).await {
            panic!("Failed to send query initializer command to store: {}", e);
        }
        receiver.await.expect("Failed to receive reply to query initializer command from db")
    }

}

fn insert_operator(conn: &Connection, operator: Operator) {
    if let Err(e) = conn.execute("INSERT INTO operators(id, name, address, public_key) values (?1, ?2, ?3, ?4)", params![&operator.id, &operator.name, format!("{0:0x}", operator.address), base64::encode(&operator.public_key)],) {
        error!("Can't insert into operators, error: {} {:?}", e, operator);
    }
}

fn insert_initializer(conn: &mut Connection, initializer: Initializer) {
    if let Err(e) = conn.execute("INSERT INTO initializers(id, address) values (?1, ?2)", params![initializer.id, format!("{0:0x}", initializer.owner_address), ]) {
        error!("Can't insert into initializer, error: {} {:?}", e, initializer);
    }
    match conn.transaction() {
        Ok(mut tx) => {
            tx.set_drop_behavior(DropBehavior::Commit);
            for operator_id in &initializer.releated_operators {
                if let Err(e) = &tx.execute("INSERT INTO initializer_operators_mapping(initializer_id, operator_id) values(?1, ?2)", params![initializer.id, operator_id], ) {
                    error!("Can't insert into initializer_operators_mapping, error: {} operator_id {:?} initializer {}", e, operator_id, initializer.id);
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

// validator_pk is in hex mode
fn update_initializer(conn: &Connection, id: u32, validator_pk: String, minipool_address: String) -> DbResult<usize> {
    conn.execute("UPDATE initializers SET validator_pk = ?1, minipool_address = ?2 WHERE id = ?3", params![validator_pk, minipool_address, id])
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

fn query_operators_public_key_by_ids(conn: &Connection, operator_ids: Vec<u32>) -> DbResult<Option<Vec<String>>> {
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

fn query_operator_public_key_by_id(conn: &Connection, operator_id: u32) -> DbResult<Option<String>> {
    match conn.prepare("SELECT public_key from operators where id = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([operator_id])?;
            match rows.next()? {
                Some(row) => {
                    Ok(Some(row.get(0)?))
                },
                None => {Ok(None)}
            }
        },
        Err(e) => {
            error!("Can't prepare statement {}", e);
            return Err(e);
        }
    }
}

fn query_initializer(conn: &Connection, id: u32) -> DbResult<Option<Initializer>> {
    match conn.prepare("SELECT id, address, validator_pk, minipool_address from initializers where id = (?)") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([id])?;
            match rows.next()? {
                Some(row) => { 
                    let address: String = row.get(1)?;
                    let validator_pk: String = row.get(2)?;
                    let minipool_address: String = row.get(3)?;
                    let va_pk_option = if validator_pk.len() == 0 { None } else {
                        Some(hex::decode(&validator_pk).unwrap().try_into().unwrap())
                    };
                    let minipool_address_option = if minipool_address.len() == 0 { None } else {
                        Some(Address::from_slice(&hex::decode(minipool_address).unwrap()))
                    };

                    Ok(Some(Initializer {
                        id: row.get(0)?,
                        owner_address: Address::from_slice(&hex::decode(address).unwrap()),
                        releated_operators: vec![],
                        validator_pk:  va_pk_option,
                        minipool_address: minipool_address_option
                    }))
                },
                None => { Ok(None) }
            }
        },
        Err(e) => { error!("Can't prepare statement {}", e); return Err(e); }
    }
}

fn query_initializer_releated_operator_pks(conn: &Connection, id: u32) -> DbResult<(Vec<String>, Vec<u32>) > {
    let mut op_pks = Vec::new();
    let mut op_ids: Vec<u32> = Vec::new();
    match conn.prepare("select public_key, id from operators where id in (select operator_id from initializer_operators_mapping where initializer_id = (?))") {
        Ok(mut stmt) => {
            let mut rows = stmt.query([id])?;
            match rows.next()? {
                Some(row) => {
                    op_pks.push(row.get(0)?);
                    op_ids.push(row.get(1)?);
                },  
                None => { }
            }
        },
        Err(e) => { error!("Can't prepare statement {}", e); return Err(e); }
    };
    Ok((op_pks,op_ids))
}