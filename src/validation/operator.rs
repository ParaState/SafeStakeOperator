use types::{Hash256, Signature, Keypair, PublicKey};
use std::sync::Arc;
use crate::utils::error::DvfError;
use network::{ReliableSender, SimpleSender, DvfMessage};
use std::net::SocketAddr;
use bytes::Bytes;
use std::collections::HashSet;
use downcast_rs::DowncastSync;
use futures::executor::block_on;
use tokio::sync::mpsc::{self, Receiver};
use std::time::Duration;
use tokio::time::timeout;
use crate::{DvfOperatorTsid,DvfCommitteeIndex};
pub enum OperatorMessage {
}

pub trait TOperator: DowncastSync + Sync + Send {
    fn sign(&self, msg: Hash256, index: DvfCommitteeIndex) -> Result<Signature, DvfError>; 
    fn public_key(&self) -> PublicKey;
    fn propose(&self, msg: Hash256, index: DvfCommitteeIndex);
    fn get_id(&self) -> DvfOperatorTsid;
}
impl_downcast!(sync TOperator);

pub struct LocalOperator {
    pub id: u64,
    pub voting_keypair: Arc<Keypair>,
    pub send_channel: mpsc::UnboundedSender<OperatorMessage>,
    pub recv_channel: mpsc::UnboundedReceiver<OperatorMessage>, 
}

impl TOperator for LocalOperator {

    fn sign(&self, msg: Hash256, index: DvfCommitteeIndex) -> Result<Signature, DvfError> {
        Ok(self.voting_keypair.sk.sign(msg))
    }

    fn public_key(&self) -> PublicKey {
        self.voting_keypair.pk.clone()
    }

    fn propose(&self, msg: Hash256, index: DvfCommitteeIndex) {
        // TODO add transaction port for local operator
        let transaction_address = format!("127.0.0.1:{}", 25_000).parse().unwrap();
        let mut sender = SimpleSender::new();
        let dvf_message = DvfMessage { validator_id: index, message: msg.to_fixed_bytes().to_vec()};
        block_on(sender.send(transaction_address, Bytes::from(bincode::serialize(&dvf_message).unwrap())));
    }

    fn get_id(&self) -> DvfOperatorTsid {
        return self.id;
    }
}

impl LocalOperator {
    pub fn new(id: u64, keypair: Arc<Keypair>) -> Self {
        let (send_channel, recv_channel) = mpsc::unbounded_channel(); 
        Self {
            id,
            voting_keypair: keypair,
            send_channel,
            recv_channel
        }
    }
}

pub struct HotStuffOperator {
    pub voting_keypair: Arc<Keypair>,
    pub network: ReliableSender,
    pub signature_address: SocketAddr,
    // bls_signature: Option<BlsSignature>,
}

/// hotstuff remote operator
impl TOperator for HotStuffOperator {

    fn sign(&self, msg: Hash256, index: DvfCommitteeIndex) -> Result<Signature, DvfError> {
        Ok(self.voting_keypair.sk.sign(msg))
    }

    fn public_key(&self) -> PublicKey {
        self.voting_keypair.pk.clone()
    }

    fn propose(&self, msg: Hash256, index: DvfCommitteeIndex) {
    }
    fn get_id(&self) -> DvfOperatorTsid {
        return 0 as u64;
    }
}

impl HotStuffOperator {
    // pub fn new(keypair: Arc<Keypair>, address: SocketAddr) -> Self {
    //     Self {
    //         voting_keypair: keypair,
    //         network: ReliableSender::new(),
    //         signature_address: address
    //     }
    // }

    // pub async fn request_signature(&mut self, msg: Hash256) -> Option<BlsSignature> {
    //     let receiver = self.network.send(self.signature_address, Bytes::from(msg.to_fixed_bytes().to_vec())).await;
    //     match receiver.await {
    //         Ok(data) => {
    //             println!("got = {:?}", data);
    //             match bincode::deserialize::<BlsSignature>(&data) {
    //                 Ok(bls_signature) =>{
    //                     Some(bls_signature)
    //                 },
    //                 Err(e) => {
    //                     None
    //                 }
    //             }
    //         },
    //         Err(_) => {
    //             println!("the sender dropped");
    //             None
    //         }
    //     }
    // }

    // pub async fn propose(&mut self, msg: Hash256) {
    //     // prefix id is fixed 
    //     // update
    //     let validator_vec : Vec<u8>= vec![50; 88];
    //     let validator_id = String::from_utf8(validator_vec).unwrap();
    //     let mut prefix_msg : Vec<u8> = Vec::new();
    //     prefix_msg.extend(validator_id.into_bytes());
    //     prefix_msg.extend(msg.to_fixed_bytes().to_vec());
    //     self.network.send(self.address, Bytes::from(prefix_msg)).await;
    // }

    // pub async fn wait_signature(&mut self) -> Vec<SignatureInfo>{
    //     let mut received = 0;
    //     let mut ids = HashSet::<u32>::new();
    //     let mut res = Vec::new();
    //     loop {
    //         if let Some(signature_info) = self.rx_signature.recv().await {
    //             if ids.contains(&signature_info.id)  {
    //                 continue;
    //             } else {
    //                 ids.insert(signature_info.id);
    //                 res.push(signature_info);
    //                 received+=1;
    //             }
    //             if received == 10 {
    //                 break;
    //             }
                    
    //         }
    //     }
    //     res
    // }
}

pub struct RemoteOperator {
    pub id: u64,
    pub public_key: PublicKey,
    pub socket_address: SocketAddr,
}

impl TOperator for RemoteOperator {
    fn sign(&self, msg: Hash256, index: DvfCommitteeIndex) -> Result<Signature, DvfError> { 
        let timeout_mill :u64 = 1000;
        // Err(DvfError::Unknown)
        let mut sender = ReliableSender::new();
        let dvf_message = DvfMessage { validator_id: index, message: msg.to_fixed_bytes().to_vec()};
        let serialize_msg = bincode::serialize(&dvf_message).unwrap();
        for retry in 0..5 {
            let receiver = block_on(sender.send(self.socket_address, Bytes::from(serialize_msg.clone())));
            let result = block_on(timeout(Duration::from_millis(timeout_mill), receiver)); 
            match result {
                Ok(output) => {
                    match output {
                        Ok(data) => {
                           println!("got = {:?}", data); 
                            match bincode::deserialize::<Signature>(&data) {
                                Ok(bls_signature) =>{
                                    return Ok(bls_signature);
                                }
                                Err(e) => {
                                    println!("deserialize failed, retry...");
                                }
                            }
                        },
                        Err(e) => {
                            println!("recv is interrupted.");
                        }
                    }
                },
                Err(_) => {
                    println!("did not receive value within {} ms", timeout_mill);
                }
            }
        }
        Err(DvfError::Unknown)
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn propose(&self, msg: Hash256, index: DvfCommitteeIndex) {
        // TODO add transaction port for local operator
        let transaction_address = format!("127.0.0.1:{}", 25_000).parse().unwrap();
        let mut sender = SimpleSender::new();
        let dvf_message = DvfMessage { validator_id: index, message: msg.to_fixed_bytes().to_vec()};
        block_on(sender.send(transaction_address, Bytes::from(bincode::serialize(&dvf_message).unwrap())));
    }

    fn get_id(&self) -> DvfOperatorTsid {
        return self.id;
    }
}

impl RemoteOperator {
    pub fn new(id: u64, public_key: PublicKey, socket_address: SocketAddr) -> Self {
        Self {
            id,
            public_key: public_key,
            socket_address : socket_address
        }
    }

}

