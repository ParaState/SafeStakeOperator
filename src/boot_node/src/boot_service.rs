use crate::proto::bootnode_server::Bootnode;
use crate::proto::*;
use dvf_utils::VERSION;
use safestake_crypto::secp::PublicKey;
use safestake_database::SafeStakeDatabase;
use tonic::{Request, Response, Status};
pub struct BootService {
    pub db: SafeStakeDatabase,
}
use slashing_protection::NotSafe;

#[tonic::async_trait]
impl Bootnode for BootService {
    async fn query_node_address(
        &self,
        request: Request<QueryNodeAddressRequest>,
    ) -> Result<Response<QueryNodeAddressResponse>, Status> {
        let req = request.into_inner();
        if req.version != VERSION {
            return Err(Status::internal(format!(
                "version mismatch, expected {}, got {}",
                VERSION, req.version
            )));
        }
        if req.operator_public_key.len() != 33 {
            return Err(Status::internal(format!(
                "unkown format of node public key, length: {}",
                req.operator_public_key.len()
            )));
        }
        let node_public_key = PublicKey(req.operator_public_key.try_into().unwrap());

        match self.db.with_transaction(|txn| {
            let addr = self
                .db
                .query_operator_socket_address(txn, &node_public_key)?;
            let seq = self.db.query_operator_seq(txn, &node_public_key)?;
            Ok::<(std::net::SocketAddr, u64), NotSafe>((addr, seq))
        }) {
            Ok((addr, seq)) => Ok(Response::new(QueryNodeAddressResponse {
                address: bincode::serialize(&addr).unwrap(),
                seq,
            })),
            Err(_) => Err(Status::internal(format!(
                "node {} not found",
                node_public_key.base64()
            ))),
        }
    }
}
