use secp256k1::{All, Secp256k1, SecretKey, PublicKey, ecdh};
use sha256::{digest_bytes};
use aes_gcm::{Aes128Gcm, Key, Nonce, Error};
use aes_gcm::aead::{Aead, NewAead};
use rand::Rng;

#[derive(PartialEq, Debug)]
pub struct Ciphertext {
    temp_pk: PublicKey,
    aes_ct: Vec<u8>, 
}

// `serde` lib inserts some bytes in the middle (e.g., for len of vector)
// and this might not be compatible across platform.
// What we need is simple, so I just implement serialize/deserialize by myself.
impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        [Vec::from(self.temp_pk.serialize()), self.aes_ct.clone()].concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let temp_pk = PublicKey::from_slice(&bytes[0..33]).unwrap();
        let aes_ct = Vec::from(&bytes[33..]);
        Self {
            temp_pk,
            aes_ct,
        }
    }
}

#[derive(Debug)]
pub struct Elgamal<R> {
	rng: R,
    secp: Secp256k1<All>,
}

impl<R> Elgamal<R>
where R: Rng {
	pub	fn new(rng: R) -> Self {
		Self {
			rng,
            secp: Secp256k1::new(),
		}
	}

}

impl<R> Elgamal<R>
where R: Rng {
    /// Generate a pair of secret key and  public key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut rng = rand::thread_rng(); 
    /// let mut elgamal = Elgamal::new(rng); 
    /// let (sk, pk) = elgamal.generate_key();
    /// ```
    pub fn generate_key(&mut self) -> (SecretKey, PublicKey) {
        let (sk, pk) = self.secp.generate_keypair(&mut self.rng);
        (sk, pk)
    }

    /// Encryption.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut rng = rand::thread_rng(); 
    /// let mut elgamal = Elgamal::new(rng); 
    /// let (_, pk) = elgamal.generate_key();
    /// let cipher = elgamal.encrypt("hello".as_bytes(), &pk);
    /// ```
    pub fn encrypt(&mut self, msg: &[u8], pk: &PublicKey) -> Result<Ciphertext, Error> {
        let (other_sk, other_pk) = self.secp.generate_keypair(&mut self.rng);

        let point = ecdh::shared_secret_point(&pk, &other_sk);
        let secret = hex::decode(digest_bytes(&point)).unwrap(); 

        let key = Key::from_slice(&secret.as_slice()[0..16]); 
        let cipher = Aes128Gcm::new(key);

        let mut nonce_bytes = vec![0u8; 12]; // 96-bit nonce
        self.rng.fill(&mut nonce_bytes[..]);
        let nonce = Nonce::from_slice(nonce_bytes.as_slice());

        let aes_ct = cipher.encrypt(nonce, msg)?;

        let _ = cipher.decrypt(nonce, aes_ct.as_slice());

        //nonce_bytes.extend_from_slice(aes_ct.as_slice());
        let aes_ct = [nonce_bytes, aes_ct].concat();
		
        Ok(Ciphertext {
            temp_pk: other_pk,
            aes_ct,
        })
    }

    /// Decryption.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the examples of `encrypt` 
    /// let result = elgamal.decrypt(&cipher, &sk); 
    /// ```

    pub fn decrypt(&mut self, ct: &Ciphertext, sk: &SecretKey) -> Result<Vec<u8>, Error> {

        let point = ecdh::shared_secret_point(&ct.temp_pk, sk);
        let secret = hex::decode(digest_bytes(&point)).unwrap();

        let key = Key::from_slice(&secret.as_slice()[0..16]); 
        let cipher = Aes128Gcm::new(key);

        let nonce_bytes = &ct.aes_ct.as_slice()[0..12];
        let nonce = Nonce::from_slice(nonce_bytes);

        let aes_ct = &ct.aes_ct.as_slice()[12..];
        cipher.decrypt(nonce, aes_ct) 
    }

}

