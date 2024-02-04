use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes128Gcm, Error, Key, Nonce};
use rand::Rng;
use secp256k1::{ecdh, All, PublicKey, Secp256k1, SecretKey};
use sha256::digest;

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
        Self { temp_pk, aes_ct }
    }
}

#[derive(Debug)]
pub struct Elgamal<R> {
    rng: R,
    secp: Secp256k1<All>,
}

impl<R> Elgamal<R>
where
    R: Rng,
{
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            secp: Secp256k1::new(),
        }
    }
}

impl<R> Elgamal<R>
where
    R: Rng,
{
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
        let secret = hex::decode(digest(&point)).unwrap();

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
        let secret = hex::decode(digest(&point)).unwrap();

        let key = Key::from_slice(&secret.as_slice()[0..16]);
        let cipher = Aes128Gcm::new(key);

        let nonce_bytes = &ct.aes_ct.as_slice()[0..12];
        let nonce = Nonce::from_slice(nonce_bytes);

        let aes_ct = &ct.aes_ct.as_slice()[12..];
        cipher.decrypt(nonce, aes_ct)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ciphertext, Elgamal};
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes128Gcm, Key, Nonce};
    use secp256k1::SecretKey;
    use sha256::digest;

    #[test]
    fn test_aes() {
        let key_bytes = hex::decode("c4c7c5b5f76482c78f667a277c8bfacb").unwrap();
        let key = Key::from_slice(key_bytes.as_slice());
        let cipher = Aes128Gcm::new(key);

        let nonce_bytes = hex::decode("e3cf46d03a3239c65c2d50a1").unwrap();
        let nonce = Nonce::from_slice(nonce_bytes.as_slice());
        let ciphertext = hex::decode("43555fb3f1b4820cdc019c0792550444e2bf7ec85a").unwrap();

        let ct = cipher.encrypt(nonce, "hello".as_bytes()).unwrap();
        println!("my ct: {:?}", hex::encode(ct.as_slice()));

        let plain = cipher.decrypt(nonce, ciphertext.as_slice());
        let plain = match plain {
            Ok(value) => value,
            Err(e) => {
                println!("error: {:?}", e);
                return;
            }
        };

        println!("Message: {:?}", String::from_utf8(plain));
    }

    #[test]
    fn test_elgamal() {
        let rng = rand::thread_rng();

        let mut elgamal = Elgamal::new(rng);
        let (sk, pk) = elgamal.generate_key();
        let ct = elgamal.encrypt("hello".as_bytes(), &pk).unwrap();

        let ct_bytes = ct.to_bytes();
        println!("ct {}", ct_bytes.len());
        let ct2 = Ciphertext::from_bytes(ct_bytes.as_slice());

        let plain = elgamal.decrypt(&ct2, &sk).unwrap();
        println!("Message: {:?}", String::from_utf8(plain));
    }

    #[test]
    fn test_elgamal_from_js_serialized() {
        let rng = rand::thread_rng();

        let sk_bytes =
            hex::decode("d7bbda914fb72b1d9604be0e86a8d9149fe1418ec95e457aac280434779c162a")
                .unwrap();
        println!("sk {}: {:?}", sk_bytes.len(), sk_bytes);
        // This is an encryption of 'hello' under the public key that corresponds to the above private key
        let ct_bytes = hex::decode("02fc986be28243bbcde76b80ef86cd0ca77b2a7083761930362882144c90c8c5ec500b4e44cdc0f7cb48f3258b5de50a30f61da8c40de6dfe06989cc3a39b72d79c0").unwrap();
        println!("ct {}: {:?}", ct_bytes.len(), ct_bytes);

        let mut elgamal = Elgamal::new(rng);
        let sk = SecretKey::from_slice(sk_bytes.as_slice()).unwrap();
        let ct = Ciphertext::from_bytes(ct_bytes.as_slice());

        let plain = elgamal.decrypt(&ct, &sk).unwrap();
        println!("Message: {:?}", String::from_utf8(plain));
    }

    #[test]
    fn test_hash() {
        let hash = digest(
            hex::decode("e767757033da4644738412e4b580a700d59d40d94cf5c0f08dd76e81f70eee94")
                .unwrap()
                .as_slice(),
        );
        println!("hash: {:?}", hash);
    }
}
