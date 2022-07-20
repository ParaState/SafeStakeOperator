use aes_gcm::{Aes128Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use secp256k1::{Secp256k1, SecretKey, PublicKey, ecdh};
use dvf::crypto::elgamal::{Elgamal, Ciphertext};
use sha256::{digest_bytes};

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

    let mut rng = rand::thread_rng();
   
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
    let mut rng = rand::thread_rng();

    let sk_bytes = hex::decode("d7bbda914fb72b1d9604be0e86a8d9149fe1418ec95e457aac280434779c162a").unwrap();
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
    let hash = digest_bytes(&hex::decode("e767757033da4644738412e4b580a700d59d40d94cf5c0f08dd76e81f70eee94").unwrap());
    println!("hash: {:?}", hash);
}

