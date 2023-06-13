use bls::Keypair;
use eth2_keystore::{
    default_kdf,
    json_keystore::{Kdf, Pbkdf2, Prf, Scrypt},
    Error, Keystore, KeystoreBuilder, DKLEN,
};
use std::fs::File;
use tempfile::tempdir;
use scrypt::{
  errors::{InvalidOutputLen, InvalidParams},
  scrypt, Params as ScryptParams,
};
use std::time::Instant;
use rand::Rng;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

const GOOD_PASSWORD: &[u8] = &[42, 42, 42];
const BAD_PASSWORD: &[u8] = &[43, 43, 43];


pub fn test1() {
  println!("Enter test1");

  let now = Instant::now();

  let keypair = Keypair::random();

  let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
      .unwrap()
      .build()
      .unwrap();
  println!("Keystore built. {:.2?}", now.elapsed());

  let now = Instant::now();
  let json = keystore.to_json_string().unwrap();
  let decoded = Keystore::from_json_str(&json).unwrap();
  assert_eq!(
      decoded.decrypt_keypair(BAD_PASSWORD).err().unwrap(),
      Error::InvalidPassword,
      "should not decrypt with bad password"
  );
  println!("Keystore decrypted with bad password. {:.2?}", now.elapsed());

  let now = Instant::now();
  assert_eq!(
      decoded.decrypt_keypair(GOOD_PASSWORD).unwrap().pk,
      keypair.pk,
      "should decrypt with good password"
  );
  println!("Keystore decrypted with good password. {:.2?}", now.elapsed());
}

// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
  if x == 0 {
      return 0;
  }
  31 - x.leading_zeros()
}


pub fn test2() -> Result<(), Error> {
  let now = Instant::now();
  let mut dk = [0 as u8; 32];
  let salt = rand::thread_rng().gen::<[u8; 32]>().to_vec();

  scrypt(
      GOOD_PASSWORD,
      &salt,
      &ScryptParams::new(log2_int(262144) as u8, 8, 1)
          .map_err(Error::ScryptInvalidParams)?,
      &mut dk,
  )
  .map_err(Error::ScryptInvaidOutputLen)?;
  println!("Scrypt kdf. {:.2?}", now.elapsed());
  
  Ok(())

}

pub fn test3() -> Result<(), Error> {
  let now = Instant::now();
  let mut dk = [0 as u8; 32];
  let salt = rand::thread_rng().gen::<[u8; 32]>().to_vec();

  pbkdf2::<Hmac<Sha256>>(
    GOOD_PASSWORD,
    &salt,
    262_144,
    &mut dk,
);
  println!("pbkdf2 kdf, 262_144 rounds. {:.2?}", now.elapsed());

  let now = Instant::now();
  pbkdf2::<Hmac<Sha256>>(
    GOOD_PASSWORD,
    &salt,
    4096,
    &mut dk,
);
  println!("pbkdf2 kdf, 4096 rounds. {:.2?}", now.elapsed());
  
  Ok(())

}

fn main() {
  test1();
  test2();
  test3();
}