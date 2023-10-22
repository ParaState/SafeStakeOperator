# Distributed Key Generation

Safestake implements the distributed key generation algorithm for BLS threshold signature introduced in [this paper](https://eprint.iacr.org/2019/985.pdf).

## Algorithm features
The algorithm generates a BLS secret key that is secret-shared among $n$ parties, with a security threshold of $t$, supporting $(t, n)$- BLS threshold signature. More details:
* The algorithm is completely distributed, hence no single party obtains the plain secret key.
* Our implementation supports different security options, against either passive adversary or active adversary (Default: active security).
* A $(3, 4)$-threshold instantiation means as long as there are 3 honest parties among 4 participants, then the security is guaranteed (i.e., tolerating at most $n-t$ malicious parties).

## Usage
Usage examples can be found in the rich tests of the code repository. A standard use case is shown [here](https://github.com/ParaState/SafeStakeOperator/blob/33df5533533436994b788d0cede34797c48e9e84/src/crypto/dkg.rs#L959).

## Unit / integration tests
You can run the DKG test with (active security):
```bash
cargo test test_dkg_secure_net -- --show-output
```