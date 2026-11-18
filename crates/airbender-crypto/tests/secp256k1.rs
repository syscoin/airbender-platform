use airbender_crypto::secp256k1::recover;
use airbender_crypto::{
    k256::elliptic_curve::ops::Reduce,
    k256::{ecdsa::SigningKey, elliptic_curve::group::GroupEncoding, Scalar},
    sha3::Keccak256,
    MiniDigest,
};

use proptest::{
    arbitrary::Mapped,
    prelude::{any, Arbitrary, BoxedStrategy, Just, Strategy},
    prop_assert_eq, proptest,
};

fn random_signing_key() -> SigningKey {
    use rand_core::{OsRng, RngCore};

    loop {
        let mut candidate = [0; 32];
        OsRng.fill_bytes(&mut candidate);
        if let Ok(key) = SigningKey::from_slice(&candidate) {
            return key;
        }
    }
}

#[derive(Debug)]
struct Message(String);

impl Arbitrary for Message {
    type Parameters = ();

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<String>().prop_map(Message)
    }

    type Strategy = Mapped<String, Message>;
}

#[derive(Debug, Clone)]
struct PrivateKey(SigningKey);

impl Arbitrary for PrivateKey {
    type Parameters = ();

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        Just(PrivateKey(random_signing_key())).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[test]
fn selftest() {
    proptest!(|(message: Message, private_key: PrivateKey)| {
        let message = message.0;
        let private_key = private_key.0;
        let digest = {
            let mut hasher = Keccak256::new();
            hasher.update(&message);
            let res = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&res);
            hash_bytes
        };

        let public_key = private_key.verifying_key().as_affine();

        let (signature, recovery_id) = private_key.sign_prehash_recoverable(&digest);
        let msg = <Scalar as Reduce<airbender_crypto::k256::FieldBytes>>::reduce((&digest).into());

        let recovered_key = recover(&msg, &signature, &recovery_id).unwrap();

        prop_assert_eq!(recovered_key.to_bytes(), public_key.to_bytes());
    })
}
