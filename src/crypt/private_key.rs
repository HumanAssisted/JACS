// use secrecy::{CloneableSecret, DebugSecret, Secret, Zeroize};

// #[derive(Clone)]
// pub struct PrivateKey(Vec<u8>);

// impl Zeroize for PrivateKey {
//     fn zeroize(&mut self) {
//         self.0.zeroize();
//     }
// }

// /// Permits cloning
// impl CloneableSecret for PrivateKey {}

// /// Provides a `Debug` impl (by default `[[REDACTED]]`)
// impl DebugSecret for PrivateKey {}

// impl PrivateKey {
//     /// A method that operates on the private key.
//     /// This method is just an example; it prints the length of the private key.
//     /// Replace this with your actual cryptographic operation.
//     pub fn use_secret(&self) -> Vec<u8> {
//         decrypt_private_key(&self.0).expect("use_secret decrypt failed")
//     }
// }


// // impl PrivateKey {
// //     pub fn with_secret<F, R>(&self, f: F) -> R
// //     where
// //         F: FnOnce(&[u8]) -> R,
// //     {
// //         let decrypted_key = decrypt_private_key(&self.0).expect("use_secret decrypt failed");
// //         f(&decrypted_key)
// //     }
// // }


// /// Use this alias when storing secret values
// pub type SecretPrivateKey = Secret<PrivateKey>;