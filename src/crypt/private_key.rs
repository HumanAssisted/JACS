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
//     pub fn use_secret(&self) -> &Vec<u8> {
//         &self.0
//     }
// }