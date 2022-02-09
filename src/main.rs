use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyU, PartyV,
};
use rand::{rngs::StdRng, Rng,SeedableRng};

use x25519_dalek::{EphemeralSecret, PublicKey,StaticSecret};


use rand_core::{RngCore, OsRng, CryptoRng,};
fn main() {

    let v_static_priv : EphemeralSecret  = EphemeralSecret::new(OsRng);
    let v_static_pub = PublicKey::from(&v_static_priv);

    let v_auth_pub = [
        0x1B, 0x66, 0x1E, 0xE5, 0xD5, 0xEF, 0x16, 0x72, 0xA2, 0xD8, 0x77,
        0xCD, 0x5B, 0xC2, 0x0F, 0x46, 0x30, 0xDC, 0x78, 0xA1, 0x14, 0xDE,
        0x65, 0x9C, 0x7E, 0x50, 0x4D, 0x0F, 0x52, 0x9A, 0x6B, 0xD3,
    ];
    let u_auth_pub = [
        0x42, 0x4C, 0x75, 0x6A, 0xB7, 0x7C, 0xC6, 0xFD, 0xEC, 0xF0, 0xB3,
        0xEC, 0xFC, 0xFF, 0xB7, 0x53, 0x10, 0xC0, 0x15, 0xBF, 0x5C, 0xBA,
        0x2E, 0xC0, 0xA2, 0x36, 0xE6, 0x65, 0x0C, 0x8A, 0xB9, 0xC7,
    ];

    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut r : StdRng = StdRng::from_entropy();
    let u_priv = r.gen::<[u8;32]>();
    
    // Choose a connection identifier
    let u_c_u = [0x1].to_vec();
    // This is the keypair used to authenticate.
    // V must have the public key.
    let u_auth_priv = [
        0x53, 0x21, 0xFC, 0x01, 0xC2, 0x98, 0x20, 0x06, 0x3A, 0x72, 0x50,
        0x8F, 0xC6, 0x39, 0x25, 0x1D, 0xC8, 0x30, 0xE2, 0xF7, 0x68, 0x3E,
        0xB8, 0xE3, 0x8A, 0xF1, 0x64, 0xA5, 0xB9, 0xAF, 0x9B, 0xE3,
    ];
    let u_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyU::new(u_c_u, u_priv, &u_auth_priv, &u_auth_pub, u_kid);

        /*
    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(1).unwrap();

    // Party V ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by V
    let v_priv = [
        0x17, 0xCD, 0xC7, 0xBC, 0xA3, 0xF2, 0xA0, 0xBD, 0xA6, 0x0C, 0x6D,
        0xE5, 0xB9, 0x6F, 0x82, 0xA3, 0x62, 0x39, 0xB4, 0x4B, 0xDE, 0x39,
        0x7A, 0x38, 0x62, 0xD5, 0x29, 0xBA, 0x8B, 0x3D, 0x7C, 0x62,
    ];
    // Choose a connection identifier
    let v_c_v = [0xC4].to_vec();
    // This is the keypair used to authenticate.
    // U must have the public key.
    let v_auth_priv = [
        0x74, 0x56, 0xB3, 0xA3, 0xE5, 0x8D, 0x8D, 0x26, 0xDD, 0x36, 0xBC,
        0x75, 0xD5, 0x5B, 0x88, 0x63, 0xA8, 0x5D, 0x34, 0x72, 0xF4, 0xA0,
        0x1F, 0x02, 0x24, 0x62, 0x1B, 0x1C, 0xB8, 0x16, 0x6D, 0xA9,
    ];
    let v_kid = [0xA3].to_vec();

    let msg1_receiver =
        PartyV::new(v_c_v, v_priv, &v_auth_priv, &v_auth_pub, v_kid);
    // This is a case where we could cause an error, which we'd send to the
    // other party

*/
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
