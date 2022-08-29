use aes::Aes128;
use x25519_dalek_ng::{PublicKey};

use alloc::{string::String, vec::Vec};
use ccm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    consts::{U13, U8},
    Ccm,
};
use digest::{FixedOutput, Input};
use hkdf::Hkdf;
use serde_bytes::{ByteBuf, Bytes};
use sha2::Sha256;
use super::{cose, error::Error, Result};
use crate::cbor;


// length in bits
pub const CCM_KEY_LEN: usize = 128;
pub const CCM_NONCE_LEN: usize = 104;
pub const SALT_LENGTH : usize = 64;
pub const EDHOC_MAC :usize = 64;
pub const HASHFUNC_OUTPUT_LEN_BITS: usize = 256;
pub const CONNECTION_IDENTIFIER_LENGTH: usize = 8;



/// EDHOC `message_1`.
#[derive(Debug, PartialEq)]
pub struct Message1 {
    pub method: u8,
    pub suite: u8,
    pub pub_ek_i: Vec<u8>,
    pub c_i : Vec<u8>,
    pub ead_1: Option<Vec<u8>>,
}

/// Serializes EDHOC `message_1`.
pub fn serialize_message_1(msg: &Message1) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message

    match &msg.ead_1 { 
        Some(ead)=>  {
            let ead_cbor = serialize_ead(ead)?;
          //  let ead = &msg.ead.as_ref().unwrap();
            let raw_msg  = (
                msg.method,
                msg.suite,
                Bytes::new(&msg.pub_ek_i),
                Bytes::new(&msg.c_i),
                Bytes::new(&ead_cbor),
            );
    
            Ok(cbor::encode_sequence(raw_msg)?)
        },
        
        None => {
        let raw_msg  = (
            msg.method,
            msg.suite,
            Bytes::new(&msg.pub_ek_i),
            Bytes::new(&msg.c_i),
        );
        Ok(cbor::encode_sequence(raw_msg)?)}
    }
}

/// Deserializes EDHOC `message_1`, first it tries to serialize with ead, and then without
pub fn deserialize_message_1(msg: &[u8]) -> Result<Message1> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
        

    
        match cbor::decode_sequence(msg, 5, &mut temp) {
            Ok(x) => {
                let raw_msg : (u8, u8, ByteBuf, ByteBuf, ByteBuf) = x;
                let ead_1 = deserialize_ead(&raw_msg.4.into_vec())?;
                Ok(Message1 {
                    method: raw_msg.0,
                    suite: raw_msg.1,
                    pub_ek_i: raw_msg.2.into_vec(),
                    c_i : raw_msg.3.into_vec(),
                    ead_1: Some(ead_1),
                })
            }
            _ => {
                let mut temp = Vec::with_capacity(msg.len() + 1);
                let raw_msg : (u8, u8, ByteBuf, ByteBuf)= cbor::decode_sequence(msg, 4, &mut temp)?;

                Ok(Message1 {
                    method: raw_msg.0,
                    suite: raw_msg.1,
                    pub_ek_i: raw_msg.2.into_vec(),
                    c_i : raw_msg.3.into_vec(),
                    ead_1: None,
                })

            }
        }
    




}
/// Serializes EDHOC `message_1`.
pub fn serialize_ead(ead: &[u8]) -> Result<Vec<u8>> {
    // Pack the data into a structure that nicely serializes almost into
    // what we want to have as the actual bytes for the EDHOC message
    let ead_tup = (
        1,
        Bytes::new(ead),
    );
    
    Ok(cbor::encode_sequence(ead_tup)?)

}
/// Deserializes EDHOC `message_1`.
pub fn deserialize_ead(ead: &[u8]) -> Result<Vec<u8>> {
    let mut temp = Vec::with_capacity(ead.len() + 1);
    // Try to deserialize into our raw message format
    let raw_ead: (u8, ByteBuf) =
        cbor::decode_sequence(ead, 2, &mut temp)?;


    // On success, just move the items into the "nice" message structure

    Ok(raw_ead.1.into_vec())
}

/// EDHOC `message_2`.
/// * 
#[derive(Debug, PartialEq)]
pub struct Message2 {
    pub ephemeral_key_r: Vec<u8>,
    pub c_r: Vec<u8>,
    pub ciphertext_2: Vec<u8>,
}

/// Serializes EDHOC `message_2`.
pub fn serialize_message_2(msg: &Message2) -> Result<Vec<u8>> {
    let pubk_and_ciphertext = [&msg.ephemeral_key_r[..], &msg.ciphertext_2[..]].concat();

let encoded = (
    Bytes::new(&pubk_and_ciphertext),
    Bytes::new(&msg.c_r),


);
    Ok(cbor::encode_sequence(encoded)?)
}

/// Deserializes EDHOC `message_2`.
pub fn deserialize_message_2(msg: &[u8]) -> Result<Message2> { //Result<Message2>
    let mut temp = Vec::with_capacity(msg.len() + 1);
    // First, attempt to decode the variant without c_u
    let (key_and_cipher2,c_r, ) = cbor::decode_sequence::<(ByteBuf, ByteBuf)>(msg, 2, &mut temp)?;

            

    let ephemeral_key_r = &key_and_cipher2[..32];
    let ciphertext2 = &key_and_cipher2[32..];


    Ok(Message2 {
        ephemeral_key_r: ephemeral_key_r.to_vec(),
        c_r: c_r.to_vec(),
        ciphertext_2: ciphertext2.to_vec(),
        })


    
}

// derive_prk
//deriving PRK's from some salt, and a key (shared key)
pub fn extract_prk(
    salt: Option<&[u8]>, 
    ikm: &[u8]
) -> Result<(Vec<u8>, Hkdf<Sha256>)> {
    // This is the extract step, resulting in the pseudorandom key (PRK)
    let (prk, hkdf) = Hkdf::<Sha256>::extract(salt, ikm);
    let prk_array = prk.to_vec();

    Ok((prk_array,hkdf))
}
/// EDHOC `message_3`.
#[derive(Debug, PartialEq)]
pub struct Message3 {
    pub ciphertext: Vec<u8>,
}

/// Serializes EDHOC `message_3`.
pub fn serialize_message_3(msg: &Message3) -> Result<Vec<u8>> {
    Ok(cbor::encode(Bytes::new(&msg.ciphertext))?)

}

/// Deserializes EDHOC `message_3`.
pub fn deserialize_message_3(msg: &[u8]) -> Result<Message3> {


    let cpy = msg.to_vec();
    let ciphertext = cbor::decode::<ByteBuf>(&cpy)?;
    // If we managed this time, we can return the struct without c_v
    Ok(Message3 {
        ciphertext: ciphertext.into_vec(),
        })
    
}

#[derive(Debug, PartialEq)]
pub struct Message4 {
    pub ciphertext: Vec<u8>,
}

/// Serializes EDHOC `message_3`.
pub fn serialize_message_4(msg: &Message4) -> Result<Vec<u8>> {
    Ok(cbor::encode(Bytes::new(&msg.ciphertext))?)

}

/// Deserializes EDHOC `message_3`.
pub fn deserialize_message_4(msg: &[u8]) -> Result<Message4> {


    let cpy = msg.to_vec();
    let ciphertext = cbor::decode::<ByteBuf>(&cpy)?;
    // If we managed this time, we can return the struct without c_v
    Ok(Message4 {
        ciphertext: ciphertext.into_vec(),
        })
    
}

/// Returns the bytes of an EDHOC error message with the given text.
pub fn build_error_message(err_msg: &str) -> Vec<u8> {

    // Build a tuple for the sequence of items
    // (type, err_msg)
    let raw_msg = (-1, err_msg);


    // Try to serialize the message. If we fail for some reason, return a
    // valid, pregenerated error message saying as much.
    cbor::encode_sequence(raw_msg).unwrap_or_else(|_| {
        vec![
            0x20, 0x78, 0x22, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x77, 0x68,
            0x69, 0x6C, 0x65, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x69, 0x6E,
            0x67, 0x20, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x6D, 0x65, 0x73,
            0x73, 0x61, 0x67, 0x65,
        ]
    })
}

/// Returns the extracted message from the EDHOC error message.
pub fn extract_error_message(msg: &[u8]) -> Result<String> {
    // Try to deserialize into our raw message format
    let mut temp = Vec::with_capacity(msg.len() + 1);
    let (_, err_msg): (isize, String) =
        cbor::decode_sequence(msg, 2, &mut temp)?;

    Ok(err_msg)
}

/// Returns `Error::Edhoc` variant containing the error message, if the given
/// message was an EDHOC error message.
///
/// Use it by passing a received message to it, before trying to parse it.
pub fn fail_on_error_message(msg: &[u8]) -> Result<()> {
    match extract_error_message(msg) {
        // If we succeed, it really is an error message
        Ok(err_msg) => Err(Error::Edhoc(err_msg)),
        // If not, then we don't have an error message
        Err(_) => Ok(()),
    }
}
/*/// Simple prk generation function

pub fn HKDFextract(
    salt : Option<&[u8]>, 
    secret: &[u8],
) -> Result<(GenericArray<u8, 10::OutputSize>,Hkdf<Sha256>)> {

    // This is the extract step, resulting in the pseudorandom key (PRK)
    let (material, PRK) = Hkdf::extract(salt, secret);
    // Expand the PRK to the desired length output keying material (OKM)

    Ok((material,  PRK))
}*/
/// The `EDHOC-Key-Derivation` function.
///
/// # Arguments
/// * `algorithm_id` - The algorithm name, e.g. "IV-GENERATION" or COSE number
///   e.g. "10" for AES-CCM-16-64-128.
/// * `key_data_length` - The desired key length in bits.
/// * `other` - Typically a transcript hash.
/// * `prk` - The prk to use as input keying material.
pub fn edhoc_kdf(
    prk: &Hkdf<Sha256>,
    th: &[u8],
    label: &str,
    context: &[u8],
    key_data_length: usize,
    
) -> Result<Vec<u8>> {
    // We use the ECDH shared secret as input keying material

    // For the Expand step, take the COSE_KDF_Context structure as info
    let info = (
        label,
        Bytes::new(context),
        key_data_length,
    );
    let mut seq = th.to_vec();
    let info_encoded =  cbor::encode_sequence(info)?;
    seq.extend(&info_encoded);
    

    // Expand the PRK to the desired length output keying material (OKM)
    let mut okm = vec![0; key_data_length];

    prk.expand(&seq, &mut okm)?;



    Ok(okm)
}


///Function for creating MAC tags for messages
///
/// # Arguments
/// * `PRK` - the prk used to create tag
/// * `maclength`  mac length given by cipher suite
/// * `th` transcript hash
/// * `id_cred_x` 
/// * `cred_x` 
/// 

pub fn create_mac_with_kdf(
    prk: &Hkdf<Sha256>,
    maclength: usize,
    th: &[u8],
    mac_identifier : &str,
    id_cred_x : Vec<u8>,
    cred_x : Vec<u8>,
    ead : &Option<Vec<u8>>,
) -> Result<Vec<u8>> {

    // prepare context
    let mut context = Vec::new();
    context.extend(id_cred_x);
    context.extend(cred_x);
    match ead {
       Some(data) => context.extend(data),
       None => ()
    }
    edhoc_kdf(prk, th, mac_identifier,&context, maclength)

}



pub fn extract_expand(
    ikm: &[u8],
    salt: &[u8],
    label : &str,
    length : usize,
) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    

    let mut okm = vec![0;  length];
    hk.expand(label.as_bytes(), &mut okm)?;
    Ok(okm)
}


// Xor function, for message 2
pub fn xor(a : &[u8], b:&[u8]) -> Result<Vec<u8>>{

    let c =  a.iter()
      .zip(b.iter())
      .map(|(&x1, &x2)| x1 ^ x2)
      .collect();
 
      Ok(c)
 }
/// The `EDHOC-Exporter` interface.
///
/// # Arguments
/// * `label` - Chosen by the application.
/// * `length` - The length in bytes (chosen by the application).
/// * `th_4` - TH_4.
/// * `secret` - The ECDH shared secret to use as input keying material.
pub fn edhoc_exporter(
    prk_4: &Hkdf<Sha256>,
    th_4: &[u8],
    label: &str,
    context : &[u8],
    length: usize,
    
) -> Result<Vec<u8>> {
    edhoc_kdf(prk_4,th_4,label,context,length )
}

/// Calculates the transcript hash of the second message.
pub fn compute_th_2(
    message_1: Vec<u8>,
    c_r: &[u8],
    responder_ephemeral_pk: PublicKey,
) -> Result<Vec<u8>> {

    let mut msg_1_hash = h(&message_1)?;
    let pk_bytes = &responder_ephemeral_pk.to_bytes();

    let hash_data = cbor::encode_sequence((
        Bytes::new(pk_bytes),
        Bytes::new(c_r),
    ))?;
    msg_1_hash.extend(&hash_data);


    // Create a sequence of CBOR items from the data
    // Return the hash of this
    h(&msg_1_hash)
}

/// Calculates the transcript hash of the third message.
pub fn compute_th_3(
    th_2: &[u8],
    ciphertext_2: &[u8],
) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    let mut seq = Vec::new();
    // Add the items that are always present
    seq.extend(th_2);
    seq.extend(cbor::encode(Bytes::new(ciphertext_2))?);

    // Return the hash of this
    h(&seq)
}

/// Calculates the final transcript hash used for the `EDHOC-Exporter`.
pub fn compute_th_4(th_3: &[u8], ciphertext_3: &[u8]) -> Result<Vec<u8>> {
    // Create a sequence of CBOR items
    let mut seq = Vec::new();
    seq.extend(th_3);
    seq.extend(cbor::encode(Bytes::new(ciphertext_3))?);

    // Return the hash of this
    h(&seq)
}

/// Returns a CBOR bstr containing the hash of the input CBOR sequence.
fn h(seq: &[u8]) -> Result<Vec<u8>> {
    let mut sha256 = Sha256::default();
    sha256.input(seq);
    let hash: [u8; 32] = sha256.fixed_result().into();

    // Return the bstr encoding
    Ok(cbor::encode(Bytes::new(&hash))?)
}

/// Returns the CBOR bstr making up the plaintext of `message_i`.
pub fn build_plaintext(kid: &[u8], mac: &[u8],ead :Option<Vec<u8>>) -> Result<Vec<u8>> {
    match ead {
        Some(ead) => {
            Ok(cbor::encode_sequence((
                Bytes::new(kid),
                Bytes::new(mac),
                Bytes::new(&ead),
            ))?)
        },
        None =>  {
            Ok(cbor::encode_sequence((
                Bytes::new(kid),
                Bytes::new(mac),
            ))?)
        }
    }

}

/// Extracts and returns the `kid` and signature from the plaintext of
/// `message_i`, which consists of the kid value, a mac, and optionally external auth data
pub fn extract_plaintext(plaintext: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {

    let mut temp = Vec::with_capacity(plaintext.len() + 1);

    
    match cbor::decode_sequence(&plaintext, 2, &mut temp) {
        Ok(tup) => {
            let (kid,mac) : (ByteBuf, ByteBuf) = tup;
            Ok((kid.to_vec(), mac.into_vec(), None))
        },
        _=> {
            let (kid,mac,ead) : (ByteBuf, ByteBuf, ByteBuf)= cbor::decode_sequence(&plaintext, 3, &mut temp)?;
            Ok((kid.to_vec(), mac.into_vec(), Some(ead.into_vec())))

        }
    }

    
}

/// Encrypts and authenticates with AES-CCM-16-64-128.
///
/// DO NOT reuse the nonce with the same key.
pub fn aead_seal(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Initialize CCM mode
    let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(key));

    
    // Encrypt and place ciphertext & tag in dst_out_ct
    let dst_out_ct = ccm.encrypt(
        GenericArray::from_slice(nonce),
        Payload {
            aad: ad,
            msg: plaintext,
        },
    )?;
    Ok(dst_out_ct)
}

/// Decrypts and verifies with AES-CCM-16-64-128.
pub fn aead_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Initialize CCM mode
    let ccm: Ccm<Aes128, U8, U13> = Ccm::new(GenericArray::from_slice(key));
    // Verify tag, if correct then decrypt and place plaintext in dst_out_pt
    let dst_out_pt = ccm.decrypt(
        GenericArray::from_slice(nonce),
        Payload {
            aad: ad,
            msg: ciphertext,
        },
    )?;

    Ok(dst_out_pt)
}


#[cfg(test)]

mod tests {

use super::super::test_vectors::*;
use super::*;
#[test]



fn test_serialize_message_2() {


    let msg2 = Message2 {
        ephemeral_key_r : R_EPHEMERAL_PK.to_vec(),
        c_r : C_R.to_vec(),
        ciphertext_2 : CIPHERTEXT_2.to_vec(),
    };
    
    let serial = serialize_message_2(&msg2).unwrap();

    assert_eq!(serial,MSG2.to_vec());
}
#[test]

fn prk_generation() {
    let (prk_2e,_) = extract_prk(None, &SHARED_SECRET_0).unwrap();
    assert_eq!(prk_2e,PRK2E.to_vec());

    let (prk3e2m,_) = extract_prk(Some(&prk_2e), &SHARED_SECRET_1.to_vec()).unwrap();

    assert_eq!(prk3e2m, PRK3EM.to_vec());

    let (prk_4x3m,_) = extract_prk(Some(&prk3e2m), &SHARED_SECRET_2).unwrap();

    assert_eq!(prk_4x3m, PRK4XM.to_vec());
}

#[test]

fn mac_2() {
    let (prk_2e,_) = extract_prk(None, &SHARED_SECRET_0).unwrap();

    let (_,prk_3e2m_hkdf) = extract_prk(Some(&prk_2e), &SHARED_SECRET_1.to_vec()).unwrap();
    let id_cred_x = cose::build_id_cred_x(&[5]).unwrap();


    
    assert_eq!(id_cred_x, ID_CRED_R);


    let th_2 = h(&TH_2_RAW_INPUT).unwrap();


    assert_eq!(&th_2, &TH_2_CBOR);
    let mac_2 = create_mac_with_kdf(&prk_3e2m_hkdf, 
        EDHOC_MAC /8, 
        &th_2, 
        "MAC_2", 
        id_cred_x, 
        CRED_R.to_vec(),
        &None).unwrap();


    assert_eq!(mac_2, &MAC_2)
}
#[test]

fn plaintext() {
    let plain = build_plaintext(&[5], &MAC_2,None).unwrap();
    assert_eq!(plain,PLAINTEXT_2);
}
#[test]

fn master_secret() {
    let (prk_2e,_) = extract_prk(None, &SHARED_SECRET_0).unwrap();

    let (prk3e2m,_) = extract_prk(Some(&prk_2e), &SHARED_SECRET_1.to_vec()).unwrap();


    let (_,prk_4x3m_hkdf) = extract_prk(Some(&prk3e2m), &SHARED_SECRET_2).unwrap();

    let master_secret = edhoc_exporter(
        &prk_4x3m_hkdf,
        &TH_4_CBOR,
        "OSCORE_Master_Secret",
        b"",
        CCM_KEY_LEN/8, //going from bits to bytes
    ).unwrap();

    assert_eq!(master_secret,MASTER_SECRET);
}
#[test]

fn test_ead() {
    let ead = [1,2,3,4].to_vec();

    let ead_cbor = serialize_ead(&ead).unwrap();

    let ead_deser = deserialize_ead(&ead_cbor).unwrap();



    assert_eq!(ead,ead_deser);
}
#[test]

fn cipher3() {
    let cipher3 = aead_seal(&K_3, &IV_3, &P_3, &A_3).unwrap();


    assert_eq!(cipher3,CIPHERTEXT_3.to_vec());
}

}