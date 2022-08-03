use criterion::{ criterion_group, criterion_main, BatchSize, Criterion};
use x25519_dalek_ng::{PublicKey, StaticSecret};
use edhoc::edhoc::{PartyI,PartyR};

pub const C_I : [u8;1] = [0xC];
pub const I_EPHEMEREAL_SK : [u8;32] = [0xB3,0x11,0x19,0x98,0xCB,0x3F,0x66,0x86,0x63,0xED,0x42,0x51,
                            0xC7,0x8B,0xE6,0xE9,0x5A,0x4D,0xA1,0x27,0xE4,0xF6,0xFE,0xE2,
                            0x75,0xE8,0x55,0xD8,0xD9,0xDF,0xD8,0xED];

pub const R_EPHEMEREAL_SK : [u8;32] = [0xBD,0x86,0xEA,0xF4,0x06,0x5A,0x83,0x6C,0xD2,0x9D,0x0F,0x06,
                            0x91,0xCA,0x2A,0x8E,0xC1,0x3F,0x51,0xD1,0xC4,0x5E,0x1B,0x43,0x72,
                            0xC0,0xCB,0xE4,0x93,0xCE,0xF6,0xBD];

pub const I_STATIC_SK : [u8;32] = [0xCF,0xC4,0xB6,0xED,0x22,0xE7,0x00,0xA3,0x0D,0x5C,0x5B,
                            0xCD,0x61,0xF1,0xF0,0x20,0x49,0xDE,0x23,0x54,0x62,0x33,
                            0x48,0x93,0xD6,0xFF,0x9F,0x0C,0xFE,0xA3,0xFE,0x04];
pub const I_STATIC_PK : [u8;32] = [0x4A,0x49,0xD8,0x8C,0xD5,0xD8,0x41,0xFA,0xB7,0xEF,0x98,
                            0x3E,0x91,0x1D,0x25,0x78,0x86,0x1F,0x95,0x88,0x4F,0x9F,0x5D,
                            0xC4,0x2A,0x2E,0xED,0x33,0xDE,0x79,0xED,0x77];
pub const R_STATIC_SK : [u8;32] = [0x52,0x8B,0x49,0xC6,0x70,0xF8,0xFC,0x16,0xA2,0xAD,0x95,
                                    0xC1,0x88,0x5B,0x2E,0x24,0xFB,0x15,0x76,0x22,0x72,0x79,
                                    0x2A,0xA1,0xCF,0x05,0x1D,0xF5,0xD9,0x3D,0x36,0x94];

pub const R_STATIC_PK : [u8;32]= [0xE6,0x6F,0x35,0x59,0x90,0x22,0x3C,0x3F,0x6C,0xAF,0xF8,
                        0x62,0xE4,0x07,0xED,0xD1,0x17,0x4D,0x07,0x01,0xA0,0x9E,
                        0xCD,0x6A,0x15,0xCE,0xE2,0xC6,0xCE,0x21,0xAA,0x50];


pub const MSG1 : [u8; 56]= [3, 0, 88, 32, 58, 169, 235, 50, 1, 179, 54, 123, 140, 139, 227, 141, 145, 229, 122, 43, 67, 62, 103, 136, 140, 134, 210, 172, 0, 106, 82, 8, 66, 237, 80, 55, 72, 1, 1, 2, 3, 2, 4, 5, 7, 74, 1, 72, 0, 1, 2, 3, 4, 5, 6, 7];
pub const MSG2 : [u8; 54] =  [88, 43, 37, 84, 145, 176, 90, 57, 137, 255, 45, 63, 254, 166, 32, 152, 170, 181, 124, 22, 15, 41, 78, 217, 72, 1, 139, 65, 144, 247, 209, 97, 130, 78, 128, 201, 78, 209, 162, 152, 175, 167, 147, 24, 130, 72, 0, 1, 2, 3, 4, 5, 6, 7];
pub const MSG3 :[u8; 20]= [83, 137, 199, 176, 205, 118, 70, 96, 152, 174, 94, 43, 21, 128, 212, 95, 156, 183, 206, 147];
pub const MSG4 : [u8;9]= [72, 24, 231, 31, 142, 53, 181, 161, 223];

pub const DEVEUI : [u8;8] = [0x1,1,2,3,2,4,5,7];
pub const APPEUI : [u8;8] = [0,1,2,3,4,5,6,7];
pub const KID_I : [u8;1] = [5];
pub const KID_R : [u8;1] = [0x10];







fn edhoc_detailed(c: &mut Criterion) {
    let mut buf = [0; 32];

    buf.copy_from_slice(&I_STATIC_SK);
    let i_static_sk = StaticSecret::from(buf);
    let pub_st_i = PublicKey::from(&i_static_sk);    


        let mut buf = [0; 32];

    buf.copy_from_slice(&R_STATIC_SK);
    let r_static_sk = StaticSecret::from(buf);
    let pub_st_r = PublicKey::from(&r_static_sk); 

    let mut group = c.benchmark_group("edhoc_detailed");



    group.bench_function("party_i_build", |b| {
        b.iter(|| {
            PartyI::new(
                DEVEUI.to_vec(),
                Some(APPEUI.to_vec()),
                I_EPHEMEREAL_SK,
                StaticSecret::from(I_STATIC_SK),
                pub_st_i,
                KID_I.to_vec(),

            )
        })
    });
  
    group.bench_function("msg1_generate", |b| {
        b.iter_batched(
            || {
                PartyI::new(
                    DEVEUI.to_vec(),
                    Some(APPEUI.to_vec()),
                    I_EPHEMEREAL_SK,
                    StaticSecret::from(I_STATIC_SK),
                    pub_st_i,
                    KID_I.to_vec(),
    
                )
            },
            |msg1_sender| msg1_sender.generate_message_1(3,0).unwrap(),
            BatchSize::SmallInput,
        )
    });

 
    group.bench_function("party_r_build", |b| {
        b.iter(|| {
            PartyR::new(
                R_EPHEMEREAL_SK,
                StaticSecret::from(R_STATIC_SK),
                pub_st_r,
                KID_R.to_vec(),

            )
        })
    });

    group.bench_function("msg1_handle", |b| {
        b.iter_batched(
            || {
                (
                    MSG1.to_vec(),
                    PartyR::new(
                        R_EPHEMEREAL_SK,
                        StaticSecret::from(R_STATIC_SK),
                        pub_st_r,
                        KID_R.to_vec(),
        
                    ),
                )
            },
            |(msg1_bytes, msg1_receiver)| {
                msg1_receiver.handle_message_1_ead(msg1_bytes).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg2_generate", |b| {
        b.iter_batched(
            || {
                let msg1_receiver = PartyR::new(
                    R_EPHEMEREAL_SK,
                    StaticSecret::from(R_STATIC_SK),
                    pub_st_r,
                    KID_R.to_vec(),
    
                );
                msg1_receiver.handle_message_1(MSG1.to_vec()).unwrap().0
            },
            |msg2_sender| msg2_sender.generate_message_2(APPEUI.to_vec(),None).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg2_extract", |b| {
        b.iter_batched(
            || {
                let msg1_sender = PartyI::new(
                    DEVEUI.to_vec(),
                    Some(APPEUI.to_vec()),
                    I_EPHEMEREAL_SK,
                    StaticSecret::from(I_STATIC_SK),
                    pub_st_i,
                    KID_I.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(3,0).unwrap();

                (MSG2.to_vec(), msg2_receiver)
            },
            |(msg2_bytes, msg2_receiver)| {
                msg2_receiver.unpack_message_2_return_kid(msg2_bytes).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg2_verify", |b| {
        b.iter_batched(
            || {
                let msg1_sender = PartyI::new(
                    DEVEUI.to_vec(),
                    Some(APPEUI.to_vec()),
                    I_EPHEMEREAL_SK,
                    StaticSecret::from(I_STATIC_SK),
                    pub_st_i,
                    KID_I.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(3,0).unwrap();
                let (_,_, msg2_verifier) = msg2_receiver
                    .unpack_message_2_return_kid(MSG2.to_vec())
                    .unwrap();
                msg2_verifier
            },
            |msg2_verifier| {
                msg2_verifier.verify_message_2(&R_STATIC_PK).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg3_generate", |b| {
        b.iter_batched(
            || {
                let msg1_sender = PartyI::new(
                    DEVEUI.to_vec(),
                    Some(APPEUI.to_vec()),
                    I_EPHEMEREAL_SK,
                    StaticSecret::from(I_STATIC_SK),
                    pub_st_i,
                    KID_I.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(3,0).unwrap();
                let (_,_, msg2_verifier) = msg2_receiver
                    .unpack_message_2_return_kid(MSG2.to_vec())
                    .unwrap();
                msg2_verifier.verify_message_2(&R_STATIC_PK).unwrap()
            },
            |msg3_sender| msg3_sender.generate_message_3(None).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg3_extract", |b| {
        b.iter_batched(
            || {
                let msg1_receiver = PartyR::new(
                    R_EPHEMEREAL_SK,
                    StaticSecret::from(R_STATIC_SK),
                    pub_st_r,
                    KID_R.to_vec(),
                );
                let msg2_sender = msg1_receiver
                    .handle_message_1(MSG1.to_vec())
                    .unwrap().0;
                let (_, msg3_receiver) =
                    msg2_sender.generate_message_2(APPEUI.to_vec(),None).unwrap();
                (MSG3.to_vec(), msg3_receiver)
            },
            |(msg3_bytes, msg3_receiver)| {
                msg3_receiver.unpack_message_3_return_kid(msg3_bytes).unwrap()
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("msg3_verify", |b| {
        b.iter_batched(
            || {
                    let msg1_receiver = PartyR::new(
                        R_EPHEMEREAL_SK,
                        StaticSecret::from(R_STATIC_SK),
                        pub_st_r,
                        KID_R.to_vec(),
                    );
                let msg2_sender = msg1_receiver
                    .handle_message_1(MSG1.to_vec())
                    .unwrap().0;
                let (_, msg3_receiver) =
                    msg2_sender.generate_message_2(APPEUI.to_vec(),None).unwrap();
                let (msg3_verifier, _i_kid) = msg3_receiver
                    .unpack_message_3_return_kid(MSG3.to_vec())
                    .unwrap();
                msg3_verifier
            },
            |msg3_verifier| {
                msg3_verifier.verify_message_3(&I_STATIC_PK).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg4_generate", |b| {
        b.iter_batched(
            || {
                let msg1_receiver = PartyR::new(
                    R_EPHEMEREAL_SK,
                    StaticSecret::from(R_STATIC_SK),
                    pub_st_r,
                    KID_R.to_vec(),
    
                );
                let (msg2_sender,_devui,_appeui) = msg1_receiver.handle_message_1_ead(MSG1.to_vec()).unwrap();
                let (_msg2_bytes,msg3_receiver) =  msg2_sender.generate_message_2(APPEUI.to_vec(),None).unwrap();
                let (msg3_verifier, _i_kid) = msg3_receiver
                .unpack_message_3_return_kid(MSG3.to_vec())
                .unwrap();
                let (msg4_sender, _as_sck, _as_rck, _as_rk) = msg3_verifier.verify_message_3(&I_STATIC_PK).unwrap();
                msg4_sender
            },
            |msg4_sender| msg4_sender.generate_message_4(None).unwrap(),
            BatchSize::SmallInput,
        )
    });
group.bench_function("msg4_verify", |b| {
    b.iter_batched(
        || {
                let msg1_sender = PartyI::new(
                    DEVEUI.to_vec(),
                    Some(APPEUI.to_vec()),
                    I_EPHEMEREAL_SK,
                    StaticSecret::from(I_STATIC_SK),
                    pub_st_i,
                    KID_I.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(3,0).unwrap();

                let (_r_kid, _deveui,msg2_verifier) = msg2_receiver
                    .unpack_message_2_return_kid(MSG2.to_vec())
                    .unwrap();
                let msg3_sender = msg2_verifier.verify_message_2(&R_STATIC_PK).unwrap();
                let (msg4_verifier,_msg3_bytes) = msg3_sender.generate_message_3(None).unwrap();

                msg4_verifier
        },
        |msg4_verifier| {
            msg4_verifier.handle_message_4(MSG4.to_vec()).unwrap()
        },
        BatchSize::SmallInput,
    )
});

}

criterion_group!(edhoc_benches, edhoc_detailed);
criterion_main!(edhoc_benches);
