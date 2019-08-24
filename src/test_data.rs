pub const AUTH_U_P: [u8; 32] = [
    0x42, 0x4C, 0x75, 0x6A, 0xB7, 0x7C, 0xC6, 0xFD, 0xEC, 0xF0, 0xB3, 0xEC,
    0xFC, 0xFF, 0xB7, 0x53, 0x10, 0xC0, 0x15, 0xBF, 0x5C, 0xBA, 0x2E, 0xC0,
    0xA2, 0x36, 0xE6, 0x65, 0x0C, 0x8A, 0xB9, 0xC7,
];
pub const KID_U: [u8; 1] = [0xA2];
pub const ID_CRED_U: [u8; 4] = [0xA1, 0x04, 0x41, 0xA2];
pub const CRED_U: [u8; 40] = [
    0xA3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x42, 0x4C, 0x75, 0x6A,
    0xB7, 0x7C, 0xC6, 0xFD, 0xEC, 0xF0, 0xB3, 0xEC, 0xFC, 0xFF, 0xB7, 0x53,
    0x10, 0xC0, 0x15, 0xBF, 0x5C, 0xBA, 0x2E, 0xC0, 0xA2, 0x36, 0xE6, 0x65,
    0x0C, 0x8A, 0xB9, 0xC7,
];
pub const AUTH_V_P: [u8; 32] = [
    0x1B, 0x66, 0x1E, 0xE5, 0xD5, 0xEF, 0x16, 0x72, 0xA2, 0xD8, 0x77, 0xCD,
    0x5B, 0xC2, 0x0F, 0x46, 0x30, 0xDC, 0x78, 0xA1, 0x14, 0xDE, 0x65, 0x9C,
    0x7E, 0x50, 0x4D, 0x0F, 0x52, 0x9A, 0x6B, 0xD3,
];
pub const KID_V: [u8; 1] = [0xA3];
pub const ID_CRED_V: [u8; 4] = [0xA1, 0x04, 0x41, 0xA3];
pub const CRED_V: [u8; 40] = [
    0xA3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20, 0x1B, 0x66, 0x1E, 0xE5,
    0xD5, 0xEF, 0x16, 0x72, 0xA2, 0xD8, 0x77, 0xCD, 0x5B, 0xC2, 0x0F, 0x46,
    0x30, 0xDC, 0x78, 0xA1, 0x14, 0xDE, 0x65, 0x9C, 0x7E, 0x50, 0x4D, 0x0F,
    0x52, 0x9A, 0x6B, 0xD3,
];

pub const TYPE: isize = 1;
pub const SUITE: isize = 0;
pub const X_U: [u8; 32] = [
    0xB1, 0xA3, 0xE8, 0x94, 0x60, 0xE8, 0x8D, 0x3A, 0x8D, 0x54, 0x21, 0x1D,
    0xC9, 0x5F, 0x0B, 0x90, 0x3F, 0xF2, 0x05, 0xEB, 0x71, 0x91, 0x2D, 0x6D,
    0xB8, 0xF4, 0xAF, 0x98, 0x0D, 0x2D, 0xB8, 0x3A,
];
pub const C_U: [u8; 1] = [0xC3];
pub const MESSAGE_1: [u8; 38] = [
    0x01, 0x00, 0x58, 0x20, 0xB1, 0xA3, 0xE8, 0x94, 0x60, 0xE8, 0x8D, 0x3A,
    0x8D, 0x54, 0x21, 0x1D, 0xC9, 0x5F, 0x0B, 0x90, 0x3F, 0xF2, 0x05, 0xEB,
    0x71, 0x91, 0x2D, 0x6D, 0xB8, 0xF4, 0xAF, 0x98, 0x0D, 0x2D, 0xB8, 0x3A,
    0x41, 0xC3,
];

pub const X_V: [u8; 32] = [
    0x8D, 0xB5, 0x77, 0xF9, 0xB9, 0xC2, 0x74, 0x47, 0x98, 0x98, 0x7D, 0xB5,
    0x57, 0xBF, 0x31, 0xCA, 0x48, 0xAC, 0xD2, 0x05, 0xA9, 0xDB, 0x8C, 0x32,
    0x0E, 0x5D, 0x49, 0xF3, 0x02, 0xA9, 0x64, 0x74,
];
pub const C_V: [u8; 1] = [0xC4];
pub const TH_2_INPUT: [u8; 74] = [
    0x01, 0x00, 0x58, 0x20, 0xB1, 0xA3, 0xE8, 0x94, 0x60, 0xE8, 0x8D, 0x3A,
    0x8D, 0x54, 0x21, 0x1D, 0xC9, 0x5F, 0x0B, 0x90, 0x3F, 0xF2, 0x05, 0xEB,
    0x71, 0x91, 0x2D, 0x6D, 0xB8, 0xF4, 0xAF, 0x98, 0x0D, 0x2D, 0xB8, 0x3A,
    0x41, 0xC3, 0x58, 0x20, 0x8D, 0xB5, 0x77, 0xF9, 0xB9, 0xC2, 0x74, 0x47,
    0x98, 0x98, 0x7D, 0xB5, 0x57, 0xBF, 0x31, 0xCA, 0x48, 0xAC, 0xD2, 0x05,
    0xA9, 0xDB, 0x8C, 0x32, 0x0E, 0x5D, 0x49, 0xF3, 0x02, 0xA9, 0x64, 0x74,
    0x41, 0xC4,
];
pub const TH_2: [u8; 34] = [
    0x58, 0x20, 0x55, 0x50, 0xB3, 0xDC, 0x59, 0x84, 0xB0, 0x20, 0x9A, 0xE7,
    0x4E, 0xA2, 0x6A, 0x18, 0x91, 0x89, 0x57, 0x50, 0x8E, 0x30, 0x33, 0x2B,
    0x11, 0xDA, 0x68, 0x1D, 0xC2, 0xAF, 0xDD, 0x87, 0x03, 0x55,
];
