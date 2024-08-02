#![allow(unused)]
pub mod interface_ops;
pub mod lang;

use crate::crypto::sign_ed25519::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stack entry enum
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum StackEntry {
    Op(OpCodes),
    Signature(Signature),
    PubKey(PublicKey),
    // TODO: This should probably be u64, as usize doesn't have a consistent range on all platforms
    Num(usize),
    Bytes(Vec<u8>),
}

/// Opcodes enum
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub enum OpCodes {
    // constants
    OP_0 = 0x00,
    OP_1 = 0x01,
    OP_2 = 0x02,
    OP_3 = 0x03,
    OP_4 = 0x04,
    OP_5 = 0x05,
    OP_6 = 0x06,
    OP_7 = 0x07,
    OP_8 = 0x08,
    OP_9 = 0x09,
    OP_10 = 0x0a,
    OP_11 = 0x0b,
    OP_12 = 0x0c,
    OP_13 = 0x0d,
    OP_14 = 0x0e,
    OP_15 = 0x0f,
    OP_16 = 0x10,
    // flow control
    OP_NOP = 0x20,
    OP_IF = 0x21,
    OP_NOTIF = 0x22,
    OP_ELSE = 0x23,
    OP_ENDIF = 0x24,
    OP_VERIFY = 0x25,
    OP_BURN = 0x26,
    // stack
    OP_TOALTSTACK = 0x30,
    OP_FROMALTSTACK = 0x31,
    OP_2DROP = 0x32,
    OP_2DUP = 0x33,
    OP_3DUP = 0x34,
    OP_2OVER = 0x35,
    OP_2ROT = 0x36,
    OP_2SWAP = 0x37,
    OP_IFDUP = 0x38,
    OP_DEPTH = 0x39,
    OP_DROP = 0x3a,
    OP_DUP = 0x3b,
    OP_NIP = 0x3c,
    OP_OVER = 0x3d,
    OP_PICK = 0x3e,
    OP_ROLL = 0x3f,
    OP_ROT = 0x40,
    OP_SWAP = 0x41,
    OP_TUCK = 0x42,
    // splice
    OP_CAT = 0x50,
    OP_SUBSTR = 0x51,
    OP_LEFT = 0x52,
    OP_RIGHT = 0x53,
    OP_SIZE = 0x54,
    // bitwise logic
    OP_INVERT = 0x60,
    OP_AND = 0x61,
    OP_OR = 0x62,
    OP_XOR = 0x63,
    OP_EQUAL = 0x64,
    OP_EQUALVERIFY = 0x65,
    // arithmetic
    OP_1ADD = 0x70,
    OP_1SUB = 0x71,
    OP_2MUL = 0x72,
    OP_2DIV = 0x73,
    OP_NOT = 0x74,
    OP_0NOTEQUAL = 0x75,
    OP_ADD = 0x76,
    OP_SUB = 0x77,
    OP_MUL = 0x78,
    OP_DIV = 0x79,
    OP_MOD = 0x7a,
    OP_LSHIFT = 0x7b,
    OP_RSHIFT = 0x7c,
    OP_BOOLAND = 0x7d,
    OP_BOOLOR = 0x7e,
    OP_NUMEQUAL = 0x7f,
    OP_NUMEQUALVERIFY = 0x80,
    OP_NUMNOTEQUAL = 0x81,
    OP_LESSTHAN = 0x82,
    OP_GREATERTHAN = 0x83,
    OP_LESSTHANOREQUAL = 0x84,
    OP_GREATERTHANOREQUAL = 0x85,
    OP_MIN = 0x86,
    OP_MAX = 0x87,
    OP_WITHIN = 0x88,
    // crypto
    OP_SHA3 = 0x90,
    OP_HASH256 = 0x91,
    OP_HASH256_V0 = 0x92,
    OP_HASH256_TEMP = 0x93,
    OP_CHECKSIG = 0x94,
    OP_CHECKSIGVERIFY = 0x95,
    OP_CHECKMULTISIG = 0x96,
    OP_CHECKMULTISIGVERIFY = 0x97,
    // smart data
    OP_CREATE = 0xa0,
    // reserved
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
}

impl OpCodes {
    /// Returns true if the opcode is a conditional
    pub fn is_conditional(&self) -> bool {
        matches!(
            self,
            OpCodes::OP_IF | OpCodes::OP_NOTIF | OpCodes::OP_ELSE | OpCodes::OP_ENDIF
        )
    }
}

/// Allows for string casting
impl fmt::Display for OpCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
