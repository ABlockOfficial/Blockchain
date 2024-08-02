use crate::crypto::sign_ed25519::{self as sign};
use crate::primitives::asset::Asset;
use crate::primitives::{
    asset::TokenAmount,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use crate::script::lang::Script;
use crate::utils::transaction_utils::{construct_address, construct_tx_in_out_signable_hash};
use std::collections::BTreeMap;

/// Generate a transaction with valid Script values
/// and accompanying UTXO set for testing a set of
/// transaction inputs and outputs.
///
/// ### Purpose:
///
/// The purpose of this utility function is to generate a transaction that
/// exhibits a valid Script, but may or may not contain invalid `genesis_hash` or amount
/// for a configuration of `TxIn`s and their corresponding `TxOut`s.
///
/// `Item` assets may **NOT** be on-spent if the `TxIn` value has a different
/// `genesis_hash` value than the ongoing `TxOut` value
///
/// ### Note:
///
/// When a `None` value is presented alongside an input amount, the asset is assumed
/// to be of type `Token`.
pub fn generate_tx_with_ins_and_outs_assets(
    input_assets: &[(u64, Option<&str>, Option<String>)], /* Input amount, genesis_hash, metadata */
    output_assets: &[(u64, Option<&str>)],                /* Input amount, genesis_hash */
) -> (BTreeMap<OutPoint, TxOut>, Transaction) {
    let (pk, sk) = sign::gen_keypair();
    let spk = construct_address(&pk);
    let mut tx = Transaction::new();
    let mut utxo_set: BTreeMap<OutPoint, TxOut> = BTreeMap::new();

    // Generate outputs
    for (output_amount, genesis_hash) in output_assets {
        let tx_out = match genesis_hash {
            Some(drs) => {
                let item = Asset::item(*output_amount, Some(drs.to_string()), None);
                TxOut::new_asset(spk.clone(), item, None)
            }
            None => TxOut::new_token_amount(spk.clone(), TokenAmount(*output_amount), None),
        };
        tx.outputs.push(tx_out);
    }

    // Generate inputs
    for (input_amount, genesis_hash, md) in input_assets {
        let tx_previous_out = OutPoint::new("tx_hash".to_owned(), tx.inputs.len() as i32);
        let tx_in_previous_out = match genesis_hash {
            Some(drs) => {
                let item = Asset::item(*input_amount, Some(drs.to_string()), md.clone());
                TxOut::new_asset(spk.clone(), item, None)
            }
            None => TxOut::new_token_amount(spk.clone(), TokenAmount(*input_amount), None),
        };
        let signable_hash = construct_tx_in_out_signable_hash(
            &TxIn {
                previous_out: Some(tx_previous_out.clone()),
                script_signature: Script::new(),
            },
            &tx.outputs,
        );
        let signature = sign::sign_detached(signable_hash.as_bytes(), &sk);
        let tx_in = TxIn::new_from_input(
            tx_previous_out.clone(),
            Script::pay2pkh(hex::decode(&signable_hash).unwrap(), signature, pk, None),
        );
        utxo_set.insert(tx_previous_out, tx_in_previous_out);
        tx.inputs.push(tx_in);
    }

    (utxo_set, tx)
}
