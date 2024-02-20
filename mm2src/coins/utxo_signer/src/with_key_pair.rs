use crate::sign_common::{complete_tx, p2pk_spend_with_signature, p2pkh_spend_with_signature,
                         p2sh_spend_with_signature, p2wpkh_spend_with_signature};
use crate::Signature;
use chain::{Transaction as UtxoTx, TransactionInput};
use derive_more::Display;
use keys::bytes::Bytes;
use keys::KeyPair;
use mm2_err_handle::prelude::*;
use primitives::hash::H256;
use script::{Builder, Script, ScriptType, SignatureVersion, TransactionInputSigner, UnsignedTransactionInput};

pub const SIGHASH_ALL: u32 = 1;
pub const _SIGHASH_NONE: u32 = 2;
pub const SIGHASH_SINGLE: u32 = 3;

pub type UtxoSignWithKeyPairResult<T> = Result<T, MmError<UtxoSignWithKeyPairError>>;

#[derive(Debug, Display)]
pub enum UtxoSignWithKeyPairError {
    #[display(
        fmt = "{} script '{}' built from input key pair doesn't match expected prev script '{}'",
        script_type,
        script,
        prev_script
    )]
    MismatchScript {
        script_type: String,
        script: Script,
        prev_script: Script,
    },
    #[display(
        fmt = "Can't spend the UTXO with script = '{}'. This script format isn't supported",
        script
    )]
    UnspendableUTXO { script: Script },
    #[display(fmt = "Error signing using a private key")]
    ErrorSigning(keys::Error),
}

impl From<keys::Error> for UtxoSignWithKeyPairError {
    fn from(sign: keys::Error) -> Self { UtxoSignWithKeyPairError::ErrorSigning(sign) }
}

pub fn sign_tx(
    unsigned: TransactionInputSigner,
    key_pair: &KeyPair,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> UtxoSignWithKeyPairResult<UtxoTx> {
    let signed_inputs = unsigned
        .inputs
        .iter()
        .map(|input| {
            match input.prev_script.script_type() {
                ScriptType::WitnessKey => {
                    p2wpkh_spend(&unsigned, input, key_pair, SignatureVersion::WitnessV0, fork_id)
                },
                ScriptType::PubKeyHash => p2pkh_spend(&unsigned, input, key_pair, signature_version, fork_id),
                // All  ow spending legacy P2PK utxos.
                ScriptType::PubKey => p2pk_spend(&unsigned, input, key_pair, signature_version, fork_id),
                _ => MmError::err(UtxoSignWithKeyPairError::UnspendableUTXO {
                    script: input.prev_script.clone(),
                }),
            }
        })
        .collect::<UtxoSignWithKeyPairResult<_>>()?;
    Ok(complete_tx(unsigned, signed_inputs))
}

/// Creates signed input spending p2pk output
pub fn p2pk_spend(
    signer: &TransactionInputSigner,
    unsigned_input: &UnsignedTransactionInput,
    key_pair: &KeyPair,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> UtxoSignWithKeyPairResult<TransactionInput> {
    let script = Builder::build_p2pk(key_pair.public());
    if script != unsigned_input.prev_script {
        return MmError::err(UtxoSignWithKeyPairError::MismatchScript {
            script_type: "P2PK".to_owned(),
            script,
            prev_script: unsigned_input.prev_script.clone(),
        });
    }

    let signature = calc_and_sign_sighash(
        signer,
        unsigned_input,
        &script,
        key_pair,
        signature_version,
        SIGHASH_ALL,
        fork_id,
    )?;
    Ok(p2pk_spend_with_signature(unsigned_input, fork_id, signature))
}

/// Creates signed input spending p2pkh output
pub fn p2pkh_spend(
    signer: &TransactionInputSigner,
    unsigned_input: &UnsignedTransactionInput,
    key_pair: &KeyPair,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> UtxoSignWithKeyPairResult<TransactionInput> {
    let script = Builder::build_p2pkh(&key_pair.public().address_hash().into());
    if script != unsigned_input.prev_script {
        return MmError::err(UtxoSignWithKeyPairError::MismatchScript {
            script_type: "P2PKH".to_owned(),
            script,
            prev_script: unsigned_input.prev_script.clone(),
        });
    }

    let signature = calc_and_sign_sighash(
        signer,
        unsigned_input,
        &script,
        key_pair,
        signature_version,
        SIGHASH_ALL,
        fork_id,
    )?;
    Ok(p2pkh_spend_with_signature(
        unsigned_input,
        key_pair.public(),
        fork_id,
        signature,
    ))
}

/// Creates signed input spending hash time locked p2sh output
pub fn p2sh_spend(
    signer: &TransactionInputSigner,
    unsigned_input: &UnsignedTransactionInput,
    key_pair: &KeyPair,
    script_data: Script,
    redeem_script: Script,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> UtxoSignWithKeyPairResult<TransactionInput> {
    let signature = calc_and_sign_sighash(
        signer,
        unsigned_input,
        &redeem_script,
        key_pair,
        signature_version,
        SIGHASH_ALL,
        fork_id,
    )?;
    Ok(p2sh_spend_with_signature(
        unsigned_input,
        redeem_script,
        script_data,
        fork_id,
        signature,
    ))
}

/// Creates signed input spending p2wpkh output
pub fn p2wpkh_spend(
    signer: &TransactionInputSigner,
    unsigned_input: &UnsignedTransactionInput,
    key_pair: &KeyPair,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> UtxoSignWithKeyPairResult<TransactionInput> {
    let script_code = Builder::build_p2pkh(&key_pair.public().address_hash().into()); // this is the scriptCode by BIP-0143: for P2WPKH scriptCode is P2PKH
    let script_pub_key = Builder::build_p2wpkh(&key_pair.public().address_hash().into())?;
    if script_pub_key != unsigned_input.prev_script {
        return MmError::err(UtxoSignWithKeyPairError::MismatchScript {
            script_type: "P2WPKH".to_owned(),
            script: script_pub_key,
            prev_script: unsigned_input.prev_script.clone(),
        });
    }

    let signature = calc_and_sign_sighash(
        signer,
        unsigned_input,
        &script_code,
        key_pair,
        signature_version,
        SIGHASH_ALL,
        fork_id,
    )?;
    Ok(p2wpkh_spend_with_signature(
        unsigned_input,
        key_pair.public(),
        fork_id,
        signature,
    ))
}

/// Calculates the input script hash and sign it using `key_pair`.
pub fn calc_and_sign_sighash(
    signer: &TransactionInputSigner,
    unsigned_input: &UnsignedTransactionInput,
    output_script: &Script,
    key_pair: &KeyPair,
    signature_version: SignatureVersion,
    sighash_type: u32,
    fork_id: u32,
) -> UtxoSignWithKeyPairResult<Signature> {
    let sighash = signature_hash_to_sign(
        signer,
        unsigned_input,
        output_script,
        signature_version,
        sighash_type,
        fork_id,
    );
    sign_message(&sighash, key_pair)
}

pub fn signature_hash_to_sign(
    signer: &TransactionInputSigner,
    unsigned_input: &UnsignedTransactionInput,
    output_script: &Script,
    signature_version: SignatureVersion,
    sighash_type: u32,
    fork_id: u32,
) -> H256 {
    let sighash_type = sighash_type | fork_id;
    signer.signature_hash(
        unsigned_input,
        output_script,
        signature_version,
        sighash_type,
    )
}

fn sign_message(message: &H256, key_pair: &KeyPair) -> UtxoSignWithKeyPairResult<Bytes> {
    let signature = key_pair.private().sign(message)?;
    Ok(Bytes::from(signature.to_vec()))
}
