use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use error_stack::Result;
use multisig::key::{PublicKey, Signature};
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use num_bigint::BigUint;
use router_api::Message;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tonlib_core::cell::{Cell, CellBuilder, TonCellError};
use tonlib_core::tlb_types::tlb::TLB;
use tonlib_core::TonAddress;

use crate::error::ContractError;
use crate::payload::Payload;

const OP_APPROVE_MESSAGES: usize = 0x00000028;
const BYTES_PER_CELL: usize = 96;

fn build_cell_chain(start_index: usize, buffer: Vec<u8>) -> Result<Cell, ContractError> {
    let mut builder = CellBuilder::new();
    let end_index = std::cmp::min(start_index + BYTES_PER_CELL, buffer.len());

    // Store bytes in the current cell
    for i in start_index..end_index {
        builder
            .store_uint(8, &BigUint::from(buffer[i]))
            .map_err(|_| ContractError::TonError)?;
    }

    // If there are more bytes, create a reference to the next cell
    if end_index < buffer.len() {
        let next_cell = build_cell_chain(end_index, buffer)?;
        builder
            .store_reference(&Arc::new(next_cell))
            .map_err(|_| ContractError::TonError)?;
    }

    Ok(builder.build().map_err(|_| ContractError::TonError)?)
}

fn buffer_to_cell(buffer: Vec<u8>) -> Result<Cell, ContractError> {
    Ok(build_cell_chain(0, buffer)?)
}

#[derive(Clone, Debug)]
struct TonProof {
    dict: HashMap<u16, WeightedSigner>,
    threshold: u128,
    nonce: u128,
}

impl TonProof {
    pub fn new(set: &VerifierSet, signatures: Vec<SignerWithSig>) -> Self {
        let nonce = set.created_at as u128;
        let threshold = set.threshold.into();

        println!("nonce: {}", nonce);
        println!("threshold: {}", threshold);

        // todo: convert set.signers to HashMap<u16, WeightedSigner>,
        let dict: HashMap<u16, WeightedSigner> = set
            .signers
            .values()
            .enumerate()
            .map(|(i, signer)| {
                let pub_key_bytes = match &signer.pub_key {
                    PublicKey::Ed25519(key) => key.as_slice().try_into().unwrap(),
                    _ => todo!(),
                };
                let signature_bytes = match &signatures[i].signature {
                    Signature::Ed25519(sig) => sig.as_slice().try_into().unwrap(),
                    _ => todo!(),
                };
                (
                    i as u16,
                    WeightedSigner::new(pub_key_bytes, signer.weight.u128(), signature_bytes),
                )
            })
            .collect();

        TonProof {
            dict,
            threshold,
            nonce,
        }
    }

    pub fn to_cell(&self) -> Result<Cell, ContractError> {
        let key_len_bits = 16;
        let mut builder = CellBuilder::new();

        let nonce = BigUint::from(self.nonce);
        let threshold = BigUint::from(self.threshold);

        builder
            .store_dict(key_len_bits, val_writer_buffer, self.dict.clone())
            .map_err(|_| ContractError::TonError)?;
        builder
            .store_uint(128, &threshold)
            .map_err(|_| ContractError::TonError)?;
        builder
            .store_uint(256, &nonce)
            .map_err(|_| ContractError::TonError)?;
        let dict_cell = builder.build().map_err(|_| ContractError::TonError)?;

        Ok(dict_cell)
    }
}

#[derive(Clone, Debug, Copy)]
struct WeightedSigner {
    signer: [u8; 32],
    weight: u128,
    signature: [u8; 64],
}

impl WeightedSigner {
    pub fn new(signer: [u8; 32], weight: u128, signature: [u8; 64]) -> Self {
        WeightedSigner {
            signer,
            weight,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.signer);
        bytes.extend_from_slice(&self.weight.to_be_bytes());
        bytes.extend_from_slice(&self.signature);

        println!("bytes: {}", vec_to_hex(bytes.clone()));

        assert!(bytes.len() == 112);
        bytes
    }
}

// Custom value writer for WeightedSigner
fn val_writer_buffer(
    builder: &mut CellBuilder,
    val: WeightedSigner,
) -> std::result::Result<(), TonCellError> {
    builder.store_slice(&val.to_bytes())?;
    Ok(())
}

fn construct_proof(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
) -> Result<Cell, ContractError> {
    let proof = TonProof::new(verifier_set, signatures);
    Ok(proof.to_cell()?)
}

fn get_arced_cell(inner: &str) -> std::result::Result<Arc<Cell>, TonCellError> {
    Ok(Arc::new(
        buffer_to_cell(inner.as_bytes().to_vec())
            .map_err(|_| TonCellError::InvalidInput("test".to_owned()))?,
    ))
}

fn message_to_cell(msg: Message) -> std::result::Result<Cell, TonCellError> {
    let mut builder = CellBuilder::new();
    builder.store_reference(&get_arced_cell(&msg.cc_id.message_id)?)?;
    builder.store_reference(&get_arced_cell(&msg.cc_id.source_chain.to_string())?)?;
    builder.store_reference(&get_arced_cell(&msg.source_address)?)?;

    let ton_address_buffer = TonAddress::from_str(&msg.destination_address)
        .unwrap()
        .hash_part
        .to_vec();

    let ton_address_buffer_cell = buffer_to_cell(ton_address_buffer)
        .map_err(|_| TonCellError::InternalError("test".to_owned()))?;

    builder.store_reference(&Arc::new(ton_address_buffer_cell.clone()))?; // problem this should be the Ton address hash!!! .storeRef(bufferToCell(msg.executableAddress.hash))

    builder.store_uint(256, &BigUint::from_bytes_be(&msg.payload_hash))?;

    let res = builder.build()?;

    println!("Message: {:?} and in cell: {:?}\n", msg, res);
    println!("destination_address: {:?}", ton_address_buffer_cell);
    Ok(res)
}

// Custom value writer for WeightedSigner
fn val_writer_cell(
    builder: &mut CellBuilder,
    val: Message,
) -> std::result::Result<(), TonCellError> {
    builder.store_reference(&Arc::new(message_to_cell(val)?))?;
    Ok(())
}

#[derive(Debug)]
struct TonMessages {
    dict: HashMap<u16, Message>,
}

impl TonMessages {
    pub fn new(messages: &Vec<Message>) -> Self {
        let msgs_hashmap: HashMap<u16, Message> = messages
            .iter() // Changed from into_iter() to iter()
            .enumerate()
            .map(|(i, msg)| (i as u16, msg.clone())) // Added clone() since we're borrowing
            .collect();
        TonMessages { dict: msgs_hashmap }
    }

    pub fn to_cell(&self) -> Result<Cell, ContractError> {
        let key_len_bits = 16;
        let mut builder = CellBuilder::new();

        builder
            .store_dict(key_len_bits, val_writer_cell, self.dict.clone())
            .map_err(|_| ContractError::TonError)?;
        let dict_cell = builder.build().map_err(|_| ContractError::TonError)?;

        Ok(dict_cell)
    }
}

fn construct_messages(messages: &Vec<Message>) -> Result<Cell, ContractError> {
    let ton_msgs = TonMessages::new(messages);

    println!("ton_msgs: {:?}", ton_msgs);

    Ok(ton_msgs.to_cell()?)
}

fn build_approve_messages_body(
    messages: &Vec<Message>,
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
) -> Result<Cell, ContractError> {
    let proof = construct_proof(verifier_set, signatures)?;
    let messages = construct_messages(messages)?;

    let mut builder = CellBuilder::new();
    builder
        .store_uint(32, &BigUint::from(OP_APPROVE_MESSAGES))
        .map_err(|_| ContractError::TonError)?;
    builder
        .store_reference(&Arc::new(proof))
        .map_err(|_| ContractError::TonError)?;
    builder
        .store_reference(&Arc::new(messages))
        .map_err(|_| ContractError::TonError)?;

    Ok(builder.build().map_err(|_| ContractError::TonError)?)
}

fn build_signer_rotation_body(set: &VerifierSet) -> Result<Cell, ContractError> {
    todo!()
}

pub fn payload_digest(
    domain_separator: &Hash,
    verifier_set: &VerifierSet,
    payload: &Payload,
) -> Result<Hash, ContractError> {
    todo!()
}
fn vec_to_hex(vec: Vec<u8>) -> String {
    vec.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub fn encode_execute_data(
    verifier_set: &VerifierSet,
    signatures: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let cell_payload = match payload {
        Payload::Messages(msgs) => build_approve_messages_body(msgs, verifier_set, signatures)?,
        Payload::VerifierSet(set) => build_signer_rotation_body(set)?,
    };

    let cell_hex = cell_payload
        .to_boc_hex(true)
        .map_err(|_| ContractError::TonError)?;

    Ok(HexBinary::from_hex(&cell_hex).unwrap())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::{nonempty, Participant};
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use multisig::{
        key::Signature,
        msg::{Signer, SignerWithSig},
        verifier_set::VerifierSet,
    };
    use router_api::{CrossChainId, Message};

    use super::encode_execute_data;
    use crate::{test::test_data::domain_separator, Payload};
    use itertools::Itertools;
    use multisig::key::KeyTyped;

    #[test]
    fn test_encoding() {
        let domain_separator = domain_separator();
        let verifier_set = curr_ton_verifier_set();

        let payload = Payload::Messages(ton_messages());

        let sigs: Vec<_> = vec![
            "25832f14ae75ee8cc958f93fb42f0019409def58e99975aadd0268bd1d04530ee491e7acdb6ef45b790e7268dc2603bc69bc2cbc5a5e15044606737fb5145703",
            "ba822dd7559eb828a67841bd869b4b99813208650090bc1c67b9630ce28c8cd47512bdfdf530c77bbb5e28ddb160387e4f9ab0fd1a05ae22ac52819a888fd80d",
            "194b84efeda7afe98c4d54d2ffb0c3f410b5d637fa3b4f01c97e18dbc412217d8b9bae50e9134e05e3ae1a4ab62e2762684397a2bfad6e51036344bfffd72809",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let encoded_execute_data =
            encode_execute_data(&verifier_set, signers_with_sigs, &payload).unwrap();

        println!("encoded_execute_data: {:?}", encoded_execute_data);
    }

    fn signers_with_sigs<'a>(
        signers: impl Iterator<Item = &'a Signer>,
        sigs: Vec<HexBinary>,
    ) -> Vec<SignerWithSig> {
        signers
            .sorted_by(|s1, s2| Ord::cmp(&s1.pub_key, &s2.pub_key))
            .zip(sigs)
            .map(|(signer, sig)| {
                signer.with_sig(Signature::try_from((signer.pub_key.key_type(), sig)).unwrap())
            })
            .collect()
    }

    pub fn curr_ton_verifier_set() -> VerifierSet {
        let pub_keys = vec![
            "03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8",
            "43CDC023D22D5F9E107D1A0693457D35D1D10EB7D21C721192F56F5DE40665D3",
            "79B5562E8FE654F94078B112E8A98BA7901F853AE695BED7E0E3910BAD049664",
        ];

        ton_verifier_set_from_pub_keys(&pub_keys)
    }

    pub fn ton_verifier_set_from_pub_keys(pub_keys: &Vec<&str>) -> VerifierSet {
        let participants: Vec<(_, _)> = (0..pub_keys.len())
            .map(|i| {
                (
                    Participant {
                        address: Addr::unchecked(format!("verifier{i}")),
                        weight: nonempty::Uint128::one(),
                    },
                    multisig::key::PublicKey::Ed25519(HexBinary::from_hex(pub_keys[i]).unwrap()),
                )
            })
            .collect();
        VerifierSet::new(participants, Uint128::from(3u128), 1)
    }

    pub fn ton_messages() -> Vec<Message> {
        vec![Message {
            cc_id: CrossChainId::new(
                "ganache-1",
                "0xff822c88807859ff226b58e24f24974a70f04b9442501ae38fd665b3c68f3834-0",
            )
            .unwrap(),
            source_address: "0x52444f1835Adc02086c37Cb226561605e2E1699b"
                .parse()
                .unwrap(),
            destination_address: "EQBGhqLAZseEqRXz4ByFPTGV7SVMlI4hrbs-Sps_Xzx01x8G"
                .parse()
                .unwrap(),
            destination_chain: "ganache-0".parse().unwrap(),
            payload_hash: HexBinary::from_hex(
                "56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432", // keccak256("0x1234");
            )
            .unwrap()
            .to_array::<32>()
            .unwrap(),
        }]
    }
}
