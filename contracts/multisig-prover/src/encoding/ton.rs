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
            .map_err(|_| TonCellError::InternalError("".to_owned()))?,
    ))
}

fn message_to_cell(msg: Message) -> std::result::Result<Cell, TonCellError> {
    let mut builder = CellBuilder::new();
    builder.store_reference(&get_arced_cell(&msg.cc_id.message_id)?)?;
    builder.store_reference(&get_arced_cell(&msg.cc_id.source_chain.to_string())?)?;
    builder.store_reference(&get_arced_cell(&msg.source_address)?)?;

    let ton_address_hash_buffer = TonAddress::from_str(&msg.destination_address)
        .map_err(|_| TonCellError::InternalError("".to_owned()))?
        .hash_part
        .to_vec();

    let ton_address_hash_buffer_cell = buffer_to_cell(ton_address_hash_buffer)
        .map_err(|_| TonCellError::InternalError("".to_owned()))?;

    builder.store_reference(&Arc::new(ton_address_hash_buffer_cell.clone()))?; // problem this should be the Ton address hash!!! .storeRef(bufferToCell(msg.executableAddress.hash))
    builder.store_uint(256, &BigUint::from_bytes_be(&msg.payload_hash))?;

    let res = builder.build()?;
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

    Ok(HexBinary::from_hex(&cell_hex).map_err(|_| ContractError::TonError)?)
}

#[cfg(test)]
mod tests {
    use super::encode_execute_data;
    use crate::{test::test_data::domain_separator, Payload};
    use axelar_wasm_std::{nonempty, Participant};
    use cosmwasm_std::{Addr, HexBinary, Uint128};
    use itertools::Itertools;
    use multisig::key::KeyTyped;
    use multisig::{
        key::Signature,
        msg::{Signer, SignerWithSig},
        verifier_set::VerifierSet,
    };
    use router_api::{CrossChainId, Message};

    #[test]
    fn should_encode_approve_messages() {
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

        assert_eq!(encoded_execute_data.to_string(), "b5ee9c7241020e0100026c0002080000002801020161800000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000c0030101c0040202ce05060102d007020120080900e1479b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad04966400000000000000000000000000000001194b84efeda7afe98c4d54d2ffb0c3f410b5d637fa3b4f01c97e18dbc412217d8b9bae50e9134e05e3ae1a4ab62e2762684397a2bfad6e51036344bfffd728098044056570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea74320a0b0c0d00e100e841effcf3842f875c374639d2f02659f9358c26e94357c777219904954c6e000000000000000000000000000000004960cbc52b9d7ba332563e4fed0bc00650277bd63a665d6ab7409a2f474114c3b92479eb36dbbd16de439c9a370980ef1a6f0b2f1697854111819cdfed4515c0e000e110f37008f48b57e7841f4681a4d15f4d747443adf4871c8464bd5bd779019974c00000000000000000000000000000006ea08b75d567ae0a299e106f61a6d2e6604c821940242f0719ee58c338a323351d44af7f7d4c31deeed78a376c580e1f93e6ac3f46816b88ab14a066a223f6036000883078666638323263383838303738353966663232366235386532346632343937346137306630346239343432353031616533386664363635623363363866333833342d30001267616e616368652d31005430783532343434663138333541646330323038366333374362323236353631363035653245313639396200404686a2c066c784a915f3e01c853d3195ed254c948e21adbb3e4a9b3f5f3c74d75fde9317");
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
