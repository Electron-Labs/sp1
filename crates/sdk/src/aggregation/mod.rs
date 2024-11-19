use crate::block_on;
use anyhow::Result;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{HashableKey, SP1VerifyingKey};
use std::env;

/// The default RPC endpoint for aggregation network.
pub const DEFAULT_AGGREGATOR_NETWORK_RPC: &str = "https://rpc.superproof.ai";

/// Represents an aggregation Merkle proof.
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct AggregationMerkleProof {
    merkle_proof: Vec<String>,
    merkle_proof_position: u64,
}

pub fn get_aggregation_rpc_url() -> String {
    env::var("AGGREGATOR_RPC").unwrap_or_else(|_| DEFAULT_AGGREGATOR_NETWORK_RPC.to_string())
}

async fn request_aggregation_proof(
    program_vkey_hash: &[u8; 32],
    public_values_hash: &[u8; 32],
) -> Result<AggregationMerkleProof> {
    let http_client = HttpClient::new();

    let url = format!("{}/sp1_proof/merkle", get_aggregation_rpc_url());

    let payload = serde_json::json!({
        "vkey_hash": program_vkey_hash,
        "pis_hash": public_values_hash
    });

    // Send the GET request
    let response = http_client.get(url).json(&payload).send().await?;

    // Check if the response was successful
    if response.status().is_success() {
        // Parse the JSON response
        let response_json: serde_json::Value = response.json().await?;
        let aggregation_merkle_proof: AggregationMerkleProof =
            serde_json::from_value(response_json.clone())?;
        Ok(aggregation_merkle_proof)
    } else {
        Err(anyhow::anyhow!("Failed with status: {}", response.status()))
    }
}

/// This method allows the user to get merkle inclusion proof for an aggregated proof
///
/// ### Examples
///
/// ```no_run
/// let merkle_proof = sp1_sdk::aggregation::fetch_batch_data(program_vkey, public_values)?
/// ```
pub fn fetch_batch_data(
    program_vkey: SP1VerifyingKey,
    public_values: SP1PublicValues,
) -> Result<AggregationMerkleProof> {
    let program_vkey_hash = program_vkey.hash_bytes();
    let public_values_hash = public_values.hash_keccak();

    let aggregation_merkle_proof =
        block_on(request_aggregation_proof(&program_vkey_hash, &public_values_hash))?;

    Ok(aggregation_merkle_proof)
}

#[cfg(test)]
mod test {
    use crate::{utils, ProverClient, SP1Stdin};
    use sp1_primitives::io::SP1PublicValues;

    use super::fetch_batch_data;

    #[test]
    fn test_fetch_batch_data() {
        utils::setup_logger();
        let client = ProverClient::local();
        let elf = test_artifacts::FIBONACCI_ELF;
        let (_pk, vk) = client.setup(elf);
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let public_values = SP1PublicValues::from(&[10]);
        fetch_batch_data(vk, public_values).unwrap();
    }
}
