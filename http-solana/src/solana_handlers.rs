use axum::Json;
use serde::{Deserialize, Serialize};
use crate::{ApiResult, ApiError, ApiResponse};
use solana_sdk::{
    signature::{Keypair, Signer}, 
    pubkey::Pubkey,
    system_instruction,
    instruction::{AccountMeta, Instruction},
    sysvar::rent,
};
use spl_token::instruction as token_instruction;
use spl_associated_token_account::instruction::create_associated_token_account;
use bs58;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use std::str::FromStr;

// Helper function to validate Pubkey
fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(pubkey_str)
        .map_err(|_| ApiError::InvalidInput(format!("Invalid public key: {}", pubkey_str)))
}

// Helper function to validate amount
fn validate_amount(amount: u64) -> Result<(), ApiError> {
    if amount == 0 {
        return Err(ApiError::InvalidInput("Amount must be greater than 0".to_string()));
    }
    Ok(())
}

// 1. Generate Keypair
#[derive(Serialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

pub async fn generate_keypair() -> ApiResult<KeypairResponse> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let resp = KeypairResponse { pubkey, secret };
    Ok(Json(ApiResponse::success(resp)))
}

// 2. Create Token
#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct TokenInstructionAccount {
    pub pubkey: String,
    #[serde(rename = "is_signer")]
    pub is_signer: bool,
    #[serde(rename = "is_writable")]
    pub is_writable: bool,
}

#[derive(Serialize)]
pub struct TokenInstructionResponse {
    pub program_id: String,
    pub accounts: Vec<TokenInstructionAccount>,
    pub instruction_data: String,
}

pub async fn create_token(Json(req): Json<CreateTokenRequest>) -> ApiResult<TokenInstructionResponse> {
    let mint = validate_pubkey(&req.mint)?;
    let mint_authority = validate_pubkey(&req.mint_authority)?;
    
    // Create initialize mint instruction
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None, // freeze authority
        req.decimals,
    )?;
    
    let accounts: Vec<TokenInstructionAccount> = instruction.accounts.iter().map(|acc| {
        TokenInstructionAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }).collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let resp = TokenInstructionResponse { 
        program_id: instruction.program_id.to_string(), 
        accounts, 
        instruction_data 
    };
    Ok(Json(ApiResponse::success(resp)))
}

// 3. Mint Token
#[derive(Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

pub async fn mint_token(Json(req): Json<MintTokenRequest>) -> ApiResult<TokenInstructionResponse> {
    let mint = validate_pubkey(&req.mint)?;
    let destination = validate_pubkey(&req.destination)?;
    let authority = validate_pubkey(&req.authority)?;
    validate_amount(req.amount)?;
    
    // Create mint to instruction
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    )?;
    
    let accounts: Vec<TokenInstructionAccount> = instruction.accounts.iter().map(|acc| {
        TokenInstructionAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }).collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let resp = TokenInstructionResponse { 
        program_id: instruction.program_id.to_string(), 
        accounts, 
        instruction_data 
    };
    Ok(Json(ApiResponse::success(resp)))
}

// 4. Sign Message
#[derive(Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Serialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

pub async fn sign_message(Json(req): Json<SignMessageRequest>) -> ApiResult<SignMessageResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Err(ApiError::MissingFields);
    }
    
    let secret_bytes = bs58::decode(&req.secret).into_vec()
        .map_err(|_| ApiError::InvalidInput("Invalid secret key encoding".to_string()))?;
    
    let keypair = Keypair::from_bytes(&secret_bytes)
        .map_err(|_| ApiError::InvalidInput("Invalid secret key bytes".to_string()))?;
    
    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());
    let public_key = keypair.pubkey().to_string();
    
    let resp = SignMessageResponse {
        signature: signature_b64,
        public_key,
        message: req.message,
    };
    Ok(Json(ApiResponse::success(resp)))
}

// 5. Verify Message
#[derive(Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

pub async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> ApiResult<VerifyMessageResponse> {
    let pubkey_bytes = bs58::decode(&req.pubkey).into_vec()
        .map_err(|_| ApiError::InvalidInput("Invalid public key encoding".to_string()))?;
    if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(ApiError::InvalidInput("Invalid public key length".to_string()));
    }
    let signature_bytes = general_purpose::STANDARD.decode(&req.signature)
        .map_err(|_| ApiError::InvalidInput("Invalid signature encoding".to_string()))?;
    if signature_bytes.len() != SIGNATURE_LENGTH {
        return Err(ApiError::InvalidInput("Invalid signature length".to_string()));
    }
    use std::convert::TryFrom;
    let ed_pubkey = ed25519_dalek::PublicKey::from_bytes(&<[u8; 32]>::try_from(pubkey_bytes).unwrap())
        .map_err(|_| ApiError::InvalidInput("Invalid public key bytes".to_string()))?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(&<[u8; 64]>::try_from(signature_bytes).unwrap())
        .map_err(|_| ApiError::InvalidInput("Invalid signature bytes".to_string()))?;
    let valid = ed_pubkey.verify(req.message.as_bytes(), &ed_sig).is_ok();
    let resp = VerifyMessageResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };
    Ok(Json(ApiResponse::success(resp)))
}

// 6. Send SOL
#[derive(Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Serialize)]
pub struct SendSolResponse {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub instruction_data: String,
}

pub async fn send_sol(Json(req): Json<SendSolRequest>) -> ApiResult<SendSolResponse> {
    let from = validate_pubkey(&req.from)?;
    let to = validate_pubkey(&req.to)?;
    validate_amount(req.lamports)?;
    
    // Create transfer instruction
    let instruction = system_instruction::transfer(&from, &to, req.lamports);
    
    let accounts: Vec<String> = instruction.accounts.iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let resp = SendSolResponse { 
        program_id: instruction.program_id.to_string(),
        accounts, 
        instruction_data 
    };
    Ok(Json(ApiResponse::success(resp)))
}

// 7. Send Token
#[derive(Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct SendTokenAccount {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

#[derive(Serialize)]
pub struct SendTokenResponse {
    pub program_id: String,
    pub accounts: Vec<SendTokenAccount>,
    pub instruction_data: String,
}

pub async fn send_token(Json(req): Json<SendTokenRequest>) -> ApiResult<SendTokenResponse> {
    let destination = validate_pubkey(&req.destination)?;
    let mint = validate_pubkey(&req.mint)?;
    let owner = validate_pubkey(&req.owner)?;
    validate_amount(req.amount)?;
    
    // For token transfers, we need the source and destination token accounts
    // This is a simplified version - in reality you'd need to derive the associated token accounts
    let source_token_account = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let destination_token_account = spl_associated_token_account::get_associated_token_address(&destination, &mint);
    
    // Create transfer instruction
    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_token_account,
        &destination_token_account,
        &owner,
        &[],
        req.amount,
    )?;
    
    let accounts: Vec<SendTokenAccount> = instruction.accounts.iter().map(|acc| {
        SendTokenAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        }
    }).collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let resp = SendTokenResponse { 
        program_id: instruction.program_id.to_string(),
        accounts, 
        instruction_data 
    };
    Ok(Json(ApiResponse::success(resp)))
}