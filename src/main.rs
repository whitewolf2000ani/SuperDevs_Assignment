use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use tokio::net::TcpListener;
use validator::Validate;
use validator_derive::Validate;



#[derive(Clone)]
struct AppState {
    token_program_id: Pubkey,
    system_program_id: Pubkey,
}

#[derive(Deserialize, Validate)]
struct KeypairRequest {}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize, Validate)]
struct CreateTokenRequest {
    #[validate(length(equal = 32))]
    mint_authority: String,
    #[validate(length(equal = 32))]
    mint: String,
    decimals: u8,
}

// Add these after your existing structs
#[derive(Deserialize, Validate)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize, Validate)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize, Validate)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize, Validate)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize, Validate)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}


fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .with_state(state)
}


async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    
    Json(json!({
        "success": true,
        "data": {
            "pubkey": keypair.pubkey().to_string(),
            "secret": bs58::encode(keypair.to_bytes()).into_string()
        }
    }))
}

async fn create_token(
    State(state): State<AppState>,
    Json(payload): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    // Validate input
    if let Err(e) = payload.validate() {
        return Json(json!({
            "success": false,
            "error": format!("Validation error: {}", e)
        }));
    }

    // Parse public keys
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid mint address"
        })),
    };

    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid mint authority"
        })),
    };

    // Create initialize mint instruction
    let instruction = token_instruction::initialize_mint(
        &state.token_program_id,
        &mint,
        &mint_authority,
        None,
        payload.decimals,
    )
    .unwrap();

    Json(json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts.iter().map(|acc| json!({
                "pubkey": acc.pubkey.to_string(),
                "is_signer": acc.is_signer,
                "is_writable": acc.is_writable
            })).collect::<Vec<_>>(),
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data)
        }
    }))
}

async fn mint_token(
    State(state): State<AppState>,
    Json(payload): Json<MintTokenRequest>,
) -> impl IntoResponse {
    // Parse public keys
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid mint address"
        })),
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid destination address"
        })),
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid authority address"
        })),
    };

    // Create mint to instruction
    let instruction = token_instruction::mint_to(
        &state.token_program_id,
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .unwrap();

    Json(json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts.iter().map(|acc| json!({
                "pubkey": acc.pubkey.to_string(),
                "is_signer": acc.is_signer,
                "is_writable": acc.is_writable
            })).collect::<Vec<_>>(),
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data)
        }
    }))
}

async fn sign_message(Json(payload): Json<SignMessageRequest>) -> impl IntoResponse {
    // Decode secret key from base58
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid secret key format"
        })),
    };

    // Create keypair from secret bytes
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid secret key"
        })),
    };

    // Sign the message
    let signature = keypair.sign_message(payload.message.as_bytes());

    Json(json!({
        "success": true,
        "data": {
            "signature": general_purpose::STANDARD.encode(signature.as_ref()),
            "public_key": keypair.pubkey().to_string(),
            "message": payload.message
        }
    }))
}

async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> impl IntoResponse {
    // Parse public key
    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid public key"
        })),
    };

    // Decode signature from base64
    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid signature format"
        })),
    };

    // Create signature object
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid signature"
        })),
    };

    // Verify signature
    let is_valid = signature.verify(pubkey.as_ref(), payload.message.as_bytes());

    Json(json!({
        "success": true,
        "data": {
            "valid": is_valid,
            "message": payload.message,
            "pubkey": payload.pubkey
        }
    }))
}

async fn send_sol(
    State(state): State<AppState>,
    Json(payload): Json<SendSolRequest>,
) -> impl IntoResponse {
    // Parse public keys
    let from = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid from address"
        })),
    };

    let to = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid to address"
        })),
    };

    // Validate lamports amount
    if payload.lamports == 0 {
        return Json(json!({
            "success": false,
            "error": "Invalid lamports amount"
        }));
    }

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    Json(json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": [
                from.to_string(),
                to.to_string()
            ],
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data)
        }
    }))
}

async fn send_token(
    State(state): State<AppState>,
    Json(payload): Json<SendTokenRequest>,
) -> impl IntoResponse {
    // Parse public keys
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid destination address"
        })),
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid mint address"
        })),
    };

    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => return Json(json!({
            "success": false,
            "error": "Invalid owner address"
        })),
    };

    // Get associated token addresses
    let source = get_associated_token_address(&owner, &mint);
    let dest_token_account = get_associated_token_address(&destination, &mint);

    // Create transfer instruction
    let instruction = token_instruction::transfer(
        &state.token_program_id,
        &source,
        &dest_token_account,
        &owner,
        &[],
        payload.amount,
    )
    .unwrap();

    Json(json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": instruction.accounts.iter().map(|acc| json!({
                "pubkey": acc.pubkey.to_string(),
                "isSigner": acc.is_signer
            })).collect::<Vec<_>>(),
            "instruction_data": general_purpose::STANDARD.encode(&instruction.data)
        }
    }))
}


#[tokio::main]
async fn main() {
    let port = std::env::var("PORT")
        .map(|p| p.parse().unwrap_or(3000))
        .unwrap_or(3000);

    let state = AppState {
        token_program_id: spl_token::id(),
        system_program_id: solana_sdk::system_program::id(),
    };

    let app = create_router(state);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    println!("Server running on 0.0.0.0:{}", port);
    axum::serve(listener, app).await.unwrap();
}
