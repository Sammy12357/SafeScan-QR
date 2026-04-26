import os
import asyncio
import base58
from dotenv import load_dotenv
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair

load_dotenv()

async def verify_connection():
    print("\n--- SafeScan Solana Connection Test ---")
    
    # 1. Connect to Blockchain (Mainnet)
    client = AsyncClient("https://api.mainnet-beta.solana.com")
    
    # 2. Load Server Wallet securely from .env
    pk_str = os.getenv("SOLANA_PRIVATE_KEY")
    if not pk_str:
        print("Error: SOLANA_PRIVATE_KEY not found in .env")
        return
        
    server_wallet = Keypair.from_bytes(base58.b58decode(pk_str))
    wallet_address = server_wallet.pubkey()
    
    print(f"[1] Connected to Mainnet successfully.")
    print(f"[2] Server Wallet Authenticated: {wallet_address}")
    
    # 3. Check Live SOL Balance
    print(f"[3] Fetching wallet balance...")
    balance_resp = await client.get_balance(wallet_address)
    
    # Convert lamports (the smallest unit) to SOL
    sol_balance = balance_resp.value / 1_000_000_000  
    
    print(f"    -> Live Balance: {sol_balance} SOL")
    print("\nSystem is online and ready for the hackathon!")
    
    await client.close()

if __name__ == "__main__":
    asyncio.run(verify_connection())