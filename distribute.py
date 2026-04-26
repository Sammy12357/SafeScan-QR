import sqlite3
import os
import asyncio
import base58
from dotenv import load_dotenv
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.transaction import VersionedTransaction
from solders.message import MessageV0
from spl.token.instructions import (
    get_associated_token_address,
    create_associated_token_account,
    transfer_checked,
    TransferCheckedParams
)
from spl.token.constants import TOKEN_PROGRAM_ID

load_dotenv()

# SQR Configuration
MINT_ADDRESS = Pubkey.from_string("Bpdt7Hey78HeEEr9Q6x19gYAns5n6w44LdjJhxN3pump")
DECIMALS = 6  
AIRDROP_AMOUNT = 10  # Low amount for safety test

async def airdrop_sweep():
    print("\n--- SafeScan Airdrop Sweep (MAINNET TEST) ---")
    client = AsyncClient("https://api.mainnet-beta.solana.com")
    
    # Load Server Wallet
    pk_str = os.getenv("SOLANA_PRIVATE_KEY")
    server_wallet = Keypair.from_bytes(base58.b58decode(pk_str))
    server_ata = get_associated_token_address(server_wallet.pubkey(), MINT_ADDRESS)
    
    # 1. Connect to Database
    conn = sqlite3.connect('qr_cache.db')
    cursor = conn.cursor()
    
    # 2. Find eligible winners (5+ scans, not yet paid)
    cursor.execute("SELECT email, wallet_address FROM scans WHERE scan_count >= 5 AND tokens_sent = 0")
    winners = cursor.fetchall()

    if not winners:
        print("No new winners found. Make sure you scanned 5 times on the web app!")
        return

    print(f"Found {len(winners)} winner(s). Starting transfer...")

    for email, wallet_str in winners:
        try:
            target_wallet = Pubkey.from_string(wallet_str)
            target_ata = get_associated_token_address(target_wallet, MINT_ADDRESS)
            
            instructions = []
            
            # 3. Create token account if they don't have one
            info = await client.get_account_info(target_ata)
            if info.value is None:
                instructions.append(create_associated_token_account(server_wallet.pubkey(), target_wallet, MINT_ADDRESS))

            # 4. Add the SQR Transfer
            amount_raw = AIRDROP_AMOUNT * (10 ** DECIMALS)
            instructions.append(transfer_checked(TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=server_ata,
                mint=MINT_ADDRESS,
                dest=target_ata,
                owner=server_wallet.pubkey(),
                amount=amount_raw,
                decimals=DECIMALS
            )))

            # 5. Sign and execute
            recent_blockhash = (await client.get_latest_blockhash()).value.blockhash
            msg = MessageV0.try_compile(server_wallet.pubkey(), instructions, [], recent_blockhash)
            tx = VersionedTransaction(msg, [server_wallet])
            result = await client.send_transaction(tx)
            
            # 6. Update Database to mark as 'sent'
            cursor.execute("UPDATE scans SET tokens_sent = 1 WHERE email = ?", (email,))
            conn.commit()
            
            print(f"SUCCESS: {AIRDROP_AMOUNT} SQR sent to {email}")
            print(f"Tx URL: https://explorer.solana.com/tx/{result.value}")

        except Exception as e:
            print(f"FAILED to pay {email}: {e}")

    conn.close()
    await client.close()

if __name__ == "__main__":
    asyncio.run(airdrop_sweep())