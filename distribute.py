import sqlite3
import os
import asyncio
import base58
import json
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
AIRDROP_AMOUNT = 10  # Low amount for safety test
RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")


def load_server_wallet():
    pk_str = os.getenv("SOLANA_PRIVATE_KEY")
    if not pk_str:
        raise RuntimeError("SOLANA_PRIVATE_KEY is not set.")

    pk_str = pk_str.strip()
    try:
        if pk_str.startswith("["):
            key_bytes = bytes(json.loads(pk_str))
        else:
            key_bytes = base58.b58decode(pk_str)
    except Exception as exc:
        raise RuntimeError("SOLANA_PRIVATE_KEY must be a base58 keypair or a JSON byte array.") from exc

    if len(key_bytes) not in (32, 64):
        raise RuntimeError(f"SOLANA_PRIVATE_KEY decoded to {len(key_bytes)} bytes; expected 32 or 64.")

    return Keypair.from_seed(key_bytes) if len(key_bytes) == 32 else Keypair.from_bytes(key_bytes)


async def get_mint_decimals(client):
    supply = await client.get_token_supply(MINT_ADDRESS)
    if not supply.value:
        raise RuntimeError(f"Could not read token supply for mint {MINT_ADDRESS}.")
    return supply.value.decimals


async def get_token_balance(client, token_account):
    balance = await client.get_token_account_balance(token_account)
    if not balance.value:
        return 0
    return int(balance.value.amount)

async def airdrop_sweep():
    print("\n--- SafeScan Airdrop Sweep (MAINNET TEST) ---")
    client = AsyncClient(RPC_URL)
    
    # Load Server Wallet
    server_wallet = load_server_wallet()
    server_ata = get_associated_token_address(server_wallet.pubkey(), MINT_ADDRESS)
    decimals = await get_mint_decimals(client)
    amount_raw = AIRDROP_AMOUNT * (10 ** decimals)

    server_info = await client.get_account_info(server_ata)
    if server_info.value is None:
        raise RuntimeError(
            f"Server wallet token account does not exist for SQR. "
            f"Send SQR to this ATA first: {server_ata}"
        )

    server_balance = await get_token_balance(client, server_ata)
    if server_balance < amount_raw:
        raise RuntimeError(
            f"Server SQR balance is too low. Need {amount_raw} raw units, found {server_balance}."
        )
    
    # 1. Connect to Database
    conn = sqlite3.connect('qr_cache.db')
    cursor = conn.cursor()
    
    # 2. Find eligible winners (5+ scans, not yet paid)
    cursor.execute("SELECT email, wallet_address FROM scans WHERE scan_count >= 5 AND tokens_sent = 0")
    winners = cursor.fetchall()

    if not winners:
        print("No new winners found. Make sure you scanned 5 times on the web app!")
        conn.close()
        await client.close()
        return

    print(f"Found {len(winners)} winner(s). Starting transfer...")

    for email, wallet_str in winners:
        try:
            if not wallet_str:
                print(f"SKIPPED {email}: no wallet address saved.")
                continue

            target_wallet = Pubkey.from_string(wallet_str)
            target_ata = get_associated_token_address(target_wallet, MINT_ADDRESS)
            
            instructions = []
            
            # 3. Create token account if they don't have one
            info = await client.get_account_info(target_ata)
            if info.value is None:
                instructions.append(create_associated_token_account(server_wallet.pubkey(), target_wallet, MINT_ADDRESS))

            instructions.append(transfer_checked(TransferCheckedParams(
                program_id=TOKEN_PROGRAM_ID,
                source=server_ata,
                mint=MINT_ADDRESS,
                dest=target_ata,
                owner=server_wallet.pubkey(),
                amount=amount_raw,
                decimals=decimals
            )))

            # 5. Sign and execute
            recent_blockhash = (await client.get_latest_blockhash()).value.blockhash
            msg = MessageV0.try_compile(server_wallet.pubkey(), instructions, [], recent_blockhash)
            tx = VersionedTransaction(msg, [server_wallet])
            result = await client.send_transaction(tx)
            await client.confirm_transaction(result.value, commitment="confirmed")
            
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
