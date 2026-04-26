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

try:
    from spl.token.constants import TOKEN_2022_PROGRAM_ID
except ImportError:
    TOKEN_2022_PROGRAM_ID = None

load_dotenv()

# SQR Configuration
MINT_ADDRESS = Pubkey.from_string("Bpdt7Hey78HeEEr9Q6x19gYAns5n6w44LdjJhxN3pump")
AIRDROP_AMOUNT = 10  # Low amount for safety test
RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")


def describe_exception(exc):
    message = str(exc) or repr(exc)
    return {
        "type": type(exc).__name__,
        "message": message
    }


def associated_token_address(owner, token_program_id):
    try:
        return get_associated_token_address(
            owner,
            MINT_ADDRESS,
            token_program_id=token_program_id
        )
    except TypeError as exc:
        if token_program_id == TOKEN_PROGRAM_ID:
            return get_associated_token_address(owner, MINT_ADDRESS)
        raise RuntimeError("Installed SPL library does not support Token-2022 associated token accounts.") from exc


def create_token_account_instruction(payer, owner, token_program_id):
    try:
        return create_associated_token_account(
            payer,
            owner,
            MINT_ADDRESS,
            token_program_id=token_program_id
        )
    except TypeError as exc:
        if token_program_id == TOKEN_PROGRAM_ID:
            return create_associated_token_account(payer, owner, MINT_ADDRESS)
        raise RuntimeError("Installed SPL library does not support Token-2022 associated token account creation.") from exc


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
        raise RuntimeError(f"Could not read token supply for mint {MINT_ADDRESS}. RPC response: {supply!r}")
    return supply.value.decimals


async def get_token_program_id(client):
    mint_info = await client.get_account_info(MINT_ADDRESS)
    if not mint_info.value:
        raise RuntimeError(f"Token mint account was not found: {MINT_ADDRESS}")

    token_program_id = mint_info.value.owner
    supported_programs = [TOKEN_PROGRAM_ID]
    if TOKEN_2022_PROGRAM_ID is not None:
        supported_programs.append(TOKEN_2022_PROGRAM_ID)

    if token_program_id not in supported_programs:
        raise RuntimeError(f"Unexpected token program for SQR mint: {token_program_id}")

    return token_program_id


async def get_token_balance(client, token_account):
    balance = await client.get_token_account_balance(token_account)
    if not balance.value:
        return 0
    return int(balance.value.amount)

async def airdrop_sweep():
    print("\n--- SafeScan Airdrop Sweep (MAINNET TEST) ---")
    client = AsyncClient(RPC_URL)
    conn = None

    try:
        # Load Server Wallet
        server_wallet = load_server_wallet()
        token_program_id = await get_token_program_id(client)
        server_ata = associated_token_address(server_wallet.pubkey(), token_program_id)
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

        summary = {
            "status": "ok",
            "eligible": len(winners),
            "sent": [],
            "skipped": [],
            "failed": [],
            "mint": str(MINT_ADDRESS),
            "token_program": str(token_program_id),
            "source_token_account": str(server_ata)
        }

        if not winners:
            print("No new winners found. Make sure you scanned 5 times on the web app!")
            return summary

        print(f"Found {len(winners)} winner(s). Starting transfer...")

        for email, wallet_str in winners:
            try:
                if not wallet_str:
                    print(f"SKIPPED {email}: no wallet address saved.")
                    summary["skipped"].append({"email": email, "reason": "No wallet address saved."})
                    continue

                target_wallet = Pubkey.from_string(wallet_str)
                target_ata = associated_token_address(target_wallet, token_program_id)

                instructions = []

                # 3. Create token account if they don't have one
                info = await client.get_account_info(target_ata)
                if info.value is None:
                    instructions.append(create_token_account_instruction(
                        server_wallet.pubkey(),
                        target_wallet,
                        token_program_id
                    ))

                instructions.append(transfer_checked(TransferCheckedParams(
                    program_id=token_program_id,
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
                summary["sent"].append({
                    "email": email,
                    "wallet": wallet_str,
                    "signature": str(result.value),
                    "explorer_url": f"https://explorer.solana.com/tx/{result.value}"
                })

            except Exception as exc:
                error = describe_exception(exc)
                print(f"FAILED to pay {email}: {error['type']} - {error['message']}")
                summary["failed"].append({"email": email, "wallet": wallet_str, "error": error})

        if summary["failed"] and not summary["sent"]:
            summary["status"] = "failed"
        elif summary["failed"]:
            summary["status"] = "partial"

        return summary

    finally:
        if conn:
            conn.close()
        await client.close()

if __name__ == "__main__":
    asyncio.run(airdrop_sweep())
