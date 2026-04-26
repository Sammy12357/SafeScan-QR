import sqlite3
import os
import asyncio
import base58
from dotenv import load_dotenv
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair

load_dotenv()

async def airdrop_sweep():
    conn = sqlite3.connect('qr_cache.db')
    cursor = conn.cursor()

    # Find users with 5+ scans who haven't been paid
    cursor.execute("SELECT email, wallet_address FROM scans WHERE scan_count >= 5 AND tokens_sent = 0")
    winners = cursor.fetchall()

    if not winners:
        print("No new winners to pay.")
        return

    print(f"Found {len(winners)} winners!")

    for email, wallet in winners:
        print(f"Attempting to send 100 SQR to: {email} at {wallet}")
        
        # Once you have tokens, we will uncomment the Solana transfer code here.
        
        # Mark as paid in DB
        # cursor.execute("UPDATE scans SET tokens_sent = 1 WHERE email = ?", (email,))
        # conn.commit()

    conn.close()

if __name__ == "__main__":
    asyncio.run(airdrop_sweep())