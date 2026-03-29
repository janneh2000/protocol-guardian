"""Quick helper to derive wallet address from a private key."""
import sys
from web3 import Web3

def main():
    if len(sys.argv) < 2:
        key = input("Enter private key (0x...): ").strip()
    else:
        key = sys.argv[1]

    try:
        account = Web3().eth.account.from_key(key)
        print(f"Address: {account.address}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
