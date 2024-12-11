class TokenSecurityManager:
    def __init__(self):
        self.blacklisted_wallets = set()
        self.whitelisted_wallets = set()

    def add_to_blacklist(self, wallet_address):
        if wallet_address not in self.whitelisted_wallets:
            self.blacklisted_wallets.add(wallet_address)
            print(f"Wallet {wallet_address} has been blacklisted.")
        else:
            print(f"Cannot blacklist {wallet_address}; it is whitelisted.")

    def add_to_whitelist(self, wallet_address):
        self.whitelisted_wallets.add(wallet_address)
        print(f"Wallet {wallet_address} has been whitelisted.")

    def is_transfer_allowed(self, sender_wallet, recipient_wallet):
        if sender_wallet in self.blacklisted_wallets and recipient_wallet not in self.whitelisted_wallets:
            return False
        return True
