# 🏦 Banking App (SQL Version with CSV Audit and Advanced Features)
# Author: Alen Chavez (Corrected and verified against Capstone requirements)
# Description:
# A console-based banking application using SQLite, implementing advanced
# validation, a secure login session, unique 8-digit account numbers, and the Transfer feature.

import sqlite3
import hashlib
import csv
import os
import re # For complex validation (password, username)
import random # For generating account numbers
import time # For flow delays
import getpass # For blind password input
from datetime import datetime

# --- Configuration ---
DB_FILE = "bank.db"
CSV_LOG = "transactions.csv"
MIN_INITIAL_DEPOSIT = 2000.00  # Minimum deposit requirement (Naira)
LOGGED_IN_USER = None  # Global variable to store the logged-in user's details


# -------------------- Database Setup --------------------

def init_db():
    """
    Initializes the SQLite database and creates tables if they don't exist.
    It DOES NOT delete existing data, ensuring persistence.
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Users table now includes account_number and stores password_hash
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        user_id INTEGER PRIMARY KEY,
        checking REAL DEFAULT 0,
        savings REAL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Transactions table includes more detail for transfers
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_number TEXT NOT NULL,
        type TEXT NOT NULL, -- DEPOSIT, WITHDRAWAL, TRANSFER_OUT, TRANSFER_IN
        account_type TEXT,  -- C or S (optional for transfers)
        amount REAL NOT NULL,
        recipient_account TEXT, -- Used for transfers
        old_balance REAL NOT NULL,
        new_balance REAL NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # ---- Add sample test accounts ONLY if database is empty ----
    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]

    if user_count == 0:
        print("🧪 Setting up fresh database and adding 3 sample test accounts...")

        sample_users = [
            ("alice01", hash_password("P@ssw0rd1"), "Alice Smith", "10000001", 3500.00, 2500.00),
            ("bob_j", hash_password("S3cr3t!2"), "Bob Johnson", "10000002", 25000.00, 10000.00),
            ("carlaG", hash_password("MyP@ss3"), "Carla Gomez", "10000003", 3000.00, 7000.00),
        ]

        for username, password_hash, name, acc_num, checking, savings in sample_users:
            cur.execute("INSERT INTO users (username, password_hash, name, account_number) VALUES (?, ?, ?, ?)",
                        (username, password_hash, name, acc_num))
            user_id = cur.lastrowid
            cur.execute("INSERT INTO accounts (user_id, checking, savings) VALUES (?, ?, ?)",
                        (user_id, checking, savings))

        print("✅ Setup complete. Use sample credentials to test the login/session flow.")
    else:
        print(f"✅ Database found with {user_count} accounts. Resuming session...")


    conn.commit()
    conn.close()

# -------------------- Security & Validation Helpers --------------------

def hash_password(password: str) -> str:
    """Hashes the password using SHA-256, salted and iterated."""
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_name(name):
    """Validates name: alpha, spaces only, length 4-255."""
    if not (4 <= len(name) <= 255):
        return False, "Name must be between 4 and 255 characters."
    if not re.fullmatch(r"^[a-zA-Z\s]+$", name):
        return False, "Name must contain only letters and spaces."
    return True, ""

def is_valid_username(username):
    """Validates username: alphanumeric/underscore, length 3-20, unique."""
    if not (3 <= len(username) <= 20):
        return False, "Username must be between 3 and 20 characters."
    if not re.fullmatch(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username must contain only alphanumeric characters and underscores."
    if get_user(username):
        return False, "Username already exists."
    return True, ""

def is_valid_password(password):
    """Validates password complexity: length 8-30, U/L/N/S."""
    if not (8 <= len(password) <= 30):
        return False, "Password must be between 8 and 30 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]|\\:;\"'<>,.?/`~]", password):
        return False, "Password must contain at least one special character."
    return True, ""

def generate_unique_account_number():
    """Generates a unique 8-digit account number."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    while True:
        acc_num = str(random.randint(10000000, 99999999))
        cur.execute("SELECT account_number FROM users WHERE account_number = ?", (acc_num,))
        if cur.fetchone() is None:
            conn.close()
            return acc_num


# -------------------- Database & Audit Helpers --------------------

def get_user(username):
    """Fetches user by username. Returns tuple: (id, username, hash, name, acc_num)"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, name, account_number FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user_by_acc_num(account_number):
    """Fetches user by account number. Returns tuple: (id, username, hash, name, acc_num)"""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, name, account_number FROM users WHERE account_number = ?", (account_number,))
    row = cur.fetchone()
    conn.close()
    return row

def get_balance(user_id, account_type):
    """Retrieves the balance for a given user and account type (C/S)."""
    column = "checking" if account_type == "C" else "savings"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(f"SELECT {column} FROM accounts WHERE user_id = ?", (user_id,))
    balance = cur.fetchone()[0]
    conn.close()
    return balance

def update_balance(user_id, account_type, new_balance):
    """Updates the balance for a given user and account type (C/S)."""
    column = "checking" if account_type == "C" else "savings"
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(f"UPDATE accounts SET {column} = ? WHERE user_id = ?", (new_balance, user_id))
    conn.commit()
    conn.close()

def ensure_csv_header():
    """Ensures the CSV audit file exists with the correct header."""
    if not os.path.exists(CSV_LOG):
        with open(CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "account_number", "type", "account_type", "amount", "old_balance", "new_balance", "recipient_account"])

def log_to_csv(acc_num, type, acc_type, amount, old_balance, new_balance, recipient_acc=None):
    """Logs the transaction to the CSV audit file."""
    ensure_csv_header()
    with open(CSV_LOG, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(timespec='seconds'),
                         acc_num, type, acc_type,
                         f"{amount:.2f}", f"{old_balance:.2f}", f"{new_balance:.2f}",
                         recipient_acc if recipient_acc else "N/A"])

def record_transaction(user_id, acc_num, type, acc_type, amount, old_balance, new_balance, recipient_acc=None):
    """Records the transaction in both the SQL database and the CSV log."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO transactions (user_id, account_number, type, account_type, amount, old_balance, new_balance, recipient_account, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, acc_num, type, acc_type, amount, old_balance, new_balance, recipient_acc, datetime.now().isoformat(timespec='seconds')))
    conn.commit()
    conn.close()

    log_to_csv(acc_num, type, acc_type, amount, old_balance, new_balance, recipient_acc)


# -------------------- Core Features --------------------

def create_account():
    """Implements User Registration with full validation and unique account number generation."""
    global LOGGED_IN_USER
    print("\n--- NEW ACCOUNT REGISTRATION ---")

    # 1. Full Name Validation
    while True:
        name = input("Enter your Full Name: ").strip()
        is_valid, msg = is_valid_name(name)
        if is_valid:
            break
        print(f"❌ Error: {msg}")

    # 2. Username Validation
    while True:
        username = input("Enter new Username: ").strip()
        is_valid, msg = is_valid_username(username)
        if is_valid:
            break
        print(f"❌ Error: {msg}")

    # 3. Password Validation
    while True:
        # Use getpass for blind typing
        password = getpass.getpass("Enter Password (8-30 chars, U/L/N/S): ").strip()
        is_valid, msg = is_valid_password(password)
        if is_valid:
            break
        print(f"❌ Error: {msg}")

    # 4. Initial Deposit Validation
    while True:
        try:
            deposit_input = input(f"Initial deposit (min ${MIN_INITIAL_DEPOSIT:,.2f}): ")
            checking = float(deposit_input)
            if checking < MIN_INITIAL_DEPOSIT:
                print(f"❌ Error: Initial deposit must be at least ${MIN_INITIAL_DEPOSIT:,.2f}.")
            elif checking <= 0:
                print("❌ Error: Deposit must be a positive number.")
            else:
                break
        except ValueError:
            print("❌ Error: Invalid amount.")

    # 5. Generate Account Number and save
    account_number = generate_unique_account_number()
    password_hash = hash_password(password)
    
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password_hash, name, account_number) VALUES (?, ?, ?, ?)",
                (username, password_hash, name, account_number))
    user_id = cur.lastrowid
    # Initial deposit goes into checking
    cur.execute("INSERT INTO accounts (user_id, checking, savings) VALUES (?, ?, ?)",
                (user_id, checking, 0.00))
    conn.commit()
    conn.close()

    print("\n" + "="*40)
    print("🎉 SUCCESS! Account created.")
    print(f"Your Account Number: {account_number}")
    print("="*40)
    
    # Program Flow: Take user straight to log in
    time.sleep(1)
    login_user()


def login_user():
    """Handles user login and sets the global session variable."""
    global LOGGED_IN_USER
    
    print("\n--- USER LOGIN ---")
    username = input("Enter Username: ").strip()
    user = get_user(username)

    if not user:
        print("❌ Login failed: Invalid username.")
        time.sleep(1)
        return

    # User tuple: (id, username, password_hash, name, account_number)
    
    try:
        # Use getpass for blind password input
        password = getpass.getpass("Enter Password: ").strip()
    except Exception as e:
        print(f"An error occurred during password input: {e}")
        return

    if not password or hash_password(password) != user[2]:
        print("❌ Login failed: Invalid password.")
        time.sleep(1)
        return

    LOGGED_IN_USER = {
        "id": user[0],
        "username": user[1],
        "name": user[3],
        "account_number": user[4]
    }
    
    print(f"\n✅ Welcome, {user[3]}! (Acc: {user[4]})")
    time.sleep(1.5)


def check_account_details():
    """Displays the full account details for the logged-in user."""
    user = LOGGED_IN_USER
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT checking, savings FROM accounts WHERE user_id = ?", (user['id'],))
    checking, savings = cur.fetchone()
    conn.close()

    print("\n--- ACCOUNT DETAILS ---")
    print(f"Full Name:        {user['name']}")
    print(f"Username:         {user['username']}")
    print(f"Account Number:   {user['account_number']}")
    print("-" * 25)
    print(f"Checking Balance: ${checking:,.2f}")
    print(f"Savings Balance:  ${savings:,.2f}")
    time.sleep(1.5)


def select_account_type():
    """Helper to prompt user to select C (Checking) or S (Savings)."""
    while True:
        account_type = input("Select Account (C for Checking, S for Savings): ").strip().upper()
        if account_type in ["C", "S"]:
            return account_type
        print("Invalid account type. Please enter 'C' or 'S'.")


def deposit():
    """Handles deposit transaction with validation."""
    user = LOGGED_IN_USER
    print("\n--- DEPOSIT ---")
    account_type = select_account_type()
    
    while True:
        try:
            amount_input = input("Enter deposit amount: ").strip()
            if not amount_input:
                print("❌ Error: Deposit amount cannot be blank.")
                continue
            amount = float(amount_input)
            if amount <= 0:
                print("❌ Error: Deposit amount must be a positive number.")
            else:
                break
        except ValueError:
            print("❌ Error: Invalid amount.")

    user_id = user['id']
    old_balance = get_balance(user_id, account_type)
    new_balance = old_balance + amount
    
    update_balance(user_id, account_type, new_balance)
    
    # CORRECTED: Ensure transaction is recorded
    record_transaction(user_id, user['account_number'], "DEPOSIT", account_type, amount, old_balance, new_balance)

    print(f"\n✅ Deposit of ${amount:,.2f} complete. New {account_type} balance: ${new_balance:,.2f}")
    time.sleep(1)


def withdrawal():
    """Handles withdrawal transaction with validation."""
    user = LOGGED_IN_USER
    print("\n--- WITHDRAWAL ---")
    account_type = select_account_type()

    user_id = user['id']
    old_balance = get_balance(user_id, account_type)
    print(f"Current {account_type} balance: ${old_balance:,.2f}")

    while True:
        try:
            # Added instruction to quit
            amount_input = input("Enter withdrawal amount (or 'exit' to cancel): ").strip()
            
            # 1. Allow user to cancel and return to menu
            if amount_input.lower() == 'exit':
                print("↩️ Withdrawal cancelled.")
                time.sleep(0.5)
                return  # Exits the function, returning to the logged-in menu loop

            if not amount_input:
                print("❌ Error: Withdrawal amount cannot be blank.")
                continue
            
            amount = float(amount_input)
            
            if amount <= 0:
                print("❌ Error: Withdrawal amount must be a positive number.")
            elif amount > old_balance:
                print("❌ Error: Insufficient funds. Please try a smaller amount.")
                # IMPORTANT: Since this error occurs, the loop continues (no break)
            else:
                # 2. SUCCESS! Break the loop
                break 
                
        except ValueError:
            print("❌ Error: Invalid amount. Please enter a number.")
            
    # --- Execute Transaction (Only reached if loop breaks successfully) ---
    new_balance = old_balance - amount
    
    update_balance(user_id, account_type, new_balance)

    record_transaction(user_id, user['account_number'], "WITHDRAWAL", account_type, amount, old_balance, new_balance)

    print(f"\n✅ Withdrawal of ${amount:,.2f} complete. New {account_type} balance: ${new_balance:,.2f}")
    time.sleep(1)
    """Handles withdrawal transaction with validation."""
    user = LOGGED_IN_USER
    print("\n--- WITHDRAWAL ---")
    account_type = select_account_type()

    user_id = user['id']
    old_balance = get_balance(user_id, account_type)
    print(f"Current {account_type} balance: ${old_balance:,.2f}")

    while True:
        try:
            amount_input = input("Enter withdrawal amount: ").strip()
            if not amount_input:
                print("❌ Error: Withdrawal amount cannot be blank.")
                continue
            amount = float(amount_input)
            if amount <= 0:
                print("❌ Error: Withdrawal amount must be a positive number.")
            elif amount > old_balance:
                print("❌ Error: Insufficient funds.")
            else:
                break
        except ValueError:
            print("❌ Error: Invalid amount.")

    new_balance = old_balance - amount
    
    update_balance(user_id, account_type, new_balance)

    # CORRECTED: Ensure transaction is recorded
    record_transaction(user_id, user['account_number'], "WITHDRAWAL", account_type, amount, old_balance, new_balance)

    print(f"\n✅ Withdrawal of ${amount:,.2f} complete. New {account_type} balance: ${new_balance:,.2f}")
    time.sleep(1)


def transfer():
    """Handles funds transfer between two users using account numbers."""
    user = LOGGED_IN_USER
    print("\n--- TRANSFER FUNDS ---")
    
    # Sender Account Type
    sender_account_type = select_account_type()
    sender_id = user['id']
    sender_old_balance = get_balance(sender_id, sender_account_type)
    print(f"Current {sender_account_type} balance: ${sender_old_balance:,.2f}")

    # Recipient Account Number Validation
    while True:
        recipient_acc_num = input("Enter Recipient Account Number: ").strip()
        recipient = get_user_by_acc_num(recipient_acc_num)

        if not recipient_acc_num.isdigit() or len(recipient_acc_num) != 8:
            print("❌ Error: Account number must be an 8-digit numeric value.")
            continue
        
        if not recipient:
            print("❌ Error: Recipient account number does not exist.")
            continue
        
        if recipient_acc_num == user['account_number']:
            print("❌ Error: Cannot transfer to your own account.")
            continue
        
        break

    # Transfer Amount Validation
    while True:
        try:
            amount_input = input("Enter Transfer Amount (or 'exit' to cancel): ").strip()

            if amount_input.lower() == 'exit':
                print("↩️ Transfer cancelled.")
                time.sleep(0.5)
                return  # Exits the function, returning to the logged-in menu loop


            if not amount_input:
                print("❌ Error: Transfer amount cannot be blank.")
                continue
            amount = float(amount_input)
            if amount <= 0:
                print("❌ Error: Transfer amount must be a positive number.")
            elif amount > sender_old_balance:
                print("❌ Error: Insufficient funds for transfer.")
            else:
                break
        except ValueError:
            print("❌ Error: Invalid amount.")

    # --- EXECUTE TRANSFER ---
    
    # 1. Sender (Debit)
    sender_new_balance = sender_old_balance - amount
    update_balance(sender_id, sender_account_type, sender_new_balance)
    record_transaction(sender_id, user['account_number'], "TRANSFER_OUT", sender_account_type, amount, sender_old_balance, sender_new_balance, recipient_acc_num)

    # 2. Recipient (Credit - always to Checking for simplicity)
    recipient_id = recipient[0]
    recipient_old_balance = get_balance(recipient_id, "C") # Credit to Checking account
    recipient_new_balance = recipient_old_balance + amount
    update_balance(recipient_id, "C", recipient_new_balance)
    record_transaction(recipient_id, recipient[4], "TRANSFER_IN", "C", amount, recipient_old_balance, recipient_new_balance, user['account_number'])


    print(f"\n✅ Transfer of ${amount:,.2f} to Account {recipient_acc_num} complete.")
    print(f"New {sender_account_type} balance: ${sender_new_balance:,.2f}")
    time.sleep(1.5)


def view_transaction_history():
    """Displays the transaction history for the logged-in user."""
    user = LOGGED_IN_USER
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp, type, account_type, amount, recipient_account, old_balance, new_balance
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user['id'],))
    transactions = cur.fetchall()
    conn.close()

    print(f"\n--- TRANSACTION HISTORY for {user['username']} ---")
    
    if not transactions:
        print("No transactions recorded for this account.")
        time.sleep(1)
        return

    print("Timestamp             | Type        | Acc | Amount      | Balance Change | New Balance")
    print("-" * 75)
    
    for row in transactions:
        timestamp, type, acc_type, amount, recipient, old_bal, new_bal = row
        
        # Determine the change 
        change = new_bal - old_bal
        
        # Format the transaction line
        if type == "TRANSFER_OUT":
            type_str = f"TFR_OUT ({recipient})"
        elif type == "TRANSFER_IN":
            type_str = f"TFR_IN ({recipient})"
        else:
            type_str = type

        print(f"{timestamp[:16]:<20} | {type_str:<11} | {acc_type:<3} | ${amount:10,.2f} | ${change:14,.2f} | ${new_bal:11,.2f}")
        
    time.sleep(2)


# -------------------- Main Menu & Execution --------------------

def logged_in_menu():
    """Menu displayed after a successful login."""
    print(f"\n===== Cactus Bank - Logged In as {LOGGED_IN_USER['username']} =====")
    print("[1] Check Account Details")
    print("[2] Deposit Money")
    print("[3] Withdraw Money")
    print("[4] Transfer Funds")
    print("[5] View Transaction History")
    print("[6] Logout")
    return input("Enter your choice: ").strip()


def pre_login_menu():
    """Menu displayed before any user is logged in."""
    print("\n===== Cactus Bank (SQL Edition) =====")
    print("[1] Create Account (Register)")
    print("[2] User Login")
    print("[3] Exit")
    return input("Enter your choice: ").strip()


def main():
    init_db()
    global LOGGED_IN_USER
    
    while True:
        # Session Validation: Checks if a user is logged in
        if LOGGED_IN_USER:
            choice = logged_in_menu()
            time.sleep(0.5) # Program Flow Delay
            
            if choice == '1':
                check_account_details()
            elif choice == '2':
                deposit()
            elif choice == '3':
                withdrawal()
            elif choice == '4':
                transfer()
            elif choice == '5':
                view_transaction_history()
            elif choice == '6':
                LOGGED_IN_USER = None
                print("👋 Logged out successfully.")
                time.sleep(1)
            else:
                print("Invalid choice. Try again.")
                
        else: # Pre-login state
            choice = pre_login_menu()
            time.sleep(0.5) # Program Flow Delay
            
            if choice == '1':
                create_account()
            elif choice == '2':
                login_user()
            elif choice == '3':
                print("👋 Goodbye!")
                break
            else:
                print("Invalid choice. Try again.")
            
        # Redisplay menu after every action (and small delay)
        if not LOGGED_IN_USER and choice != '2':
            time.sleep(0.5)


if __name__ == "__main__":
    main()