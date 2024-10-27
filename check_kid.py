import sqlite3

DATABASE = 'totally_not_my_privateKeys.db'

def check_kid(kid):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM keys WHERE kid = ?", (kid,))
        result = cursor.fetchone()
        if result:
            print(f"Key ID found: {result}")
        else:
            print("Key ID not found in the database.")

# Replace 'expected_kid' with the actual key ID you're checking
check_kid('valid_key')  # Example key ID
