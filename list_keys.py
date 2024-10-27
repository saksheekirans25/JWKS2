import sqlite3

DATABASE = 'totally_not_my_privateKeys.db'  # Ensure this is the correct path to your database

def list_keys():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Query to get all keys
        cursor.execute("SELECT kid FROM keys")
        keys = cursor.fetchall()
        return keys

all_keys = list_keys()

if all_keys:
    print("Key IDs in the database:")
    for key in all_keys:
        print(key[0])  # Print each key ID
else:
    print("No keys found in the database.")
