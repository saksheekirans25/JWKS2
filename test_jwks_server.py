import unittest
from unittest.mock import patch, MagicMock
import json
import jwt
import main
import time

class TestJWKSServer(unittest.TestCase):

    @patch('main.sign_jwt')
    def test_generate_jwt(self, mock_sign_jwt):
        mock_sign_jwt.return_value = 'mocked_token'
        token = main.sign_jwt({'user': 'username', 'exp': int(time.time()) + 3600}, 'secret')
        self.assertEqual(token, 'mocked_token')

    @patch('sqlite3.connect')
    def test_get_jwks(self, mock_connect):
        mock_cursor = MagicMock()
        mock_connect.return_value.cursor.return_value = mock_cursor
        
        # Simulate fetching one valid key from the database
        current_time = int(time.time())
        mock_cursor.fetchall.return_value = [
            (b'mock_private_key', current_time + 3600)  # A valid key
        ]

        with patch('main.int_to_base64', side_effect=['mock_n', 'mock_e']):
            with patch('cryptography.hazmat.primitives.serialization.load_pem_private_key') as mock_load_key:
                # Mock the return value of the public key's public_numbers method
                mock_private_key = MagicMock()
                mock_private_key.public_key.return_value.public_numbers.return_value = MagicMock(n=123456, e=65537)
                mock_load_key.return_value = mock_private_key

                valid_keys = main.MyServer.get_valid_keys(main.MyServer)  # Call instance method
                print("Valid Keys Retrieved:", valid_keys)  # Debug output
                self.assertEqual(len(valid_keys), 1)
                self.assertEqual(valid_keys[0]["kid"], str(current_time + 3600))

    @patch('sqlite3.connect')
    def test_store_private_key(self, mock_connect):
        mock_cursor = mock_connect.return_value.cursor.return_value
        
        # Call the function to store a key
        main.generate_and_store_key(int(time.time()) + 3600)
        
        # Check that the execute method was called with the expected query
        print("Cursor Called:", mock_cursor.execute.call_args)  # Debug output
        mock_cursor.execute.assert_called_once()
        args, _ = mock_cursor.execute.call_args[0]
        self.assertIn("INSERT INTO keys (key, exp) VALUES (?, ?)", args[0])

if __name__ == '__main__':
    unittest.main()
