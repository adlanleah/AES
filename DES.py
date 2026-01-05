from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


def choose_key():
    print("\nChoose Secret Key Option:")
    print("1. Enter key manually")
    print("2. Generate random key")

    choice = input("Select option (1 or 2): ")

    if choice == '1':
        key_input = input("Enter an 8-character key: ")
        if len(key_input) != 8:
            print("Key must be exactly 8 characters")
            return choose_key()
        return key_input.encode()

    elif choice == '2':
        key = get_random_bytes(8)
        print("Random Secret Key (Base64):",
              base64.b64encode(key).decode())
        return key

    else:
        print("Invalid choice!")
        return choose_key()


def encrypt_text():
    plaintext = input("\nEnter text to encrypt: ")
    key = choose_key()

    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)

    encrypted_text = base64.b64encode(encrypted_bytes).decode()
    print("\nEncrypted Text:", encrypted_text)


def decrypt_text():
    ciphertext = input("\nEnter text to decrypt: ")
    key = choose_key()

    cipher = DES.new(key, DES.MODE_ECB)
    decoded_bytes = base64.b64decode(ciphertext)
    decrypted_padded = cipher.decrypt(decoded_bytes)

    decrypted_text = unpad(decrypted_padded, DES.block_size).decode()
    print("\nDecrypted Text:", decrypted_text)


def main():
    print("DES Program")
    print("1. Encrypt Text")
    print("2. Decrypt Text")

    choice = input("Choose an option (1 or 2): ")

    if choice == '1':
        encrypt_text()
    elif choice == '2':
        decrypt_text()
    else:
        print("Invalid choice!")
if __name__ == "__main__":
    main()
