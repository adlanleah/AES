from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


def get_key_from_user(prompt="Enter secret key (minimum 16 characters): "):
    while True:
        try:
            # Get key input from user
            key_input = input(prompt)
            
            # Validate minimum length (128-bit = 16 bytes)
            if len(key_input) < 16:
                print("Error: Key must be at least 16 characters (128-bit)")
                continue
            
            # Convert string to bytes using UTF-8 encoding
            # UTF-8 encoding converts text characters to byte representation
            key_bytes = key_input.encode('utf-8')
            
            # Truncate key to valid AES size (16, 24, or 32 bytes)
            # AES only accepts these specific key lengths
            if len(key_bytes) > 32:
                key_bytes = key_bytes[:32]  # Use first 32 bytes for AES-256
            elif len(key_bytes) > 24:
                key_bytes = key_bytes[:24]  # Use first 24 bytes for AES-192
            elif len(key_bytes) > 16:
                key_bytes = key_bytes[:16]  # Use first 16 bytes for AES-128
            
            # Display the key size being used
            print(f"Using {len(key_bytes)*8}-bit key")
            return key_bytes
            
        except Exception as e:
            print(f"Error reading key: {e}")


def get_iv_from_user(allow_random=True):
    print("\n" + "=" * 50)
    print("IV Configuration")
    print("=" * 50)
    print("IV must be exactly 16 bytes (128 bits).")
    print("Choose input format:")
    print("1. Random IV ")
    print("2. Enter IV manually")
    print("=" * 50)
    
    while True:
        choice = input("\nChoose option (1 or 2): ").strip()
        
        if choice == "1" and allow_random:
            # Generate cryptographically secure random IV
            # get_random_bytes() uses the operating system's secure random generator
            # This ensures the IV is unpredictable and suitable for cryptographic use
            iv = get_random_bytes(16)
            print(f"Generated random IV: {iv.hex()}")
            return iv
            
        elif choice == "2":
            print("\nEnter a 16 character IV:")
            print()
            
            iv_input = input("Enter IV: ").strip()
            
            try:
                # Try to detect and parse the IV format
                
                # Option 1: Hex format (32 hex characters)
                # Hexadecimal uses 0-9 and A-F, 2 hex chars = 1 byte
                if len(iv_input) == 32 and all(c in '0123456789abcdefABCDEF' for c in iv_input):
                    # bytes.fromhex() converts hex string to bytes
                    iv = bytes.fromhex(iv_input)
                    print(f"Using hex IV: {iv.hex()}")
                    return iv
                
                # Option 2: Base64 format
                # Base64 encodes binary data as ASCII text (A-Z, a-z, 0-9, +, /)
                try:
                    # base64.b64decode() converts Base64 string back to bytes
                    iv = base64.b64decode(iv_input)
                    if len(iv) == 16:
                        print(f"Using Base64 IV: {iv.hex()}")
                        return iv
                    else:
                        print(f"Note: Base64 decoded to {len(iv)} bytes, using as text instead")
                except:
                    pass  # Not valid Base64, try next format
                
                # Option 3: Text format (convert to bytes) - DEFAULT
                # Converts text string to bytes using UTF-8 encoding
                iv_bytes = iv_input.encode('utf-8')
                if len(iv_bytes) >= 16:
                    # Use first 16 bytes if input is longer
                    iv = iv_bytes[:16]
                    print(f"Using text IV: {iv.hex()}")
                    return iv
                else:
                    print(f"Error: Need at least 16 bytes, got {len(iv_bytes)}")
                    
            except Exception as e:
                print(f"Error processing IV: {e}")
        else:
            print("Invalid choice. Please enter 1 or 2.")


def encrypt_aes(plaintext, key, iv, output_format='both'):
    try:
        # Step 1: Create AES cipher object with CBC mode
        # This initializes the encryption engine with our key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Step 2: Pad plaintext to multiple of AES block size (16 bytes)
        # First converts string to bytes, then adds PKCS7 padding
        padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
        
        # Step 3: Encrypt the padded plaintext
        # This is where the actual encryption happens
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Step 4: Return encrypted data in requested format
        # Different formats for different use cases
        if output_format == 'ciphertext_only':
            # Most common format: just ciphertext (IV sent separately)
            return ciphertext, iv
        elif output_format == 'full':
            # Combined format: IV prepended to ciphertext
            return iv + ciphertext, iv
        else:  # 'both'
            # Show both formats for comparison
            return {
                'ciphertext_only': ciphertext,
                'full_output': iv + ciphertext,
                'iv': iv
            }, iv
            
    except Exception as e:
        print(f"Encryption error: {e}")
        return None, None


def decrypt_aes(encrypted_data, key, iv=None):
    try:
        # Step 1: Determine input format and extract IV and ciphertext
        if iv is not None:
            # Format 1: IV provided separately, encrypted_data is just ciphertext
            ciphertext = encrypted_data
        else:
            # Format 2: IV prepended to ciphertext (first 16 bytes)
            # Extract IV from beginning of encrypted data
            iv = encrypted_data[:AES.block_size]
            # Extract ciphertext (everything after first 16 bytes)
            ciphertext = encrypted_data[AES.block_size:]
        
        # Step 2: Create AES cipher object with same parameters as encryption
        # Key, mode, and IV must match exactly what was used to encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Step 3: Decrypt the ciphertext
        # This reverses the encryption, giving us padded plaintext
        decrypted_padded = cipher.decrypt(ciphertext)
        
        # Step 4: Remove PKCS7 padding
        # This also validates the padding is correct (detects wrong key)
        decrypted = unpad(decrypted_padded, AES.block_size)
        
        # Step 5: Convert bytes back to string
        # Reverses the UTF-8 encoding from encryption
        plaintext = decrypted.decode('utf-8')
        
        return plaintext, iv
        
    except ValueError as e:
        # unpad() raises ValueError if padding is invalid
        # This usually means wrong key, wrong IV, or corrupted data
        print(f"Decryption error: {e}")
        print("This indicates wrong key or IV")
        return None, None
    except Exception as e:
        print(f"Decryption error: {e}")
        return None, None


def encryption_mode():
    print("=" * 60)
    print("ENCRYPTION MODE")
    print("=" * 60)
    
    # Step 1: Get plaintext message
    plaintext = input("Enter plaintext message to encrypt: ")
    
    # Step 2: Get secret key from user
    # Key will be validated and truncated to appropriate AES size
    key = get_key_from_user()
    
    # Step 3: Get IV
    # User can choose random generation or manual entry
    iv = get_iv_from_user()
    
    # Step 4: Choose output format
    print("\n" + "=" * 50)
    print("Output Format Selection")
    print("=" * 50)
    print("Choose how to output the encrypted data:")
    print("1. Ciphertext only (IV separate)")
    print("2. IV + Ciphertext (combined)")
    print("3. Show both formats")
    print("=" * 50)
    
    while True:
        format_choice = input("\nChoose output format (1, 2, or 3): ").strip()
        if format_choice == '1':
            output_format = 'ciphertext_only'
            break
        elif format_choice == '2':
            output_format = 'full'
            break
        elif format_choice == '3':
            output_format = 'both'
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Step 5: Encrypt the plaintext
    print("\n" + "=" * 60)
    print("Encrypting...")
    print(f"Using IV: {iv.hex()}")
    
    # Call encryption function
    encrypted_result, iv_used = encrypt_aes(plaintext, key, iv, output_format)
    
    # Step 6: Display results
    if encrypted_result:
        print("\n" + "=" * 60)
        print("ENCRYPTION COMPLETE")
        print("=" * 60)
        
        if output_format == 'both':
            # Show both ciphertext-only and combined formats
            ciphertext_only_b64 = base64.b64encode(encrypted_result['ciphertext_only']).decode()
            full_output_b64 = base64.b64encode(encrypted_result['full_output']).decode()
            iv_b64 = base64.b64encode(iv_used).decode()
            
            print(f"\n1. CIPHERTEXT ONLY:")
            print(f"   Ciphertext: {ciphertext_only_b64}")
            print(f"   IV: {iv_b64}")
            print(f"   IV (hex): {iv_used.hex()}")
            print()
            
            print(f"2. FULL OUTPUT (IV + ciphertext):")
            print(f"   {full_output_b64}")
            print(f"   Length: {len(full_output_b64)} Base64 chars")
            
        elif output_format == 'ciphertext_only':
            # Ciphertext and IV displayed separately
            ciphertext_b64 = base64.b64encode(encrypted_result).decode()
            iv_b64 = base64.b64encode(iv_used).decode()
            
            print(f"\nCIPHERTEXT ONLY:")
            print(f"   Ciphertext: {ciphertext_b64}")
            print(f"   IV: {iv_b64}")
            print(f"   IV (hex): {iv_used.hex()}")
            print(f"\nIMPORTANT: Save BOTH the ciphertext AND IV!")
            print(f"   You need both to decrypt later.")
            
        else:  # 'full'
            # IV and ciphertext combined in single output
            full_b64 = base64.b64encode(encrypted_result).decode()
            
            print(f"\nFULL OUTPUT (IV + ciphertext):")
            print(f"   {full_b64}")
            print(f"   Length: {len(full_b64)} Base64 chars")
            print(f"   First 24 chars are IV: {full_b64[:24]}")
        
        print("\n" + "=" * 60)
        print("READY FOR DECRYPTION")
        print("=" * 60)
        print("To decrypt, you will need:")
        print(f"1. The encrypted data (above)")
        print(f"2. The secret key")
        
        if output_format == 'ciphertext_only':
            print(f"3. The IV")


def decryption_mode():
    print("=" * 60)
    print("DECRYPTION MODE")
    print("=" * 60)
    
    # Step 1: Get encrypted data from user
    print("\nEnter the encrypted data:")
    print("1. If you have ciphertext only, enter Base64 string")
    print("2. If you have IV + ciphertext, enter Base64 string")
    print()
    
    encrypted_b64 = input("Enter encrypted data (Base64): ").strip()
    
    # Step 2: Decode Base64 to bytes
    # Base64 is used because encrypted data contains non-printable bytes
    try:
        encrypted_data = base64.b64decode(encrypted_b64)
        print(f"Successfully decoded {len(encrypted_data)} bytes")
    except:
        print("Error: Invalid Base64 string")
        return
    
    # Step 3: Determine format
    print("\nWhat format is your encrypted data?")
    print("1. Ciphertext only (need separate IV)")
    print("2. IV + Ciphertext (all in one)")
    print()
    print(f"Your data is {len(encrypted_data)} bytes")
    
    while True:
        format_choice = input("\nChoose format (1 or 2): ").strip()
        
        if format_choice == '1':
            # Format 1: Ciphertext only - IV needed separately
            print("\nSince you chose ciphertext only, you need to provide the IV")
            print("The IV is 16 bytes (hex or Base64 chars)") 
            iv_b64 = input("Enter IV (Base64 or hex): ").strip()
            
            try:
                # Try to decode IV as hex first, then Base64
                if len(iv_b64) == 32 and all(c in '0123456789abcdefABCDEF' for c in iv_b64):
                    # Hex format: convert hex string to bytes
                    iv = bytes.fromhex(iv_b64)
                else:
                    # Base64 format: decode Base64 to bytes
                    iv = base64.b64decode(iv_b64)
                
                # Validate IV length
                if len(iv) != 16:
                    print(f"Error: IV must be 16 bytes, got {len(iv)}")
                    return
                
                # Get decryption key
                key = get_key_from_user("Enter secret key for decryption: ")
                
                # Decrypt using separate IV
                decrypted, iv_used = decrypt_aes(encrypted_data, key, iv)
                
                if decrypted:
                    print(f"\n Decrypted message: {decrypted}")
                else:
                    print(" Decryption failed - check your key and IV")
                
                return
                
            except Exception as e:
                print(f"Error processing IV: {e}")
                return
                
        elif format_choice == '2':
            # Format 2: IV prepended to ciphertext
            # Get decryption key
            key = get_key_from_user("Enter secret key for decryption: ")
            
            # Decrypt (IV will be extracted from encrypted_data)
            decrypted, iv = decrypt_aes(encrypted_data, key)
            
            if decrypted:
                print(f"\n Decrypted message: {decrypted}")
            else:
                print(" Decryption failed - check your key")
            
            return
            
        else:
            print("Invalid choice. Please enter 1 or 2.")


def main():
    while True:
        print("\n" + "=" * 60)
        print("AES ENCRYPTION/DECRYPTION")
        print("=" * 60)
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        print("=" * 60)
        
        choice = input("\nChoose option (1, 2, or 3): ").strip()
        
        if choice == '1':
            encryption_mode()
        elif choice == '2':
            decryption_mode()
        elif choice == '3':
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    
    main()