import os
import random
import math
import json
import struct
import base64
import hashlib

# --- File Headers ---
PUBLIC_KEY_HEADER = "-----BEGIN SAF PUBLIC KEY-----"
PUBLIC_KEY_FOOTER = "-----END SAF PUBLIC KEY-----"
PRIVATE_KEY_HEADER = "-----BEGIN SAF PRIVATE KEY-----"
PRIVATE_KEY_FOOTER = "-----END SAF PRIVATE KEY-----"
MESSAGE_HEADER = "-----BEGIN SAF ENCRYPTED MESSAGE-----"
MESSAGE_FOOTER = "-----END SAF ENCRYPTED MESSAGE-----"


# --- Mathematical Primitives ---

def _gcd(a, b):
    """Finds the greatest common divisor (GCD) of a and b."""
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a, b):
    """
    Computes GCD(a, b) and coefficients x, y such that ax + by = GCD(a, b).
    Used to find the modular inverse.
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def _mod_inverse(a, m):
    """Finds the modular multiplicative inverse of a modulo m."""
    gcd_val, x, y = _extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _power(base, exp, mod):
    """Computes (base^exp) % mod using modular exponentiation."""
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


def _is_prime_miller_rabin(n, k=5):
    """
    Probabilistic primality test using Miller-Rabin algorithm.
    Higher k increases confidence.
    """
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = int.from_bytes(os.urandom(math.ceil(math.log2(n - 1) / 8)), 'big') % (n - 3) + 2
        x = _power(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = _power(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits):
    """Generates a random prime number of the specified bit length."""
    while True:
        num_bytes = bits // 8 + (1 if bits % 8 else 0)
        num = int.from_bytes(os.urandom(num_bytes), 'big')

        num = num % (1 << bits)
        num |= (1 << (bits - 1)) | 1

        if _is_prime_miller_rabin(num):
            return num


# --- Key Generation and Saving/Loading ---

def generate_key_pair(bits):
    """Generates an SAF public and private key pair."""

    prime_bits = bits // 2
    if prime_bits < 2:
        print("Error: Key length is too small for prime generation. Minimum 6 bits per prime factor.")
        return None, None

    p = _generate_prime(prime_bits)
    q = _generate_prime(prime_bits)

    while p == q:
        q = _generate_prime(prime_bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while _gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = _mod_inverse(e, phi)

    public_key = {'e': e, 'n': n}
    private_key = {'d': d, 'n': n}

    print("Key pair successfully generated.")
    return public_key, private_key


def save_key(key, filename, is_private=False):
    """
    Saves a key to a file with appropriate headers and Base64 encoding.
    Automatically appends .pub or .priv extension.
    """

    if is_private and not filename.endswith('.priv'):
        filename += '.priv'
    elif not is_private and not filename.endswith('.pub'):
        filename += '.pub'

    key_data = {k: str(v) for k, v in key.items()}
    json_str = json.dumps(key_data, indent=4)
    encoded_data = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

    header = PRIVATE_KEY_HEADER if is_private else PUBLIC_KEY_HEADER
    footer = PRIVATE_KEY_FOOTER if is_private else PUBLIC_KEY_FOOTER

    try:
        with open(filename, 'w') as f:
            f.write(header + "\n")
            f.write(encoded_data + "\n")
            f.write(footer + "\n")
        print(f"Key saved to {filename}")
    except IOError as e:
        print(f"Error saving key to {filename}: {e}")


def load_key(filename):
    """Loads a key from a file, decodes Base64, and removes headers."""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()

        if not lines:
            print(f"Error: File '{filename}' is empty.")
            return None

        if PUBLIC_KEY_HEADER.strip() in lines[0].strip():
            header = PUBLIC_KEY_HEADER
            footer = PUBLIC_KEY_FOOTER
        elif PRIVATE_KEY_HEADER.strip() in lines[0].strip():
            header = PRIVATE_KEY_HEADER
            footer = PRIVATE_KEY_FOOTER
        else:
            print(f"Error: File '{filename}' is not an SAF key or has an invalid header.")
            return None

        content_lines = []
        in_content = False
        for line in lines:
            if line.strip() == header.strip():
                in_content = True
                continue
            if line.strip() == footer.strip():
                in_content = False
                break
            if in_content:
                content_lines.append(line.strip())

        if not content_lines:
            print(f"Error: No key data found between headers in file '{filename}'.")
            return None

        encoded_data = "".join(content_lines)
        decoded_bytes = base64.b64decode(encoded_data)
        key_data_str = decoded_bytes.decode('utf-8')

        key_data = json.loads(key_data_str)
        key_data = {k: int(v) for k, v in key_data.items()}

        print(f"Key loaded from {filename}")
        return key_data
    except FileNotFoundError:
        print(f"Error: Key file '{filename}' not found.")
        return None
    except (json.JSONDecodeError, ValueError, base64.binascii.Error) as e:
        print(f"Error: Invalid key data format in '{filename}': {e}")
        return None


# --- Helper Functions for Bytes and Integers ---

def _bytes_to_int(data):
    """Converts bytes to a large integer."""
    return int.from_bytes(data, 'big')


def _int_to_bytes(num, length):
    """Converts a large integer to bytes of a specified length."""
    return num.to_bytes(length, 'big')


def calculate_sha256(data_or_filepath, is_filepath=True):
    """Calculates the SHA-256 hash of data or a file."""
    hasher = hashlib.sha256()
    if is_filepath:
        try:
            with open(data_or_filepath, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.digest()
        except FileNotFoundError:
            print(f"Error: File '{data_or_filepath}' not found.")
            return None
        except IOError as e:
            print(f"Error reading file '{data_or_filepath}': {e}")
            return None
    else:
        hasher.update(data_or_filepath)
        return hasher.digest()


# --- Encryption ---

def encrypt_data(data_bytes, public_key_recipient, private_signing_key=None):
    """
    Encrypts data bytes using the recipient's PUBLIC key.
    Optionally signs the data with the sender's PRIVATE key
    or includes an encrypted hash for integrity verification.
    """
    e = public_key_recipient['e']
    n_pub_recipient = public_key_recipient['n']

    data_hash = hashlib.sha256(data_bytes).digest()

    is_signed_message_flag = 0
    hash_payload_bytes = b''

    if private_signing_key:
        is_signed_message_flag = 1
        d_sig = private_signing_key['d']
        n_sig = private_signing_key['n']

        if _bytes_to_int(data_hash) >= n_sig:
            raise ValueError(
                f"Hash ({len(data_hash)} bytes) is too large to be signed by this private key (modulus n_sig = {n_sig.bit_length() // 8} bytes)."
            )

        signed_hash_int = _power(_bytes_to_int(data_hash), d_sig, n_sig)
        hash_payload_bytes = _int_to_bytes(signed_hash_int,
                                           n_sig.bit_length() // 8 + (1 if n_sig.bit_length() % 8 else 0))
    else:
        if _bytes_to_int(data_hash) >= n_pub_recipient:
            print(
                f"Warning: Recipient's public key modulus ({n_pub_recipient.bit_length()} bits) is smaller than SHA-256 hash size (256 bits). "
                "Hash will be truncated for integrity check. This reduces reliability of the check."
            )
            data_hash_to_encrypt = data_hash[:(n_pub_recipient.bit_length() // 8)]
            if not data_hash_to_encrypt:
                raise ValueError("Public key modulus is too small to encrypt even part of the hash.")
        else:
            data_hash_to_encrypt = data_hash

        encrypted_hash_int = _power(_bytes_to_int(data_hash_to_encrypt), e, n_pub_recipient)
        hash_payload_bytes = _int_to_bytes(encrypted_hash_int, n_pub_recipient.bit_length() // 8 + (
            1 if n_pub_recipient.bit_length() % 8 else 0))

    block_size_bytes = (n_pub_recipient.bit_length() - 1) // 8
    if block_size_bytes == 0: block_size_bytes = 1

    remaining_bytes = len(data_bytes) % block_size_bytes
    padding_len = block_size_bytes - remaining_bytes
    if remaining_bytes == 0:
        padding_len = block_size_bytes

    data_bytes_padded = data_bytes + bytes([padding_len]) * padding_len

    encrypted_blocks = []
    for i in range(0, len(data_bytes_padded), block_size_bytes):
        block = data_bytes_padded[i: i + block_size_bytes]
        m = _bytes_to_int(block)
        c = _power(m, e, n_pub_recipient)
        encrypted_blocks.append(c)

    ciphertext_block_size = n_pub_recipient.bit_length() // 8 + (1 if n_pub_recipient.bit_length() % 8 else 0)
    encrypted_payload_bytes_list = []
    for block_val in encrypted_blocks:
        encrypted_payload_bytes_list.append(_int_to_bytes(block_val, ciphertext_block_size))
    encrypted_payload_bytes = b"".join(encrypted_payload_bytes_list)

    header_main = struct.pack('>I B B', len(data_bytes), padding_len, is_signed_message_flag)
    header_hash_len = struct.pack('>I', len(hash_payload_bytes))

    full_encrypted_bytes = header_main + header_hash_len + hash_payload_bytes + encrypted_payload_bytes
    return full_encrypted_bytes


# --- Decryption ---

def decrypt_data(encrypted_bytes_payload, private_key_recipient, public_signing_key=None):
    """
    Decrypts bytes using the recipient's PRIVATE key.
    Verifies integrity based on the mode (signed/unsigned).
    """
    d = private_key_recipient['d']
    n_priv_recipient = private_key_recipient['n']

    if len(encrypted_bytes_payload) < 10:
        raise ValueError("Invalid encrypted data format: header too short.")

    header_main = encrypted_bytes_payload[:6]
    original_data_len, padding_len, is_signed_flag = struct.unpack('>I B B', header_main)

    header_hash_len_bytes = encrypted_bytes_payload[6:10]
    hash_payload_len = struct.unpack('>I', header_hash_len_bytes)[0]

    if len(encrypted_bytes_payload) < 10 + hash_payload_len:
        raise ValueError("Invalid encrypted data format: hash payload truncated.")

    hash_payload_bytes = encrypted_bytes_payload[10: 10 + hash_payload_len]
    encrypted_payload_only = encrypted_bytes_payload[10 + hash_payload_len:]

    ciphertext_block_size = n_priv_recipient.bit_length() // 8 + (1 if n_priv_recipient.bit_length() % 8 else 0)

    if len(encrypted_payload_only) % ciphertext_block_size != 0:
        raise ValueError("Length of encrypted data (message) is not a multiple of block size.")

    decrypted_blocks = []
    for i in range(0, len(encrypted_payload_only), ciphertext_block_size):
        block_bytes = encrypted_payload_only[i: i + ciphertext_block_size]
        c = _bytes_to_int(block_bytes)
        m = _power(c, d, n_priv_recipient)
        decrypted_blocks.append(m)

    block_size_bytes_for_data = (n_priv_recipient.bit_length() - 1) // 8
    if block_size_bytes_for_data == 0: block_size_bytes_for_data = 1

    decrypted_full_data = b""
    for block_val in decrypted_blocks:
        decrypted_full_data += _int_to_bytes(block_val, block_size_bytes_for_data)

    if len(decrypted_full_data) < padding_len:
        print(
            "Warning: Decrypted payload is shorter than expected (original data + padding). Data might be corrupted or wrong key used. Attempting partial recovery.")
        final_decrypted_data = decrypted_full_data
    else:
        detected_padding_val = decrypted_full_data[-1]

        padding_is_valid = True
        if detected_padding_val <= 0 or detected_padding_val > block_size_bytes_for_data:
            padding_is_valid = False
        else:
            for i in range(1, detected_padding_val + 1):
                if decrypted_full_data[-i] != detected_padding_val:
                    padding_is_valid = False
                    break

        if not padding_is_valid:
            print(
                "Warning: Invalid padding detected. Data might be corrupted or wrong key used. Reverting to header's padding length.")
            detected_padding_val = padding_len
            if detected_padding_val > len(decrypted_full_data):
                detected_padding_val = 0
                print("Header padding length also invalid or too large. No padding removed.")

        final_decrypted_data = decrypted_full_data[:-detected_padding_val]

    if len(final_decrypted_data) != original_data_len:
        print(
            f"Warning: Final decrypted data length ({len(final_decrypted_data)}) after padding removal does not match original length ({original_data_len}). "
            "Data may have been altered or corrupted. Truncating to original length for integrity check."
        )
        final_decrypted_data = final_decrypted_data[:original_data_len]

    print(
        f"\nComputed SHA-256 hash of decrypted data: {calculate_sha256(final_decrypted_data, is_filepath=False).hex()}"
    )

    if is_signed_flag == 1:
        if not public_signing_key:
            print("Error: Sender's public key is required for signature verification.")
            print("Data integrity check was skipped - no signature key provided.")
            return final_decrypted_data

        e_sig = public_signing_key['e']
        n_sig = public_signing_key['n']

        signed_hash_int = _bytes_to_int(hash_payload_bytes)

        if signed_hash_int >= n_sig:
            print(
                "Signature verification error: Decrypted signed hash is too large for sender's public key modulus. Possibly wrong key or corruption."
            )
            print("Data integrity check failed - invalid signature.")
            return final_decrypted_data

        retrieved_hash_int = _power(signed_hash_int, e_sig, n_sig)
        retrieved_hash = _int_to_bytes(retrieved_hash_int, 32)

        computed_hash = hashlib.sha256(final_decrypted_data).digest()

        if retrieved_hash == computed_hash:
            print("Data integrity (signature) check: SUCCESS! Data has not been altered and is signed by the sender.")
        else:
            print(
                "Data integrity (signature) check: FAILED! Data may have been altered or the wrong sender's key was used."
            )
            print(f"Expected hash from signature: {retrieved_hash.hex()}")
            print(f"Computed hash of decrypted data: {computed_hash.hex()}")
    else:
        retrieved_hash_int = _power(_bytes_to_int(hash_payload_bytes), d, n_priv_recipient)

        hash_part_len = min(32, n_priv_recipient.bit_length() // 8 + (1 if n_priv_recipient.bit_length() % 8 else 0))
        retrieved_hash_actual = _int_to_bytes(retrieved_hash_int, hash_part_len)

        computed_hash_full = hashlib.sha256(final_decrypted_data).digest()
        computed_hash_actual = computed_hash_full[:len(retrieved_hash_actual)]

        if retrieved_hash_actual == computed_hash_actual:
            print("Data integrity (unsigned) check: SUCCESS! Data has not been corrupted.")
        else:
            print("Data integrity (unsigned) check: FAILED! Data may have been corrupted.")
            print(f"Expected hash from header: {retrieved_hash_actual.hex()}")
            print(f"Computed hash of decrypted data (partial): {computed_hash_actual.hex()}")

    return final_decrypted_data


# --- User Interface and File Operations ---

def list_files_for_choice(extension=None, exclude_extensions=None):
    """Lists files in the current directory, optionally filtering by extension."""
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    if extension:
        files = [f for f in files if f.endswith(extension)]
    if exclude_extensions:
        files = [f for f in files if not f.endswith(tuple(exclude_extensions))]
    return files


def main_menu():
    """Main menu for SAF."""
    while True:
        print("\n--- SAF — Simple As Fuck Encryption ---")
        print("1. Generate Key Pair")
        print("2. Encrypt File (with signature)")
        print("3. Encrypt File (without signature)")
        print("4. Decrypt File")
        print("5. Get SHA-256 Hash of a File")
        print("6. Exit")

        choice = input("Select an action (1-6): ")

        if choice == '1':
            try:
                key_length_str = input("Enter desired key length in bits (default 256, minimum 6): ")
                key_length = int(key_length_str) if key_length_str else 256

                if key_length <= 0:
                    print("Key length must be a positive integer.")
                    continue

                base_filename = input("Enter base filename for keys (e.g., my_key): ")
                public_k, private_k = generate_key_pair(bits=key_length)
                if public_k and private_k:
                    save_key(public_k, base_filename, is_private=False)
                    save_key(private_k, base_filename, is_private=True)
            except ValueError:
                print("Invalid input. Please enter an integer for key length.")
            except Exception as e:
                print(f"Error generating keys: {e}")

        elif choice == '2' or choice == '3':
            is_signed_mode = (choice == '2')

            mode_text = "with signature" if is_signed_mode else "without signature"
            print(f"\n--- Encrypt File ({mode_text}) ---")

            files_to_process = list_files_for_choice(exclude_extensions=['.pub', '.priv', '.enc', '.decrypted'])
            if not files_to_process:
                print("No files to encrypt in the current directory.")
                continue

            print("Available files for encryption:")
            for i, f in enumerate(files_to_process):
                print(f"{i + 1}. {f}")

            try:
                file_idx = int(input("Select file to encrypt (number): ")) - 1
                if not (0 <= file_idx < len(files_to_process)):
                    print("Invalid file selection.")
                    continue
                input_filename = files_to_process[file_idx]

                file_hash_bytes = calculate_sha256(input_filename)
                if file_hash_bytes is None:
                    continue
                print(f"SHA-256 hash of original file '{input_filename}': {file_hash_bytes.hex()}")

            except ValueError:
                print("Invalid input. Please enter a number.")
                continue

            public_key_files = list_files_for_choice(".pub")
            if not public_key_files:
                print("No SAF public key files (*.pub) found in the current directory for encryption.")
                continue

            print("\nAvailable RECIPIENT PUBLIC keys:")
            for i, f in enumerate(public_key_files):
                print(f"{i + 1}. {f}")

            try:
                key_idx = int(input("Select RECIPIENT PUBLIC key for encryption (number): ")) - 1
                if not (0 <= key_idx < len(public_key_files)):
                    print("Invalid key selection.")
                    continue
                public_key_filename = public_key_files[key_idx]
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue
            public_key_recipient = load_key(public_key_filename)
            if not public_key_recipient: continue

            private_signing_key = None
            if is_signed_mode:
                private_key_files = list_files_for_choice(".priv")
                if not private_key_files:
                    print("No SAF private key files (*.priv) found in the current directory for signing.")
                    print("Encryption will proceed without a signature (please select option 3).")
                    continue

                print("\nAvailable SENDER PRIVATE keys (for data signing):")
                for i, f in enumerate(private_key_files):
                    print(f"{i + 1}. {f}")

                try:
                    key_idx = int(input("Select SENDER PRIVATE key for signing (number): ")) - 1
                    if not (0 <= key_idx < len(private_key_files)):
                        print("Invalid key selection. Operation cancelled.")
                        continue
                    private_signing_key_filename = private_key_files[key_idx]
                    private_signing_key = load_key(private_signing_key_filename)
                    if not private_signing_key:
                        print("Error loading private key. Operation cancelled.")
                        continue
                except ValueError:
                    print("Invalid input. Operation cancelled.")
                    continue

            try:
                with open(input_filename, 'rb') as f_in:
                    data_bytes = f_in.read()

                encrypted_payload_bytes = encrypt_data(data_bytes, public_key_recipient, private_signing_key)
                encoded_encrypted_data = base64.b64encode(encrypted_payload_bytes).decode('utf-8')

                output_filename = input_filename + ".enc"
                with open(output_filename, 'w') as f_out:
                    f_out.write(MESSAGE_HEADER + "\n")
                    f_out.write(encoded_encrypted_data + "\n")
                    f_out.write(MESSAGE_FOOTER + "\n")

                if is_signed_mode:
                    print(f"File '{input_filename}' successfully encrypted and signed to '{output_filename}'.")
                else:
                    print(f"File '{input_filename}' successfully encrypted (unsigned) to '{output_filename}'.")

            except Exception as e:
                print(f"Error during encryption: {e}")

        elif choice == '4':
            print("\n--- Decrypt File ---")

            encrypted_files = list_files_for_choice(".enc")
            if not encrypted_files:
                print("No SAF encrypted files (*.enc) found in the current directory.")
                continue

            print("Available files for decryption:")
            for i, f in enumerate(encrypted_files):
                print(f"{i + 1}. {f}")

            try:
                file_idx = int(input("Select file to decrypt (number): ")) - 1
                if not (0 <= file_idx < len(encrypted_files)):
                    print("Invalid file selection.")
                    continue
                input_filename = encrypted_files[file_idx]

                file_hash_bytes = calculate_sha256(input_filename)
                if file_hash_bytes is None:
                    continue
                print(f"SHA-256 hash of encrypted file '{input_filename}': {file_hash_bytes.hex()}")

            except ValueError:
                print("Invalid input. Please enter a number.")
                continue

            private_key_files = list_files_for_choice(".priv")
            if not private_key_files:
                print("No SAF private key files (*.priv) found in the current directory for decryption.")
                continue

            print("\nAvailable RECIPIENT PRIVATE keys:")
            for i, f in enumerate(private_key_files):
                print(f"{i + 1}. {f}")

            try:
                key_idx = int(input("Select RECIPIENT PRIVATE key for decryption (number): ")) - 1
                if not (0 <= key_idx < len(private_key_files)):
                    print("Invalid key selection.")
                    continue
                private_key_filename = private_key_files[key_idx]
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue
            private_key_recipient = load_key(private_key_filename)
            if not private_key_recipient: continue

            try:
                with open(input_filename, 'r') as f_in:
                    lines = f_in.readlines()

                if not (MESSAGE_HEADER.strip() in lines[0].strip() and MESSAGE_FOOTER.strip() in lines[-1].strip()):
                    raise ValueError("File is not an SAF encrypted message or has incorrect headers.")

                content_lines = []
                in_content = False
                for line in lines:
                    if line.strip() == MESSAGE_HEADER.strip():
                        in_content = True
                        continue
                    if line.strip() == MESSAGE_FOOTER.strip():
                        in_content = False
                        break
                    if in_content:
                        content_lines.append(line.strip())

                if not content_lines:
                    raise ValueError("No encrypted data found between message headers.")

                encoded_encrypted_data = "".join(content_lines)
                encrypted_payload_bytes_for_check = base64.b64decode(encoded_encrypted_data)

                if len(encrypted_payload_bytes_for_check) >= 6:
                    is_signed_flag_from_file = struct.unpack('>I B B', encrypted_payload_bytes_for_check[:6])[2]
                else:
                    is_signed_flag_from_file = 0

            except Exception as e:
                print(f"Error reading file header to determine mode: {e}")
                print("Proceeding with decryption without signature verification.")
                is_signed_flag_from_file = 0

            public_signing_key = None
            if is_signed_flag_from_file == 1:
                print("\nFile contains a digital signature. Sender's PUBLIC key is required for verification.")
                public_key_files = list_files_for_choice(".pub")
                if not public_key_files:
                    print("No SAF public key files (*.pub) found in the current directory for signature verification.")
                    print("Signature verification will be skipped.")
                else:
                    print("Available SENDER PUBLIC keys (for data signature verification):")
                    for i, f in enumerate(public_key_files):
                        print(f"{i + 1}. {f}")

                    try:
                        key_idx = int(input("Select SENDER PUBLIC key for signature verification (number): ")) - 1
                        if not (0 <= key_idx < len(public_key_files)):
                            print("Invalid key selection. Signature verification will be skipped.")
                        else:
                            public_signing_key_filename = public_key_files[key_idx]
                            public_signing_key = load_key(public_signing_key_filename)
                            if not public_signing_key:
                                print("Error loading public key. Signature verification will be skipped.")
                    except ValueError:
                        print("Invalid input. Signature verification will be skipped.")
            else:
                print("\nFile is encrypted without a digital signature. Only data integrity check will be performed.")

            try:
                decrypted_data = decrypt_data(encrypted_payload_bytes_for_check, private_key_recipient,
                                              public_signing_key)
                output_filename = input_filename.replace(".enc", "") + ".decrypted"
                with open(output_filename, 'wb') as f_out:
                    f_out.write(decrypted_data)
                print(f"File '{input_filename}' successfully decrypted to '{output_filename}'.")
            except Exception as e:
                print(f"Error during decryption: {e}")

        elif choice == '5':
            print("\n--- Get SHA-256 Hash of a File ---")
            all_files = list_files_for_choice()
            if not all_files:
                print("No files in the current directory.")
                continue

            print("Available files:")
            for i, f in enumerate(all_files):
                print(f"{i + 1}. {f}")

            try:
                file_idx = int(input("Select file to get hash (number): ")) - 1
                if not (0 <= file_idx < len(all_files)):
                    print("Invalid file selection.")
                    continue
                selected_filename = all_files[file_idx]

                file_hash = calculate_sha256(selected_filename)
                if file_hash:
                    print(f"SHA-256 hash of file '{selected_filename}': {file_hash.hex()}")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except Exception as e:
                print(f"Error getting hash: {e}")

        elif choice == '6':
            print("Exiting SAF...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 6.")


if __name__ == "__main__":
    main_menu()