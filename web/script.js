function bytesToBigInt(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return BigInt('0x' + hex);
}

function bigIntToBytes(n, length) {
    n = BigInt(n);
    if (n === 0n) {
        return new Uint8Array(length).fill(0);
    }

    let hex = n.toString(16);
    hex = hex.padStart(length * 2, '0');

    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function gcd(a, b) {
    while (b !== 0n) {
        [a, b] = [b, a % b];
    }
    return a;
}

function extendedGcd(a, b) {
    if (a === 0n) {
        return [b, 0n, 1n];
    }
    let [gcdVal, x1, y1] = extendedGcd(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;
    return [gcdVal, x, y];
}

function modInverse(a, m) {
    let [gcdVal, x, y] = extendedGcd(a, m);
    if (gcdVal !== 1n) {
        throw new Error("Modular inverse does not exist");
    }
    return (x % m + m) % m;
}

function power(base, exp, mod) {
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2n;
    }
    return result;
}

function getRandomBigInt(min, max) {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        const range = max - min;
        if (range < 0n) {
            throw new Error("Min value cannot be greater than max value.");
        }
        if (range === 0n) return min;

        const numBits = max.toString(2).length;
        const numBytes = Math.ceil(numBits / 8);
        const randomBytes = new Uint8Array(numBytes);

        let randomVal;
        let attempts = 0;
        const maxAttempts = 1000;

        do {
            crypto.getRandomValues(randomBytes);
            randomVal = bytesToBigInt(randomBytes);
            attempts++;
            if (attempts > maxAttempts) {
                console.warn("Max attempts reached for getRandomBigInt. Range might be too small or values are extremely rare.");
                return min + BigInt(Math.floor(Math.random() * Number(range + 1n)));
            }
        } while (randomVal > range);

        return min + randomVal;
    } else {
        console.warn("Using Math.random for getRandomBigInt.");
        return min + BigInt(Math.floor(Math.random() * Number(max - min + 1n)));
    }
}

async function isPrimeMillerRabin(n, k = 5) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;

    let s = 0n;
    let d = n - 1n;
    while (d % 2n === 0n) {
        d /= 2n;
        s++;
    }

    for (let i = 0; i < k; i++) {
        let a = getRandomBigInt(2n, n - 2n);
        let x = power(a, d, n);

        if (x === 1n || x === n - 1n) {
            continue;
        }

        let isComposite = true;
        for (let j = 0n; j < s - 1n; j++) {
            x = power(x, 2n, n);
            if (x === n - 1n) {
                isComposite = false;
                break;
            }
        }
        if (isComposite) {
            return false;
        }
    }
    return true;
}

// --- Prime Generation ---

async function generatePrime(bits, statusElement, stage, startTime) {
    let num;
    const maxAttempts = 5000;
    const minVal = 2n ** BigInt(bits - 1);
    const maxVal = (2n ** BigInt(bits)) - 1n;

    for (let i = 0; i < maxAttempts; i++) {
        num = getRandomBigInt(minVal, maxVal);
        num |= 1n;

        if (num < minVal) {
            num += minVal;
        }

        if (await isPrimeMillerRabin(num)) {
            return num;
        }
        if (i % 100 === 0) {
            const progress = Math.min(99, Math.floor((i / maxAttempts) * 100));
            const currentTime = (performance.now() - startTime).toFixed(2);
            statusElement.textContent = `Generating ${stage} (${progress}%) \t ${currentTime} ms`;
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
    throw new Error(`Failed to find a prime number after ${maxAttempts} attempts for ${bits} bits. Try again or reduce key length.`);
}

// --- Main SAF functions ---

async function generateKeypair(bits, statusElement) {
    const startTime = performance.now();
    statusElement.classList.remove('success', 'error', 'warning');
    statusElement.textContent = `Starting key generation. This may take several seconds for larger keys... \t 0.00 ms`;

    const primeBits = Math.floor(bits / 2);
    if (primeBits < 16) {
        throw new Error("Key length is too small for prime generation. Minimum 32 bits for key (16 bits per prime factor).");
    }

    let p;
    let q;
    try {
        p = await generatePrime(primeBits, statusElement, 'p', startTime);
        statusElement.textContent = `Generating q... \t ${(performance.now() - startTime).toFixed(2)} ms`;
        q = await generatePrime(primeBits, statusElement, 'q', startTime);

        while (p === q) {
            statusElement.textContent = `p equals q, generating new q... \t ${(performance.now() - startTime).toFixed(2)} ms`;
            q = await generatePrime(primeBits, statusElement, 'q', startTime);
        }

        const n = p * q;
        const phi = (p - 1n) * (q - 1n);

        const e = 65537n;
        if (gcd(e, phi) !== 1n) {
            throw new Error("Failed to find e, coprime to phi. Try again.");
        }

        statusElement.textContent = `Calculating d... \t ${(performance.now() - startTime).toFixed(2)} ms`;
        const d = modInverse(e, phi);

        const endTime = performance.now();
        const timeTaken = (endTime - startTime).toFixed(2);
        statusElement.textContent = `Keys generated! (${timeTaken} ms)`;
        statusElement.classList.add('success');
        return {
            publicKey: { e: e, n: n },
            privateKey: { d: d, n: n }
        };
    } catch (error) {
        const endTime = performance.now();
        const timeTaken = (endTime - startTime).toFixed(2);
        statusElement.textContent = `Error generating keys: ${error.message} (${timeTaken} ms)`;
        statusElement.classList.add('error');
        throw error;
    }
}

async function encryptData(dataBytes, public_key_recipient, private_signing_key = null, statusElement, startTime) {
    statusElement.classList.remove('success', 'error');

    const e_recipient = BigInt(public_key_recipient.e);
    const n_recipient = BigInt(public_key_recipient.n);

    statusElement.textContent = `Computing data hash (0%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const data_hash_buffer = await crypto.subtle.digest('SHA-256', dataBytes);
    const data_hash_bytes = new Uint8Array(data_hash_buffer);
    const data_hash_int = bytesToBigInt(data_hash_bytes);
    statusElement.textContent = `Data hash computed (10%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    let is_signed_message_flag = 0;
    let hash_payload_bytes;

    if (private_signing_key) {
        is_signed_message_flag = 1;
        const d_sig = BigInt(private_signing_key.d);
        const n_sig = BigInt(private_signing_key.n);

        if (data_hash_int >= n_sig) {
            throw new Error(
                `Hash (${data_hash_bytes.length * 8} bits) is too large to be signed by this private key (modulus n_sig = ${n_sig.toString(2).length} bits). ` +
                `It is recommended to use a private key with a modulus N length of at least 256 bits for SHA-256.`
            );
        }
        statusElement.textContent = `Signing hash (20%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
        const signed_hash_int = power(data_hash_int, d_sig, n_sig);
        hash_payload_bytes = bigIntToBytes(signed_hash_int, Math.ceil(n_sig.toString(2).length / 8));
        statusElement.textContent = `Hash signed (30%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    } else {
        let data_hash_to_encrypt = data_hash_bytes;
        const recipient_key_byte_length = Math.ceil(n_recipient.toString(2).length / 8);

        if (data_hash_int >= n_recipient) {
            console.warn(
                `Warning: Recipient's public key modulus (${n_recipient.toString(2).length} bits) is smaller than SHA-256 hash size (256 bits). ` +
                "Hash will be truncated for integrity check. This reduces reliability of the check. It is recommended to use a recipient key of at least 256 bits."
            );
            data_hash_to_encrypt = data_hash_bytes.slice(0, recipient_key_byte_length);
            if (data_hash_to_encrypt.length === 0) {
                throw new Error("Public key modulus is too small to encrypt even part of the hash.");
            }
        }
        statusElement.textContent = `Encrypting hash for integrity (20%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
        const encrypted_hash_int = power(bytesToBigInt(data_hash_to_encrypt), e_recipient, n_recipient);
        hash_payload_bytes = bigIntToBytes(encrypted_hash_int, recipient_key_byte_length);
        statusElement.textContent = `Hash encrypted (30%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    }

    const keyByteLength_recipient = Math.ceil(n_recipient.toString(2).length / 8);
    const maxBlockSize = keyByteLength_recipient - 1;

    if (maxBlockSize <= 0) {
        throw new Error("Recipient's key modulus is too small to encrypt data. Increase key length (minimum 2 bytes, i.e., 16 bits).");
    }

    const remainingBytes = dataBytes.length % maxBlockSize;
    let padding_len;
    if (remainingBytes === 0) {
        padding_len = maxBlockSize;
    } else {
        padding_len = maxBlockSize - remainingBytes;
    }

    const data_bytes_padded = new Uint8Array(dataBytes.length + padding_len);
    data_bytes_padded.set(dataBytes);
    for (let i = dataBytes.length; i < data_bytes_padded.length; i++) {
        data_bytes_padded[i] = padding_len;
    }

    const encrypted_blocks = [];
    const totalBlocks = Math.ceil(data_bytes_padded.length / maxBlockSize);
    for (let i = 0; i < data_bytes_padded.length; i += maxBlockSize) {
        const block = data_bytes_padded.slice(i, i + maxBlockSize);
        const m = bytesToBigInt(block);
        const c = power(m, e_recipient, n_recipient);
        encrypted_blocks.push(c);
        const progress = Math.min(100, 30 + Math.floor(((i / maxBlockSize) / totalBlocks) * 70));
        statusElement.textContent = `Encrypting data blocks (${progress}%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
        await new Promise(resolve => setTimeout(resolve, 0));
    }

    const ciphertext_block_size = keyByteLength_recipient;
    const encrypted_payload_bytes_list = [];
    for (const block_val of encrypted_blocks) {
        encrypted_payload_bytes_list.push(bigIntToBytes(block_val, ciphertext_block_size));
    }
    const encrypted_payload_bytes = new Uint8Array(encrypted_payload_bytes_list.flatMap(arr => Array.from(arr)));

    const header_main = new Uint8Array(6);
    new DataView(header_main.buffer).setUint32(0, dataBytes.length, false);
    new DataView(header_main.buffer).setUint8(4, padding_len);
    new DataView(header_main.buffer).setUint8(5, is_signed_message_flag);

    const header_hash_len = new Uint8Array(4);
    new DataView(header_hash_len.buffer).setUint32(0, hash_payload_bytes.length, false);

    const full_encrypted_bytes = new Uint8Array([
        ...header_main,
        ...header_hash_len,
        ...hash_payload_bytes,
        ...encrypted_payload_bytes
    ]);

    const endTime = performance.now();
    const timeTaken = (endTime - startTime).toFixed(2);
    statusElement.textContent = `Message successfully encrypted! (${timeTaken} ms)`;
    statusElement.classList.add('success');
    return btoa(String.fromCharCode(...full_encrypted_bytes));
}

async function decryptData(encryptedBase64, private_key_recipient, public_signing_key = null, statusElement, startTime) {
    statusElement.classList.remove('success', 'error', 'warning');

    statusElement.textContent = `Parsing encrypted data (0%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const d_recipient = BigInt(private_key_recipient.d);
    const n_recipient = BigInt(private_key_recipient.n);

    const encrypted_bytes_payload = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

    if (encrypted_bytes_payload.length < 10) {
        throw new Error("Invalid encrypted data format: header too short.");
    }

    const header_main_view = new DataView(encrypted_bytes_payload.buffer, 0, 6);
    const original_data_len = header_main_view.getUint32(0, false);
    const padding_len = header_main_view.getUint8(4);
    const is_signed_flag = header_main_view.getUint8(5);

    const header_hash_len_view = new DataView(encrypted_bytes_payload.buffer, 6, 4);
    const hash_payload_len = header_hash_len_view.getUint32(0, false);

    if (encrypted_bytes_payload.length < 10 + hash_payload_len) {
        throw new Error("Invalid encrypted data format: hash payload truncated.");
    }

    const hash_payload_bytes = encrypted_bytes_payload.slice(10, 10 + hash_payload_len);
    const encrypted_payload_only = encrypted_bytes_payload.slice(10 + hash_payload_len);
    statusElement.textContent = `Headers parsed (10%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    const ciphertext_block_size = Math.ceil(n_recipient.toString(2).length / 8);
    const original_data_block_size_before_encryption = ciphertext_block_size - 1;

    if (encrypted_payload_only.length % ciphertext_block_size !== 0) {
        throw new Error("Length of encrypted data (message) is not a multiple of block size. Data might be corrupted or wrong key used.");
    }

    const decrypted_blocks = [];
    const totalBlocks = encrypted_payload_only.length / ciphertext_block_size;
    for (let i = 0; i < encrypted_payload_only.length; i += ciphertext_block_size) {
        const block_bytes = encrypted_payload_only.slice(i, i + ciphertext_block_size);
        const c = bytesToBigInt(block_bytes);
        const m = power(c, d_recipient, n_recipient);
        decrypted_blocks.push(m);
        const progress = Math.min(100, 10 + Math.floor(((i / ciphertext_block_size) / totalBlocks) * 60));
        statusElement.textContent = `Decrypting data blocks (${progress}%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
        await new Promise(resolve => setTimeout(resolve, 0));
    }
    statusElement.textContent = `Data blocks decrypted (70%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    let decrypted_full_data_array = [];
    for (const block_val of decrypted_blocks) {
        decrypted_full_data_array.push(bigIntToBytes(block_val, original_data_block_size_before_encryption));
    }
    const decrypted_full_data = new Uint8Array(decrypted_full_data_array.flatMap(arr => Array.from(arr)));
    statusElement.textContent = `Reassembling data (75%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    let final_decoded_data;

    if (decrypted_full_data.length < original_data_len + padding_len) {
        console.warn("Warning: Decrypted payload is shorter than expected (original data + padding). Data might be corrupted or wrong key used. Attempting partial recovery.");
        final_decoded_data = decrypted_full_data;
    } else {
        let detected_padding_val = decrypted_full_data[decrypted_full_data.length - 1];

        let padding_is_valid = true;
        if (detected_padding_val <= 0 || detected_padding_val > original_data_block_size_before_encryption) {
            padding_is_valid = false;
        } else {
            for (let i = 1; i <= detected_padding_val; i++) {
                if (decrypted_full_data[decrypted_full_data.length - i] !== detected_padding_val) {
                    padding_is_valid = false;
                    break;
                }
            }
        }

        if (!padding_is_valid) {
            console.warn("Warning: Invalid padding detected. Data might be corrupted or wrong key used. Reverting to header's padding length.");
            detected_padding_val = padding_len;
            if (detected_padding_val > decrypted_full_data.length) {
                detected_padding_val = 0;
                console.warn("Header padding length also invalid or too large. No padding removed.");
            }
        }

        final_decoded_data = decrypted_full_data.slice(0, decrypted_full_data.length - detected_padding_val);
    }
    statusElement.textContent = `Padding removed (80%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    if (final_decoded_data.length !== original_data_len) {
        console.warn(
            `Warning: Final decrypted data length (${final_decoded_data.length}) after padding removal does not match original length (${original_data_len}). ` +
            "Data may have been altered or corrupted. Truncating to original length for integrity check."
        );
        final_decoded_data = final_decoded_data.slice(0, original_data_len);
    }

    statusElement.textContent = `Verifying integrity (85%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    await verifyIntegrity(final_decoded_data, is_signed_flag, hash_payload_bytes, private_key_recipient, public_signing_key, statusElement, startTime);

    const endTime = performance.now();
    const timeTaken = (endTime - startTime).toFixed(2);
    if (statusElement.classList.contains('success') || statusElement.classList.contains('error') || statusElement.classList.contains('warning')) {
    } else {
        statusElement.textContent = `Decryption complete. No integrity check performed. (${timeTaken} ms)`;
        statusElement.classList.add('warning');
    }


    return new TextDecoder().decode(final_decoded_data);
}

async function verifyIntegrity(decrypted_data_bytes, is_signed_flag, hash_payload_bytes, private_key_recipient, public_signing_key, statusElement, startTime) {
    statusElement.classList.remove('success', 'error', 'warning');

    const initialTimeCheck = (performance.now() - startTime).toFixed(2);

    if (is_signed_flag === 1) {
        if (!public_signing_key) {
            statusElement.textContent = `Data integrity check (signature): SKIPPED! Message is signed, but sender's public key was not provided. (${initialTimeCheck} ms)`;
            statusElement.classList.add('warning');
            console.warn("Data integrity check (signature): SKIPPED! Message is signed, but sender's public key was not provided.");
            return false;
        }

        const e_sig = BigInt(public_signing_key.e);
        const n_sig = BigInt(public_signing_key.n);

        const signed_hash_int = bytesToBigInt(hash_payload_bytes);

        if (signed_hash_int >= n_sig) {
            statusElement.textContent = `Signature verification FAILED: Decrypted signed hash is too large for sender's public key modulus. Possibly wrong key or corruption. (${initialTimeCheck} ms)`;
            statusElement.classList.add('error');
            console.error(
                "Signature verification error: Decrypted signed hash is too large for sender's public key modulus. Possibly wrong key or corruption."
            );
            return false;
        }
        statusElement.textContent = `Verifying signature (90%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
        const retrieved_hash_int = power(signed_hash_int, e_sig, n_sig);
        const retrieved_hash_bytes = bigIntToBytes(retrieved_hash_int, 32);

        const computed_hash_buffer = await crypto.subtle.digest('SHA-256', decrypted_data_bytes);
        const computed_hash_bytes = new Uint8Array(computed_hash_buffer);

        const endTime = performance.now();
        const timeTaken = (endTime - startTime).toFixed(2);

        if (retrieved_hash_bytes.every((val, i) => val === computed_hash_bytes[i])) {
            statusElement.textContent = `Data integrity (signature) check: SUCCESS! Data has not been altered and is signed by the sender. (${timeTaken} ms)`;
            statusElement.classList.add('success');
            return true;
        } else {
            statusElement.textContent = `Data integrity (signature) check: FAILED! Data may have been altered or the wrong sender's key was used. (${timeTaken} ms)`;
            statusElement.classList.add('error');
            console.warn(
                "Data integrity (signature) check: FAILED! Data may have been altered or the wrong sender's key was used."
            );
            console.warn(`Expected hash from signature: ${Array.from(retrieved_hash_bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            console.warn(`Computed hash of decrypted data: ${Array.from(computed_hash_bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            return false;
        }
    } else {
        statusElement.textContent = `Verifying integrity (90%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
        const retrieved_hash_int = power(bytesToBigInt(hash_payload_bytes), private_key_recipient.d, private_key_recipient.n);

        const recipient_key_byte_length = Math.ceil(private_key_recipient.n.toString(2).length / 8);
        const hash_part_len = Math.min(32, recipient_key_byte_length);

        const retrieved_hash_actual_bytes = bigIntToBytes(retrieved_hash_int, hash_part_len);

        const computed_hash_buffer = await crypto.subtle.digest('SHA-256', decrypted_data_bytes);
        const computed_hash_full_bytes = new Uint8Array(computed_hash_buffer);
        const computed_hash_actual_bytes = computed_hash_full_bytes.slice(0, hash_part_len);

        const endTime = performance.now();
        const timeTaken = (endTime - startTime).toFixed(2);

        if (retrieved_hash_actual_bytes.every((val, i) => val === computed_hash_actual_bytes[i])) {
            statusElement.textContent = `Data integrity (unsigned) check: SUCCESS! Data has not been corrupted. (${timeTaken} ms)`;
            statusElement.classList.add('success');
            return true;
        } else {
            statusElement.textContent = `Data integrity (unsigned) check: FAILED! Data may have been corrupted. (${timeTaken} ms)`;
            statusElement.classList.add('error');
            console.warn("Data integrity (unsigned) check: FAILED! Data may have been corrupted.");
            console.warn(`Expected hash from header: ${Array.from(retrieved_hash_actual_bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            console.warn(`Computed hash of decrypted data (partial): ${Array.from(computed_hash_actual_bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            return false;
        }
    }
}


// --- Hashing functions (Web Crypto API) ---

async function computeHash(message, algorithm, statusElement, startTime) {
    statusElement.classList.remove('success', 'error');
    statusElement.textContent = `Computing hash (0%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    const textEncoder = new TextEncoder();
    const data = textEncoder.encode(message);
    
    statusElement.textContent = `Hashing data (50%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    
    statusElement.textContent = `Converting hash to hex (90%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const endTime = performance.now();
    const timeTaken = (endTime - startTime).toFixed(2);
    statusElement.textContent = `Hash (${algorithm}) successfully computed! (${timeTaken} ms)`;
    statusElement.classList.add('success');
    return hexHash;
}

// --- Digital Signature and Verification functions ---

async function signMessageRaw(message, privateKey, statusElement, startTime) {
    statusElement.classList.remove('success', 'error');
    statusElement.textContent = `Starting signing process (0%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    const d = BigInt(privateKey.d);
    const n = BigInt(privateKey.n);

    statusElement.textContent = `Computing message hash (20%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const hashHex = await computeHash(message, 'SHA-256', statusElement, startTime); 
    const hashBigInt = BigInt('0x' + hashHex);

    if (hashBigInt >= n) {
        throw new Error(
            `Message hash (${hashHex.length * 4} bits) is too large for the signing key's modulus N (${n.toString(2).length} bits). ` +
            `Use a longer signing key (minimum 256 bits for SHA-256).`
        );
    }
    statusElement.textContent = `Applying private key to hash (70%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const signatureBigInt = power(hashBigInt, d, n);

    const keyByteLength = Math.ceil(n.toString(2).length / 8);
    statusElement.textContent = `Converting signature to bytes (90%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const signatureBytes = bigIntToBytes(signatureBigInt, keyByteLength);

    const endTime = performance.now();
    const timeTaken = (endTime - startTime).toFixed(2);
    statusElement.textContent = `Message successfully signed! (${timeTaken} ms)`;
    statusElement.classList.add('success');
    return btoa(String.fromCharCode(...signatureBytes));
}

async function verifySignatureRaw(message, signatureBase64, publicKey, statusElement, startTime) {
    statusElement.classList.remove('success', 'error');
    statusElement.textContent = `Starting verification process (0%) \t ${(performance.now() - startTime).toFixed(2)} ms`;

    const e = BigInt(publicKey.e);
    const n = BigInt(publicKey.n);

    statusElement.textContent = `Computing expected hash (20%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const expectedHashHex = await computeHash(message, 'SHA-256', statusElement, startTime); 
    const expectedHashBigInt = BigInt('0x' + expectedHashHex);

    statusElement.textContent = `Parsing signature (50%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
    const signatureBigInt = bytesToBigInt(signatureBytes);

    if (signatureBigInt >= n) {
        console.warn("Signature value is greater than public key's modulus N. Likely an invalid signature or wrong public key.");
        statusElement.textContent = `Signature is invalid: signature value too large. (${(performance.now() - startTime).toFixed(2)} ms)`;
        statusElement.classList.add('error');
        return false;
    }
    statusElement.textContent = `Decrypting signature with public key (70%) \t ${(performance.now() - startTime).toFixed(2)} ms`;
    const decryptedHashBigInt = power(signatureBigInt, e, n);

    const isValid = expectedHashBigInt === decryptedHashBigInt;
    
    const endTime = performance.now();
    const timeTaken = (endTime - startTime).toFixed(2);

    if (isValid) {
        statusElement.textContent = `Signature is valid: message is unaltered and from the sender! (${timeTaken} ms)`;
        statusElement.classList.add('success');
    } else {
        statusElement.textContent = `Signature is invalid: message has been altered or signature is not from this key. (${timeTaken} ms)`;
        statusElement.classList.add('error');
    }
    return isValid;
}


// --- Key, Encrypted, and Signed Message Formatting/Parsing Functions ---

function formatKey(keyObject, type) {
    const header = `-----BEGIN SAF ${type} KEY-----`;
    const footer = `-----END SAF ${type} KEY-----`;
    const jsonKey = JSON.stringify({
        e: keyObject.e ? keyObject.e.toString() : undefined,
        d: keyObject.d ? keyObject.d.toString() : undefined,
        n: keyObject.n.toString()
    });
    const base64Content = btoa(jsonKey);
    const wrappedContent = base64Content.match(/.{1,64}/g).join('\n');
    return `${header}\n${wrappedContent}\n${footer}`;
}

function parseKey(formattedKey) {
    const lines = formattedKey.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    if (lines.length < 3 || (!lines[0].startsWith('-----BEGIN SAF') || !lines[lines.length - 1].startsWith('-----END SAF'))) {
        throw new Error("Invalid SAF key format. Expected BEGIN/END headers.");
    }
    const base64Content = lines.slice(1, lines.length - 1).join('');
    try {
        const jsonString = atob(base64Content);
        const keyData = JSON.parse(jsonString);
        const parsedKey = {};
        if (keyData.e) parsedKey.e = BigInt(keyData.e);
        if (keyData.d) parsedKey.d = BigInt(keyData.d);
        if (keyData.n) parsedKey.n = BigInt(keyData.n);

        if (!parsedKey.n) {
            throw new Error("Key does not contain modulus N.");
        }
        if (!parsedKey.e && !parsedKey.d) {
            throw new Error("Key does not contain either public exponent (e) or private exponent (d).");
        }
        return parsedKey;
    } catch (e) {
        console.error("Error parsing key:", e);
        throw new Error(`Error parsing Base64 or JSON content of key: ${e.message}`);
    }
}

function formatEncryptedMessage(base64Message) {
    const header = `-----BEGIN SAF ENCRYPTED MESSAGE-----`;
    const footer = `-----END SAF ENCRYPTED MESSAGE-----`;
    const wrappedContent = base64Message.match(/.{1,64}/g).join('\n');
    return `${header}\n${wrappedContent}\n${footer}`;
}

function parseEncryptedMessage(formattedMessage) {
    const lines = formattedMessage.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    if (lines.length < 3 || !lines[0].startsWith('-----BEGIN SAF ENCRYPTED MESSAGE-----') || !lines[lines.length - 1].startsWith('-----END SAF ENCRYPTED MESSAGE-----')) {
        throw new Error("Invalid SAF encrypted message format. Expected BEGIN/END headers.");
    }
    return lines.slice(1, lines.length - 1).join('');
}

function formatSignedMessage(originalMessage, signatureBase64, hashAlgorithm, hashHex) {
    const header = `-----BEGIN SAF SIGNED MESSAGE-----`;
    const hashInfo = `Hash: ${hashAlgorithm}\nHash (HEX): ${hashHex}`;
    const signatureHeader = `-----BEGIN SAF SIGNATURE-----`;
    const signatureFooter = `-----END SAF SIGNATURE-----`;

    const wrappedSignature = signatureBase64.match(/.{1,64}/g).join('\n');

    return `${header}\n${hashInfo}\n\n${originalMessage}\n${signatureHeader}\n${wrappedSignature}\n${signatureFooter}`;
}

function parseSignedMessage(formattedSignedMessage) {
    const lines = formattedSignedMessage.split('\n').map(line => line.trim()).filter(line => line.length > 0);

    const BEGIN_SIGNED_MESSAGE = `-----BEGIN SAF SIGNED MESSAGE-----`;
    const BEGIN_SIGNATURE = `-----BEGIN SAF SIGNATURE-----`;
    const END_SIGNATURE = `-----END SAF SIGNATURE-----`;

    if (!lines[0].startsWith(BEGIN_SIGNED_MESSAGE) || !lines.some(line => line.startsWith(BEGIN_SIGNATURE)) || !lines.some(line => line.startsWith(END_SIGNATURE))) {
        throw new Error("Invalid SAF signed message format. Expected BEGIN SAF SIGNED MESSAGE, BEGIN SAF SIGNATURE, and END SAF SIGNATURE headers.");
    }

    let originalMessage = [];
    let signatureBase64 = '';
    let hashAlgorithm = '';
    let hashHex = '';

    let inSignature = false;
    let messageStartReached = false;

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];

        if (line.startsWith('Hash:')) {
            hashAlgorithm = line.substring('Hash:'.length).trim();
            continue;
        }
        if (line.startsWith('Hash (HEX):')) {
            hashHex = line.substring('Hash (HEX):'.length).trim();
            continue;
        }

        if (line.startsWith(BEGIN_SIGNATURE)) {
            inSignature = true;
            messageStartReached = false;
            continue;
        }
        if (line.startsWith(END_SIGNATURE)) {
            inSignature = false;
            break;
        }

        if (inSignature) {
            signatureBase64 += line;
        } else if (line.length > 0) {
            if (!messageStartReached && (line.includes('Hash:') || line.includes('Hash (HEX:'))){
            } else {
                messageStartReached = true;
                originalMessage.push(line);
            }
        }
    }
    
    let finalOriginalMessage = originalMessage.join('\n');
    if (finalOriginalMessage.startsWith('\n')) {
        finalOriginalMessage = finalOriginalMessage.substring(1);
    }
    finalOriginalMessage = finalOriginalMessage.trim();

    if (!finalOriginalMessage || !signatureBase64 || !hashAlgorithm || !hashHex) {
        throw new Error("Failed to extract all required components (message, signature, hash info) from the signed message. Ensure the format is correct.");
    }

    return { originalMessage: finalOriginalMessage, signatureBase64, hashAlgorithm, hashHex };
}


// --- Helper function for file download ---
function downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// --- Event Handlers ---

async function handleGenerateKeys() {
    const keyLength = parseInt(document.getElementById('keyLength').value);
    const statusElement = document.getElementById('keyGenStatus');
    statusElement.textContent = "Starting key generation...";
    statusElement.classList.remove('success', 'error', 'warning');
    document.getElementById('publicKeyOutput').value = '';
    document.getElementById('privateKeyOutput').value = '';

    const startTime = performance.now();

    if (keyLength < 512) {
        statusElement.textContent = `Warning: Key length less than 512 bits is not recommended for security. Proceeding anyway... \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.remove('success');
        statusElement.classList.add('warning');
    } else if (keyLength > 2048) {
        statusElement.textContent = `Warning: Key length greater than 2048 bits may result in very slow generation and operation. Proceeding anyway... \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.remove('success');
        statusElement.classList.add('warning');
    } else {
        statusElement.textContent = `Starting generation. This may take some time... \t ${(performance.now() - startTime).toFixed(2)} ms`;
    }

    try {
        const { publicKey, privateKey } = await generateKeypair(keyLength, statusElement);

        const formattedPublicKey = formatKey(publicKey, 'PUBLIC');
        const formattedPrivateKey = formatKey(privateKey, 'PRIVATE');

        document.getElementById('publicKeyOutput').value = formattedPublicKey;
        document.getElementById('privateKeyOutput').value = formattedPrivateKey;
    } catch (error) {
        console.error("Error generating keys:", error);
    }
}

function handleDownloadPublicKey() {
    const publicKeyContent = document.getElementById('publicKeyOutput').value;
    if (publicKeyContent) {
        downloadFile('public_key.pub', publicKeyContent, 'text/plain');
    } else {
        alert('Please generate or upload a public key first.');
    }
}

function handleDownloadPrivateKey() {
    const privateKeyContent = document.getElementById('privateKeyOutput').value;
    if (privateKeyContent) {
        downloadFile('private_key.priv', privateKeyContent, 'text/plain');
    } else {
        alert('Please generate or upload a private key first.');
    }
}

function handleDownloadEncryptedMessage() {
    const encryptedMessageContent = document.getElementById('encryptedOutput').value;
    if (encryptedMessageContent) {
        downloadFile('encrypted_message.enc', encryptedMessageContent, 'text/plain');
    } else {
        alert('Please encrypt a message first.');
    }
}

function handleDownloadSignedMessage() {
    const signedMessageContent = document.getElementById('signatureOutput').value;
    if (signedMessageContent) {
        downloadFile('signed_message.sig', signedMessageContent, 'text/plain');
    } else {
        alert('Please sign a message first.');
    }
}

async function handleKeyFileUpload(fileInputId, targetTextAreaId) {
    const fileInput = document.getElementById(fileInputId);
    if (fileInput.files.length === 0) {
        alert('Please select a key file.');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    return new Promise((resolve, reject) => {
        reader.onload = function(event) {
            try {
                const fileContent = event.target.result;
                const parsedKey = parseKey(fileContent);
                const keyType = parsedKey.e ? 'PUBLIC' : 'PRIVATE';
                const formattedKey = formatKey(parsedKey, keyType);
                document.getElementById(targetTextAreaId).value = formattedKey;
                alert('Key successfully uploaded!');
                resolve(formattedKey);
            } catch (error) {
                document.getElementById(targetTextAreaId).value = '';
                alert(`Error uploading key: ${error.message}`);
                console.error("Error uploading key:", error);
                reject(error);
            }
        };
        reader.onerror = (error) => {
            alert('Error reading file.');
            console.error('File read error:', error);
            reject(error);
        };
        reader.readAsText(file);
    });
}

async function handleEncryptedFileUpload(fileInputId, targetTextAreaId) {
    const fileInput = document.getElementById(fileInputId);
    if (fileInput.files.length === 0) {
        alert('Please select an encrypted message file.');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    return new Promise((resolve, reject) => {
        reader.onload = function(event) {
            try {
                const fileContent = event.target.result;
                const parsedMessage = parseEncryptedMessage(fileContent);
                const formattedMessage = formatEncryptedMessage(parsedMessage);
                document.getElementById(targetTextAreaId).value = formattedMessage;
                alert('Encrypted message successfully uploaded!');

                const rawEncryptedBase64 = parsedMessage;
                const encrypted_bytes_payload_for_check = Uint8Array.from(atob(rawEncryptedBase64), c => c.charCodeAt(0));
                let is_signed_flag_from_file = 0;
                if (encrypted_bytes_payload_for_check.length >= 6) {
                    const header_main_view = new DataView(encrypted_bytes_payload_for_check.buffer, 0, 6);
                    is_signed_flag_from_file = header_main_view.getUint8(5);
                }

                const verifySignatureDecryptCheckbox = document.getElementById('verifySignatureDecryptCheckbox');
                const publicKeyForVerificationContainer = document.getElementById('publicKeyForVerificationContainer');

                if (is_signed_flag_from_file === 1) {
                    verifySignatureDecryptCheckbox.checked = true;
                    publicKeyForVerificationContainer.style.display = 'block';
                } else {
                    verifySignatureDecryptCheckbox.checked = false;
                    publicKeyForVerificationContainer.style.display = 'none';
                    document.getElementById('publicKeyInputDecryptVerify').value = '';
                }

                resolve(formattedMessage);
            } catch (error) {
                document.getElementById(targetTextAreaId).value = '';
                alert(`Error uploading encrypted message: ${error.message}`);
                console.error("Error uploading encrypted message:", error);
                reject(error);
            }
        };
        reader.onerror = (error) => {
            alert('Error reading file.');
            console.error('File read error:', error);
            reject(error);
        };
        reader.readAsText(file);
    });
}

async function handleSignedMessageFileUpload(fileInputId, targetTextAreaId) {
    const fileInput = document.getElementById(fileInputId);
    if (fileInput.files.length === 0) {
        alert('Please select a signed message file.');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    return new Promise((resolve, reject) => {
        reader.onload = function(event) {
            try {
                const fileContent = event.target.result;
                const parsedContent = parseSignedMessage(fileContent);
                document.getElementById(targetTextAreaId).value = formatSignedMessage(
                    parsedContent.originalMessage,
                    parsedContent.signatureBase64,
                    parsedContent.hashAlgorithm,
                    parsedContent.hashHex
                );
                alert('Signed message successfully uploaded!');
                resolve(fileContent);
            } catch (error) {
                document.getElementById(targetTextAreaId).value = '';
                alert(`Error uploading signed message: ${error.message}`);
                console.error("Error uploading signed message:", error);
                reject(error);
            }
        };
        reader.onerror = (error) => {
            alert('Error reading file.');
            console.error('File read error:', error);
            reject(error);
        };
        reader.readAsText(file);
    });
}


function handleSelectPublicKeyFileEncrypt() {
    document.getElementById('uploadPublicKeyInputEncrypt').click();
}
function handleSelectPrivateKeyFileEncryptSign() {
    document.getElementById('uploadPrivateKeyInputEncryptSign').click();
}
function handleSelectPrivateKeyFileDecrypt() {
    document.getElementById('uploadPrivateKeyInputDecrypt').click();
}
function handleSelectEncryptedFileDecrypt() {
    document.getElementById('uploadEncryptedInputDecrypt').click();
}
function handleSelectPublicKeyFileDecryptVerify() {
    document.getElementById('uploadPublicKeyInputDecryptVerify').click();
}
function handleSelectPrivateKeyFileSign() {
    document.getElementById('uploadPrivateKeyInputSign').click();
}
function handleSelectSignedMessageFileVerify() {
    document.getElementById('uploadSignedMessageInputVerify').click();
}
function handleSelectPublicKeyFileVerify() {
    document.getElementById('uploadPublicKeyInputVerify').click();
}


async function handleEncryptMessage() {
    const message = document.getElementById('messageToEncrypt').value;
    const publicKeyInput = document.getElementById('publicKeyInputEncrypt').value;
    const signAndEncrypt = document.getElementById('signAndEncryptCheckbox').checked;
    const privateKeyInputEncryptSign = document.getElementById('privateKeyInputEncryptSign').value;
    const statusElement = document.getElementById('encryptStatus');
    
    const startTime = performance.now();
    statusElement.textContent = `Encrypting... \t ${(performance.now() - startTime).toFixed(2)} ms`;
    statusElement.classList.remove('success', 'error');
    document.getElementById('encryptedOutput').value = '';

    if (!message) {
        statusElement.textContent = `Error: Please enter a message to encrypt. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }
    if (!publicKeyInput) {
        statusElement.textContent = `Error: Please paste or upload the recipient's public key. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }

    try {
        const publicKeyRecipient = parseKey(publicKeyInput);
        if (!publicKeyRecipient.e || !publicKeyRecipient.n) {
            throw new Error("Invalid recipient's public key format. Expected a key with 'e' and 'n'.");
        }

        let privateKeySigner = null;
        if (signAndEncrypt) {
            if (!privateKeyInputEncryptSign) {
                throw new Error("Please select a private key for signing if 'Sign Message' is checked.");
            }
            privateKeySigner = parseKey(privateKeyInputEncryptSign);
            if (!privateKeySigner.d || !privateKeySigner.n) {
                throw new Error("Invalid private key format for signing. Expected a key with 'd' and 'n'.");
            }
        }

        const dataBytes = new TextEncoder().encode(message);

        const rawEncryptedBase64 = await encryptData(dataBytes, publicKeyRecipient, privateKeySigner, statusElement, startTime);
        const formattedEncrypted = formatEncryptedMessage(rawEncryptedBase64);
        document.getElementById('encryptedOutput').value = formattedEncrypted;

    } catch (error) {
        statusElement.textContent = `Encryption error: ${error.message}`;
        statusElement.classList.add('error');
        console.error("Encryption error:", error);
    }
}

async function handleDecryptMessage() {
    const encryptedMessageInput = document.getElementById('messageToDecrypt').value;
    const privateKeyInput = document.getElementById('privateKeyInputDecrypt').value;
    const verifySignatureDecryptCheckbox = document.getElementById('verifySignatureDecryptCheckbox');
    const publicKeyInputDecryptVerify = document.getElementById('publicKeyInputDecryptVerify').value;
    const statusElement = document.getElementById('decryptStatus');

    const startTime = performance.now();
    statusElement.textContent = `Decrypting... \t ${(performance.now() - startTime).toFixed(2)} ms`;
    statusElement.classList.remove('success', 'error');
    document.getElementById('decryptedOutput').value = '';

    if (!encryptedMessageInput) {
        statusElement.textContent = `Error: Please paste or upload an encrypted message. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }
    if (!privateKeyInput) {
        statusElement.textContent = `Error: Please paste or upload the recipient's private key. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }

    try {
        const rawEncryptedBase64 = parseEncryptedMessage(encryptedMessageInput);
        const privateKeyRecipient = parseKey(privateKeyInput);
        if (!privateKeyRecipient.d || !privateKeyRecipient.n) {
            throw new Error("Invalid recipient's private key format. Expected a key with 'd' and 'n'.");
        }

        const encrypted_bytes_payload_for_check = Uint8Array.from(atob(rawEncryptedBase64), c => c.charCodeAt(0));
        let is_signed_flag_from_file = 0;
        if (encrypted_bytes_payload_for_check.length >= 6) {
            const header_main_view = new DataView(encrypted_bytes_payload_for_check.buffer, 0, 6);
            is_signed_flag_from_file = header_main_view.getUint8(5);
        } else {
            console.warn("Encrypted message too short to check signed flag. Assuming unsigned.");
        }

        const publicKeyForVerificationContainer = document.getElementById('publicKeyForVerificationContainer');
        publicKeyForVerificationContainer.style.display = verifySignatureDecryptCheckbox.checked ? 'block' : 'none';


        let publicSigningKey = null;
        if (verifySignatureDecryptCheckbox.checked) {
            if (is_signed_flag_from_file === 0) {

                throw new Error("Message is not signed, but 'Verify Signature' option is enabled. Disable it or load a signed message.");
            }

            if (!publicKeyInputDecryptVerify) {
                console.warn("Sender's public key not provided for signature verification. Decrypting, but signature will not be verified.");
                statusElement.textContent = `Warning: Signature verification skipped. No public key provided. \t ${(performance.now() - startTime).toFixed(2)} ms`;
                statusElement.classList.add('warning');
            } else {
                publicSigningKey = parseKey(publicKeyInputDecryptVerify);
                if (!publicSigningKey.e || !publicSigningKey.n) {
                    throw new Error("Invalid sender's public key format for verification. Expected a key with 'e' and 'n'.");
                }
            }
        } else {
            document.getElementById('publicKeyInputDecryptVerify').value = '';
        }

        const decryptedText = await decryptData(rawEncryptedBase64, privateKeyRecipient, publicSigningKey, statusElement, startTime);
        document.getElementById('decryptedOutput').value = decryptedText;

    } catch (error) {
        statusElement.textContent = `Decryption error: ${error.message}`;
        statusElement.classList.add('error');
        console.error("Decryption error:", error);
    }
}


async function handleComputeHash() {
    const message = document.getElementById('messageForHash').value;
    const algorithm = document.getElementById('hashAlgorithm').value;
    const statusElement = document.getElementById('hashStatus');
    const outputElement = document.getElementById('hashOutput');
    
    const startTime = performance.now();
    statusElement.textContent = `Computing hash... \t ${(performance.now() - startTime).toFixed(2)} ms`;
    statusElement.classList.remove('success', 'error');
    outputElement.value = '';

    try {
        const hash = await computeHash(message, algorithm, statusElement, startTime);
        outputElement.value = hash;
    } catch (error) {
        statusElement.textContent = `Error computing hash: ${error.message}`;
        statusElement.classList.add('error');
        console.error("Error computing hash:", error);
    }
}

async function handleSignMessage() {
    const message = document.getElementById('messageToSign').value;
    const privateKeyInput = document.getElementById('privateKeyInputSign').value;
    const statusElement = document.getElementById('signStatus');
    const signatureOutput = document.getElementById('signatureOutput');
    
    const startTime = performance.now();
    statusElement.textContent = `Signing message... \t ${(performance.now() - startTime).toFixed(2)} ms`;
    statusElement.classList.remove('success', 'error');
    signatureOutput.value = '';

    if (!message) {
        statusElement.textContent = `Error: Please enter a message to sign. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }
    if (!privateKeyInput) {
        statusElement.textContent = `Error: Please paste or upload your private key for signing. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }

    try {
        const privateKey = parseKey(privateKeyInput);
        if (!privateKey.d || !privateKey.n) {
            throw new Error("Invalid private key format. Expected a key with 'd' and 'n'.");
        }
        
        const rawSignatureBase64 = await signMessageRaw(message, privateKey, statusElement, startTime);
        const hashHex = await computeHash(message, 'SHA-256', {textContent: '', classList: {add:()=>{}, remove:()=>{}}}, performance.now());

        const formattedSigned = formatSignedMessage(message, rawSignatureBase64, 'SHA-256', hashHex);

        signatureOutput.value = formattedSigned;
    } catch (error) {
        statusElement.textContent = `Signing error: ${error.message}`;
        statusElement.classList.add('error');
        console.error("Signing error:", error);
    }
}

async function handleVerifySignature() {
    const signedMessageInput = document.getElementById('signedMessageToVerify').value;
    const publicKeyInput = document.getElementById('publicKeyInputVerify').value;
    const statusElement = document.getElementById('verifyStatus');
    
    const startTime = performance.now();
    statusElement.textContent = `Verifying signature... \t ${(performance.now() - startTime).toFixed(2)} ms`;
    statusElement.classList.remove('success', 'error');

    if (!signedMessageInput) {
        statusElement.textContent = `Error: Please paste or upload a signed message. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }
    if (!publicKeyInput) {
        statusElement.textContent = `Error: Please paste or upload the sender's public key. \t ${(performance.now() - startTime).toFixed(2)} ms`;
        statusElement.classList.add('error');
        return;
    }

    try {
        const { originalMessage, signatureBase64, hashAlgorithm, hashHex } = parseSignedMessage(signedMessageInput);

        const publicKey = parseKey(publicKeyInput);
        if (!publicKey.e || !publicKey.n) {
            throw new Error("Invalid public key format. Expected a key with 'e' and 'n'.");
        }

        if (hashAlgorithm !== 'SHA-256') {
            console.warn(`Hash algorithm in signed message (${hashAlgorithm}) is not SHA-256. This implementation only supports SHA-256 for signature verification.`);
        }

        const isValid = await verifySignatureRaw(originalMessage, signatureBase64, publicKey, statusElement, startTime);
    } catch (error) {
        statusElement.textContent = `Verification error: ${error.message}`;
        statusElement.classList.add('error');
        console.error("Verification error:", error);
    }
}


// --- DOMContentLoaded event listener ---
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('generateKeysBtn').addEventListener('click', handleGenerateKeys);
    document.getElementById('downloadPublicKeyBtn').addEventListener('click', handleDownloadPublicKey);
    document.getElementById('downloadPrivateKeyBtn').addEventListener('click', handleDownloadPrivateKey);

    document.getElementById('selectPublicKeyFileEncryptBtn').addEventListener('click', handleSelectPublicKeyFileEncrypt);
    document.getElementById('uploadPublicKeyInputEncrypt').addEventListener('change', () => handleKeyFileUpload('uploadPublicKeyInputEncrypt', 'publicKeyInputEncrypt'));

    const signAndEncryptCheckbox = document.getElementById('signAndEncryptCheckbox');
    const privateKeyForSigningContainer = document.getElementById('privateKeyForSigningContainer');
    signAndEncryptCheckbox.addEventListener('change', () => {
        privateKeyForSigningContainer.style.display = signAndEncryptCheckbox.checked ? 'block' : 'none';
    });
    document.getElementById('selectPrivateKeyFileEncryptSignBtn').addEventListener('click', handleSelectPrivateKeyFileEncryptSign);
    document.getElementById('uploadPrivateKeyInputEncryptSign').addEventListener('change', () => handleKeyFileUpload('uploadPrivateKeyInputEncryptSign', 'privateKeyInputEncryptSign'));

    document.getElementById('encryptMessageBtn').addEventListener('click', handleEncryptMessage);
    document.getElementById('downloadEncryptedMessageBtn').addEventListener('click', handleDownloadEncryptedMessage);

    document.getElementById('selectEncryptedFileDecryptBtn').addEventListener('click', handleSelectEncryptedFileDecrypt);
    document.getElementById('uploadEncryptedInputDecrypt').addEventListener('change', () => handleEncryptedFileUpload('uploadEncryptedInputDecrypt', 'messageToDecrypt'));

    document.getElementById('selectPrivateKeyFileDecryptBtn').addEventListener('click', handleSelectPrivateKeyFileDecrypt);
    document.getElementById('uploadPrivateKeyInputDecrypt').addEventListener('change', () => handleKeyFileUpload('uploadPrivateKeyInputDecrypt', 'privateKeyInputDecrypt'));

    const verifySignatureDecryptCheckbox = document.getElementById('verifySignatureDecryptCheckbox');
    const publicKeyForVerificationContainer = document.getElementById('publicKeyForVerificationContainer');

    publicKeyForVerificationContainer.style.display = verifySignatureDecryptCheckbox.checked ? 'block' : 'none';

    verifySignatureDecryptCheckbox.addEventListener('change', () => {
        publicKeyForVerificationContainer.style.display = verifySignatureDecryptCheckbox.checked ? 'block' : 'none';
        if (!verifySignatureDecryptCheckbox.checked) {
            document.getElementById('publicKeyInputDecryptVerify').value = '';
        }
    });

    document.getElementById('selectPublicKeyFileDecryptVerifyBtn').addEventListener('click', handleSelectPublicKeyFileDecryptVerify);
    document.getElementById('uploadPublicKeyInputDecryptVerify').addEventListener('change', () => handleKeyFileUpload('uploadPublicKeyInputDecryptVerify', 'publicKeyInputDecryptVerify'));

    document.getElementById('decryptMessageBtn').addEventListener('click', handleDecryptMessage);

    document.getElementById('computeHashBtn').addEventListener('click', handleComputeHash);

    document.getElementById('selectPrivateKeyFileSignBtn').addEventListener('click', handleSelectPrivateKeyFileSign);
    document.getElementById('uploadPrivateKeyInputSign').addEventListener('change', () => handleKeyFileUpload('uploadPrivateKeyInputSign', 'privateKeyInputSign'));
    document.getElementById('signMessageBtn').addEventListener('click', handleSignMessage);
    document.getElementById('downloadSignedMessageBtn').addEventListener('click', handleDownloadSignedMessage);

    document.getElementById('selectSignedMessageFileVerifyBtn').addEventListener('click', handleSelectSignedMessageFileVerify);
    document.getElementById('uploadSignedMessageInputVerify').addEventListener('change', () => handleSignedMessageFileUpload('uploadSignedMessageInputVerify', 'signedMessageToVerify'));
    document.getElementById('selectPublicKeyFileVerifyBtn').addEventListener('click', handleSelectPublicKeyFileVerify);
    document.getElementById('uploadPublicKeyInputVerify').addEventListener('change', () => handleKeyFileUpload('uploadPublicKeyInputVerify', 'publicKeyInputVerify'));
    document.getElementById('verifySignatureBtn').addEventListener('click', handleVerifySignature);
});
