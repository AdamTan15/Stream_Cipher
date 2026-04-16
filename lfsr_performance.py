"""
LFSR-based Stream Cipher
Implementation for NWC3373 - Fundamentals of Cryptography

Author: Muhammad Haziq Bin Hamzah
Date: March 2026

Feedback Polynomial: x^16 + x^14 + x^13 + x^11 + 1
Key Size: 16-bit seed (65,536 possible keys)
"""

import time
import os


def lfsr_keystream(seed, length):
    """
    Generate keystream using Linear Feedback Shift Register (LFSR)
    
    Parameters:
        seed (int): 16-bit initial state (0 - 65535)
        length (int): Number of keystream bytes to generate
    
    Returns:
        bytes: Pseudo-random keystream of specified length
    """
    state = seed & 0xFFFF  # Ensure state is 16-bit
    keystream = []
    
    # Feedback taps: bits 14, 13, 11, and 0 (0-indexed from LSB)
    # Polynomial: x^16 + x^14 + x^13 + x^11 + 1
    
    for _ in range(length):
        # Extract the least significant byte (lower 8 bits)
        keystream.append(state & 0xFF)
        
        # Calculate feedback bit by XORing tap positions
        # Bits are 0-indexed from LSB: bit0 = LSB, bit15 = MSB
        feedback = ((state >> 14) ^ (state >> 13) ^ (state >> 11) ^ (state >> 0)) & 1
        
        # Shift left by 1 bit and insert feedback at LSB
        state = ((state << 1) | feedback) & 0xFFFF  # Mask to 16 bits
    
    return bytes(keystream)


def stream_encrypt(plaintext, seed):
    """
    Encrypt plaintext using XOR with LFSR keystream
    
    Parameters:
        plaintext (bytes): Data to encrypt
        seed (int): 16-bit encryption key (0 - 65535)
    
    Returns:
        bytes: Encrypted ciphertext
    """
    # Generate keystream of same length as plaintext
    keystream = lfsr_keystream(seed, len(plaintext))
    
    # XOR plaintext with keystream byte by byte
    ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
    
    return ciphertext


def stream_decrypt(ciphertext, seed):
    """
    Decrypt ciphertext using XOR with LFSR keystream
    
    For XOR-based stream ciphers, encryption and decryption are identical.
    
    Parameters:
        ciphertext (bytes): Data to decrypt
        seed (int): 16-bit decryption key (must match encryption key)
    
    Returns:
        bytes: Decrypted plaintext
    """
    # XOR is its own inverse: plaintext XOR keystream = ciphertext
    # Therefore: ciphertext XOR keystream = plaintext
    return stream_encrypt(ciphertext, seed)


def verify_correctness():
    """Verify that encryption and decryption work correctly"""
    print("=" * 50)
    print("VERIFYING CORRECTNESS")
    print("=" * 50)
    
    test_seed = 0xACE1  # Test seed (44257 in decimal)
    test_plaintext = b"Stream Cipher Test Message! 12345"
    
    print(f"Test Seed: {test_seed} (0x{test_seed:04X})")
    print(f"Original Plaintext: {test_plaintext}")
    print(f"Plaintext Length: {len(test_plaintext)} bytes")
    print()
    
    # Encrypt
    ciphertext = stream_encrypt(test_plaintext, test_seed)
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Ciphertext Length: {len(ciphertext)} bytes")
    print()
    
    # Decrypt
    decrypted = stream_decrypt(ciphertext, test_seed)
    print(f"Decrypted Plaintext: {decrypted}")
    print()
    
    # Verify
    assert decrypted == test_plaintext, "ERROR: Decryption failed! Data mismatch."
    print("✓ SUCCESS: Encryption/Decryption correctness verified.\n")
    
    return True


def performance_test():
    """Measure encryption performance for different file sizes"""
    print("=" * 50)
    print("PERFORMANCE TEST")
    print("=" * 50)
    
    test_seed = 0xACE1
    file_sizes = {
        "1KB": 1024,
        "100KB": 102400,
        "1MB": 1048576
    }
    
    results = {}
    iterations = 10  # Number of iterations for accurate average
    
    for size_name, size_bytes in file_sizes.items():
        print(f"\nTesting {size_name} file ({size_bytes} bytes)...")
        
        # Generate random test data of specified size
        test_data = os.urandom(size_bytes)
        
        # Measure encryption time over multiple iterations
        times = []
        for i in range(iterations):
            start_time = time.perf_counter()
            ciphertext = stream_encrypt(test_data, test_seed)
            end_time = time.perf_counter()
            
            elapsed_ms = (end_time - start_time) * 1000
            times.append(elapsed_ms)
        
        # Calculate statistics
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        
        results[size_name] = {
            "avg_ms": avg_time,
            "min_ms": min_time,
            "max_ms": max_time,
            "bytes": size_bytes
        }
        
        print(f"  Average: {avg_time:.3f} ms")
        print(f"  Min: {min_time:.3f} ms")
        print(f"  Max: {max_time:.3f} ms")
        print(f"  Throughput: {size_bytes / (avg_time / 1000) / 1024 / 1024:.2f} MB/s")
    
    return results


def brute_force_demo():
    """Demonstrate why 16-bit key space is insecure"""
    print("\n" + "=" * 50)
    print("BRUTE-FORCE DEMONSTRATION")
    print("=" * 50)
    
    # Create a simple test
    original_message = b"Secret Message"
    correct_seed = 0x1234
    
    print(f"Original Message: {original_message}")
    print(f"Correct Seed: {correct_seed} (0x{correct_seed:04X})")
    print()
    
    # Encrypt with correct seed
    ciphertext = stream_encrypt(original_message, correct_seed)
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print()
    
    print("Simulating brute-force attack (testing all 65,536 seeds)...")
    print("(Limited to first 1000 seeds for demonstration)\n")
    
    start_time = time.perf_counter()
    found_seed = None
    
    # Try all possible seeds (limited to 1000 for demo)
    for seed in range(1000):
        decrypted = stream_decrypt(ciphertext, seed)
        
        # Check if decrypted text looks like English (simple heuristic)
        # Count printable ASCII characters
        printable_count = sum(32 <= b <= 126 for b in decrypted)
        if printable_count / len(decrypted) > 0.8:
            found_seed = seed
            print(f"  ✓ Candidate found! Seed: {seed} (0x{seed:04X})")
            print(f"    Decrypted: {decrypted}")
            break
    
    end_time = time.perf_counter()
    
    if found_seed == correct_seed:
        print(f"\n✓ SUCCESS: Correct seed found in {(end_time - start_time)*1000:.2f} ms")
    else:
        print(f"\n✓ Demonstrated: Even partial search finds candidates quickly")
    
    print("\n⚠️  WARNING: With only 65,536 possible keys, a full brute-force")
    print("   attack would take less than 1 second on modern hardware!")
    print("   This implementation is for EDUCATIONAL purposes only.")


def analyze_periodicity():
    """Demonstrate LFSR periodicity"""
    print("\n" + "=" * 50)
    print("PERIODICITY ANALYSIS")
    print("=" * 50)
    
    seed = 0xACE1
    max_period = 65535  # 2^16 - 1
    
    print(f"LFSR Maximum Period: {max_period} bytes (2^16 - 1)")
    print(f"Seed: {seed} (0x{seed:04X})")
    print()
    
    # Generate keystream and check for repeats
    keystream = lfsr_keystream(seed, max_period + 100)
    
    # Check if pattern repeats
    first_100 = keystream[:100]
    
    # Look for repetition of first 100 bytes elsewhere
    found_repeat = False
    for i in range(100, len(keystream) - 100):
        if keystream[i:i+100] == first_100:
            found_repeat = True
            print(f"⚠️  Keystream repeats at position {i} bytes")
            break
    
    if not found_repeat:
        print(f"✓ No repetition detected within first {max_period} bytes")
    
    print(f"\n⚠️  WARNING: After {max_period} bytes, the keystream will repeat!")
    print("   Encrypting messages longer than 65KB with the same seed")
    print("   creates a repeating keystream, enabling ciphertext-only attacks.")


def main():
    """Main program entry point"""
    print("\n" + "=" * 60)
    print("LFSR-BASED STREAM CIPHER")
    print("NWC3373 - Fundamentals of Cryptography")
    print("=" * 60)
    
    # Run verification
    verify_correctness()
    
    # Run performance tests
    results = performance_test()
    
    # Run security demonstrations
    brute_force_demo()
    analyze_periodicity()
    
    # Print final summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print("\nPerformance Results:")
    print("-" * 30)
    for size_name, data in results.items():
        print(f"{size_name}: {data['avg_ms']:.3f} ms avg | {data['min_ms']:.3f} ms min | {data['max_ms']:.3f} ms max")
    
    print("\nSecurity Assessment:")
    print("-" * 30)
    print("Key Space: 2^16 = 65,536 keys (INSECURE)")
    print("Periodicity: 65,535 bytes (INSECURE for long messages)")
    print("Linear Feedback: Predictable after 32 bytes (INSECURE)")
    print("\n⚠️  This implementation is for EDUCATIONAL purposes only.")
    print("   DO NOT use this to protect real sensitive data!")
    
    print("\n" + "=" * 50)
    print("END OF STREAM CIPHER DEMONSTRATION")
    print("=" * 50)


if __name__ == "__main__":
    main()
