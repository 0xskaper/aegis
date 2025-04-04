#!/usr/bin/env python3
"""
Aegis Demo Application

This demo shows how to use the Aegis quantum-resistant cryptography module
for secure messaging between two users, Alice and Bob.
"""

import aegis
import base64
import json
import os
import time
from pathlib import Path

class User:
    """Represents a user in the secure messaging system."""
    
    def __init__(self, name, key_dir="keys"):
        self.name = name
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        
        # Load or generate keys
        self.kyber_pk, self.kyber_sk = self._load_or_generate_kyber_keys()
        self.sphincs_pk, self.sphincs_sk = self._load_or_generate_sphincs_keys()
        
        print(f"{self.name}'s keys are ready.")
    
    def _load_or_generate_kyber_keys(self):
        """Load Kyber keys from file or generate new ones if they don't exist."""
        kyber_pk_file = self.key_dir / f"{self.name}_kyber_pk.bin"
        kyber_sk_file = self.key_dir / f"{self.name}_kyber_sk.bin"
        
        if kyber_pk_file.exists() and kyber_sk_file.exists():
            print(f"Loading existing Kyber keys for {self.name}...")
            with open(kyber_pk_file, "rb") as f:
                kyber_pk = f.read()
            with open(kyber_sk_file, "rb") as f:
                kyber_sk = f.read()
        else:
            print(f"Generating new Kyber keys for {self.name}...")
            kyber_pk, kyber_sk = aegis.kyber_keygen()
            with open(kyber_pk_file, "wb") as f:
                f.write(kyber_pk)
            with open(kyber_sk_file, "wb") as f:
                f.write(kyber_sk)
        
        return kyber_pk, kyber_sk
    
    def _load_or_generate_sphincs_keys(self):
        """Load SPHINCS+ keys from file or generate new ones if they don't exist."""
        sphincs_pk_file = self.key_dir / f"{self.name}_sphincs_pk.bin"
        sphincs_sk_file = self.key_dir / f"{self.name}_sphincs_sk.bin"
        
        if sphincs_pk_file.exists() and sphincs_sk_file.exists():
            print(f"Loading existing SPHINCS+ keys for {self.name}...")
            with open(sphincs_pk_file, "rb") as f:
                sphincs_pk = f.read()
            with open(sphincs_sk_file, "rb") as f:
                sphincs_sk = f.read()
        else:
            print(f"Generating new SPHINCS+ keys for {self.name}...")
            sphincs_pk, sphincs_sk = aegis.sphincs_keygen()
            with open(sphincs_pk_file, "wb") as f:
                f.write(sphincs_pk)
            with open(sphincs_sk_file, "wb") as f:
                f.write(sphincs_sk)
        
        return sphincs_pk, sphincs_sk
    
    def get_public_key_bundle(self):
        """Get a bundle with both public keys for sharing."""
        return {
            "name": self.name,
            "kyber_pk": base64.b64encode(self.kyber_pk).decode('utf-8'),
            "sphincs_pk": base64.b64encode(self.sphincs_pk).decode('utf-8'),
            "timestamp": time.time()
        }
    
    def encrypt_message(self, message, recipient_key_bundle):
        """Encrypt and sign a message for the recipient."""
        # Extract recipient's public key
        recipient_kyber_pk = base64.b64decode(recipient_key_bundle["kyber_pk"])
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Encrypt and sign the message
        start_time = time.time()
        ciphertext, encaps_ct, signature = aegis.encrypt_and_sign(
            message, recipient_kyber_pk, self.sphincs_sk
        )
        encryption_time = time.time() - start_time
        
        # Create the message package
        message_package = {
            "sender": self.name,
            "recipient": recipient_key_bundle["name"],
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "encaps_ct": base64.b64encode(encaps_ct).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "timestamp": time.time()
        }
        
        print(f"Message encrypted and signed in {encryption_time:.3f} seconds")
        return message_package
    
    def decrypt_message(self, message_package, sender_key_bundle):
        """Decrypt and verify a message from the sender."""
        # Extract sender's public key
        sender_sphincs_pk = base64.b64decode(sender_key_bundle["sphincs_pk"])
        
        # Extract message components
        ciphertext = base64.b64decode(message_package["ciphertext"])
        encaps_ct = base64.b64decode(message_package["encaps_ct"])
        signature = base64.b64decode(message_package["signature"])
        
        # Verify and decrypt the message
        start_time = time.time()
        try:
            decrypted_message = aegis.verify_and_decrypt(
                ciphertext, encaps_ct, signature,
                self.kyber_sk, sender_sphincs_pk
            )
            decryption_time = time.time() - start_time
            print(f"Message verified and decrypted in {decryption_time:.3f} seconds")
            return decrypted_message.decode('utf-8')
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None


def save_message_package(message_package, messages_dir="messages"):
    """Save a message package to a file."""
    # Create the messages directory if it doesn't exist
    Path(messages_dir).mkdir(exist_ok=True)
    
    # Generate a filename based on sender, recipient, and timestamp
    sender = message_package["sender"]
    recipient = message_package["recipient"]
    timestamp = message_package["timestamp"]
    filename = f"{messages_dir}/{sender}_to_{recipient}_{timestamp}.json"
    
    # Save the message package
    with open(filename, "w") as f:
        json.dump(message_package, f, indent=2)
    
    return filename


def load_message_package(filename):
    """Load a message package from a file."""
    with open(filename, "r") as f:
        return json.load(f)


def main():
    print("="*50)
    print("  AEGIS QUANTUM-RESISTANT MESSAGING DEMO")
    print("="*50)
    print()
    
    # Create users Alice and Bob
    print("Setting up users...")
    alice = User("Alice")
    bob = User("Bob")
    
    # Exchange public keys (in a real application, this would be done through a server)
    alice_keys = alice.get_public_key_bundle()
    bob_keys = bob.get_public_key_bundle()
    
    # Measure key sizes
    alice_kyber_pk_size = len(base64.b64decode(alice_keys["kyber_pk"]))
    alice_sphincs_pk_size = len(base64.b64decode(alice_keys["sphincs_pk"]))
    print(f"\nKey sizes:")
    print(f"  Kyber public key: {alice_kyber_pk_size} bytes")
    print(f"  SPHINCS+ public key: {alice_sphincs_pk_size} bytes")
    print()
    
    # Alice sends a message to Bob
    print("\nAlice is composing a message to Bob...")
    alice_message = "Hello Bob! This message is encrypted with quantum-resistant cryptography. Even quantum computers won't be able to read this!"
    alice_package = alice.encrypt_message(alice_message, bob_keys)
    
    # Save Alice's message
    alice_msg_file = save_message_package(alice_package)
    print(f"Alice's message saved to {alice_msg_file}")
    
    # Measure encrypted message size
    ciphertext_size = len(base64.b64decode(alice_package["ciphertext"]))
    encaps_ct_size = len(base64.b64decode(alice_package["encaps_ct"]))
    signature_size = len(base64.b64decode(alice_package["signature"]))
    print(f"\nMessage sizes:")
    print(f"  Original message: {len(alice_message)} bytes")
    print(f"  Encrypted message: {ciphertext_size} bytes")
    print(f"  Kyber ciphertext: {encaps_ct_size} bytes")
    print(f"  SPHINCS+ signature: {signature_size} bytes")
    print(f"  Total size: {ciphertext_size + encaps_ct_size + signature_size} bytes")
    print()
    
    # Bob receives and decrypts Alice's message
    print("\nBob is reading Alice's message...")
    bob_received_msg = bob.decrypt_message(alice_package, alice_keys)
    print(f"Bob received: \"{bob_received_msg}\"")
    
    # Bob replies to Alice
    print("\nBob is composing a reply to Alice...")
    bob_message = "Hi Alice! Your quantum-resistant message was received successfully. This technology is amazing!"
    bob_package = bob.encrypt_message(bob_message, alice_keys)
    
    # Save Bob's message
    bob_msg_file = save_message_package(bob_package)
    print(f"Bob's message saved to {bob_msg_file}")
    
    # Alice receives and decrypts Bob's message
    print("\nAlice is reading Bob's message...")
    alice_received_msg = alice.decrypt_message(bob_package, bob_keys)
    print(f"Alice received: \"{alice_received_msg}\"")
    
    print("\nDemo completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up Aegis library
        aegis.cleanup()
