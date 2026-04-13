import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# --- SHAMIR SECRET SHARING (SSS) ---
from secretsharing import SecretSharingFactory

class SentinelEngine:
    """The core security engine for RadiantAI SP."""
    
    def __init__(self):
        self.ledger_file = "sentinel_anchor.txt"
        self.sss = SecretSharingFactory.initialize("heya") # 16-bit field for chunking

    def generate_doctor_keys(self):
        """Generates a new ED25519 keypair for a doctor and splits the private key."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize keys
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # SSS: Split 32-byte key into two 16-byte halves and share them
        # Note: Simplification for demo. Real SSS would use 32-byte field.
        # We share the hex representation of the key
        priv_hex = priv_bytes.hex()
        shares = self.sss.split(2, 3, priv_hex) # 2-of-3 threshold
        
        return pub_bytes, shares

    def anchor_diagnostic(self, patient_name, scan_type, result):
        """Generates a cryptographically anchored hash for a diagnostic event."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_str = f"{patient_name}|{scan_type}|{result}|{timestamp}"
        
        block_hash = hashlib.sha256(event_str.encode()).hexdigest()
        return block_hash
