# aegis.py - Python bindings for Aegis prototype

import ctypes
import os
from ctypes import c_int, c_size_t, c_uint8, POINTER, byref

# Load the Aegis library
def _load_aegis_lib():
    # Determine the library file extension based on the platform
    if os.name == 'posix':
        lib_ext = '.so'
    elif os.name == 'nt':
        lib_ext = '.dll'
    else:
        raise RuntimeError("Unsupported platform")
    
    # Try to find the library in common locations
    lib_name = 'libaegis' + lib_ext
    locations = [
        os.path.dirname(os.path.abspath(__file__)),  # Same directory as this script
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'),  # lib subdirectory
        '/usr/local/lib',  # Common Unix location
        '/usr/lib',        # Common Unix location
    ]
    
    for loc in locations:
        try:
            lib_path = os.path.join(loc, lib_name)
            return ctypes.CDLL(lib_path)
        except OSError:
            continue
    
    raise RuntimeError(f"Could not find {lib_name} in any of the expected locations")

# Error handling
class AegisError(Exception):
    """Exception raised for Aegis library errors."""
    
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"Aegis error {code}: {message}")

def _check_error(result):
    """Check the return code from Aegis functions and raise an exception if an error occurred."""
    if result != 0:  # AEGIS_SUCCESS
        error_messages = {
            -1: "Invalid parameter",
            -2: "Memory allocation failed",
            -3: "Insufficient buffer",
            -4: "Verification failed",
            -5: "Internal error"
        }
        message = error_messages.get(result, "Unknown error")
        raise AegisError(result, message)
    return result

# Try to load the library
try:
    _lib = _load_aegis_lib()
    
    # Define function prototypes
    _lib.aegis_init.argtypes = []
    _lib.aegis_init.restype = c_int
    
    _lib.aegis_cleanup.argtypes = []
    _lib.aegis_cleanup.restype = c_int
    
    _lib.aegis_kyber_keygen.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), POINTER(c_size_t)
    ]
    _lib.aegis_kyber_keygen.restype = c_int
    
    _lib.aegis_kyber_encaps.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), c_size_t
    ]
    _lib.aegis_kyber_encaps.restype = c_int
    
    _lib.aegis_kyber_decaps.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    _lib.aegis_kyber_decaps.restype = c_int
    
    _lib.aegis_sphincs_keygen.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), POINTER(c_size_t)
    ]
    _lib.aegis_sphincs_keygen.restype = c_int
    
    _lib.aegis_sphincs_sign.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    _lib.aegis_sphincs_sign.restype = c_int
    
    _lib.aegis_sphincs_verify.argtypes = [
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    _lib.aegis_sphincs_verify.restype = c_int
    
    _lib.aegis_encrypt_and_sign.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    _lib.aegis_encrypt_and_sign.restype = c_int
    
    _lib.aegis_verify_and_decrypt.argtypes = [
        POINTER(c_uint8), POINTER(c_size_t),
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t,
        POINTER(c_uint8), c_size_t
    ]
    _lib.aegis_verify_and_decrypt.restype = c_int
    
except (OSError, AttributeError) as e:
    raise RuntimeError(f"Failed to initialize Aegis library: {str(e)}")

# Initialize the library when the module is imported
_check_error(_lib.aegis_init())

# Clean up the library when the module is unloaded
import atexit
atexit.register(lambda: _lib.aegis_cleanup())

# Kyber key sizes (approximate for buffer allocation)
KYBER_PUBLIC_KEY_SIZE = 1200
KYBER_SECRET_KEY_SIZE = 2400
KYBER_CIPHERTEXT_SIZE = 1100
KYBER_SHARED_SECRET_SIZE = 32

# SPHINCS+ key and signature sizes (approximate for buffer allocation)
SPHINCS_PUBLIC_KEY_SIZE = 64
SPHINCS_SECRET_KEY_SIZE = 128
SPHINCS_SIGNATURE_SIZE = 16_000  # SPHINCS+ signatures can be large


def init():
    """Initialize the Aegis library explicitly (though it's done automatically on import)."""
    return _check_error(_lib.aegis_init())


def cleanup():
    """Clean up the Aegis library explicitly (though it's done automatically at exit)."""
    return _check_error(_lib.aegis_cleanup())


def kyber_keygen():
    """
    Generate a new Kyber key pair.
    
    Returns:
        tuple: (public_key, secret_key) as bytes
    """
    # Prepare buffers
    public_key = (c_uint8 * KYBER_PUBLIC_KEY_SIZE)()
    public_key_len = c_size_t(KYBER_PUBLIC_KEY_SIZE)
    secret_key = (c_uint8 * KYBER_SECRET_KEY_SIZE)()
    secret_key_len = c_size_t(KYBER_SECRET_KEY_SIZE)
    
    # Call the function
    _check_error(_lib.aegis_kyber_keygen(
        public_key, byref(public_key_len),
        secret_key, byref(secret_key_len)
    ))
    
    # Convert to Python bytes
    return (bytes(public_key[:public_key_len.value]),
            bytes(secret_key[:secret_key_len.value]))


def kyber_encaps(public_key):
    """
    Encapsulate a shared secret using Kyber.
    
    Args:
        public_key (bytes): Recipient's Kyber public key
    
    Returns:
        tuple: (ciphertext, shared_secret) as bytes
    """
    # Prepare buffers
    ciphertext = (c_uint8 * KYBER_CIPHERTEXT_SIZE)()
    ciphertext_len = c_size_t(KYBER_CIPHERTEXT_SIZE)
    shared_secret = (c_uint8 * KYBER_SHARED_SECRET_SIZE)()
    shared_secret_len = c_size_t(KYBER_SHARED_SECRET_SIZE)
    
    # Convert Python bytes to ctypes array
    pk_array = (c_uint8 * len(public_key))(*public_key)
    
    # Call the function
    _check_error(_lib.aegis_kyber_encaps(
        ciphertext, byref(ciphertext_len),
        shared_secret, byref(shared_secret_len),
        pk_array, len(public_key)
    ))
    
    # Convert to Python bytes
    return (bytes(ciphertext[:ciphertext_len.value]),
            bytes(shared_secret[:shared_secret_len.value]))


def kyber_decaps(ciphertext, secret_key):
    """
    Decapsulate a shared secret using Kyber.
    
    Args:
        ciphertext (bytes): Ciphertext containing the encapsulated shared secret
        secret_key (bytes): Recipient's Kyber secret key
    
    Returns:
        bytes: The shared secret
    """
    # Prepare buffers
    shared_secret = (c_uint8 * KYBER_SHARED_SECRET_SIZE)()
    shared_secret_len = c_size_t(KYBER_SHARED_SECRET_SIZE)
    
    # Convert Python bytes to ctypes arrays
    ct_array = (c_uint8 * len(ciphertext))(*ciphertext)
    sk_array = (c_uint8 * len(secret_key))(*secret_key)
    
    # Call the function
    _check_error(_lib.aegis_kyber_decaps(
        shared_secret, byref(shared_secret_len),
        ct_array, len(ciphertext),
        sk_array, len(secret_key)
    ))
    
    # Convert to Python bytes
    return bytes(shared_secret[:shared_secret_len.value])


def sphincs_keygen():
    """
    Generate a new SPHINCS+ key pair.
    
    Returns:
        tuple: (public_key, secret_key) as bytes
    """
    # Prepare buffers
    public_key = (c_uint8 * SPHINCS_PUBLIC_KEY_SIZE)()
    public_key_len = c_size_t(SPHINCS_PUBLIC_KEY_SIZE)
    secret_key = (c_uint8 * SPHINCS_SECRET_KEY_SIZE)()
    secret_key_len = c_size_t(SPHINCS_SECRET_KEY_SIZE)
    
    # Call the function
    _check_error(_lib.aegis_sphincs_keygen(
        public_key, byref(public_key_len),
        secret_key, byref(secret_key_len)
    ))
    
    # Convert to Python bytes
    return (bytes(public_key[:public_key_len.value]),
            bytes(secret_key[:secret_key_len.value]))


def sphincs_sign(message, secret_key):
    """
    Sign a message using SPHINCS+.
    
    Args:
        message (bytes): Message to sign
        secret_key (bytes): Signer's SPHINCS+ secret key
    
    Returns:
        bytes: The signature
    """
    # Prepare buffers
    signature = (c_uint8 * SPHINCS_SIGNATURE_SIZE)()
    signature_len = c_size_t(SPHINCS_SIGNATURE_SIZE)
    
    # Convert Python bytes to ctypes arrays
    msg_array = (c_uint8 * len(message))(*message)
    sk_array = (c_uint8 * len(secret_key))(*secret_key)
    
    # Call the function
    _check_error(_lib.aegis_sphincs_sign(
        signature, byref(signature_len),
        msg_array, len(message),
        sk_array, len(secret_key)
    ))
    
    # Convert to Python bytes
    return bytes(signature[:signature_len.value])


def sphincs_verify(signature, message, public_key):
    """
    Verify a SPHINCS+ signature.
    
    Args:
        signature (bytes): Signature to verify
        message (bytes): Message that was signed
        public_key (bytes): Signer's SPHINCS+ public key
    
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    # Convert Python bytes to ctypes arrays
    sig_array = (c_uint8 * len(signature))(*signature)
    msg_array = (c_uint8 * len(message))(*message)
    pk_array = (c_uint8 * len(public_key))(*public_key)
    
    # Call the function
    try:
        _check_error(_lib.aegis_sphincs_verify(
            sig_array, len(signature),
            msg_array, len(message),
            pk_array, len(public_key)
        ))
        return True
    except AegisError as e:
        if e.code == -4:  # AEGIS_ERROR_VERIFICATION
            return False
        raise


def encrypt_and_sign(message, recipient_kyber_pk, sender_sphincs_sk):
    """
    Encrypt and sign a message.
    
    Args:
        message (bytes): Message to encrypt and sign
        recipient_kyber_pk (bytes): Recipient's Kyber public key
        sender_sphincs_sk (bytes): Sender's SPHINCS+ secret key
    
    Returns:
        tuple: (ciphertext, encaps_ct, signature) as bytes
    """
    # Estimate buffer sizes
    max_ciphertext_len = len(message) + 100  # Message plus AES-GCM overhead
    
    # Prepare buffers
    ciphertext = (c_uint8 * max_ciphertext_len)()
    ciphertext_len = c_size_t(max_ciphertext_len)
    encaps_ct = (c_uint8 * KYBER_CIPHERTEXT_SIZE)()
    encaps_ct_len = c_size_t(KYBER_CIPHERTEXT_SIZE)
    signature = (c_uint8 * SPHINCS_SIGNATURE_SIZE)()
    signature_len = c_size_t(SPHINCS_SIGNATURE_SIZE)
    
    # Convert Python bytes to ctypes arrays
    msg_array = (c_uint8 * len(message))(*message)
    kyber_pk_array = (c_uint8 * len(recipient_kyber_pk))(*recipient_kyber_pk)
    sphincs_sk_array = (c_uint8 * len(sender_sphincs_sk))(*sender_sphincs_sk)
    
    # Call the function
    _check_error(_lib.aegis_encrypt_and_sign(
        ciphertext, byref(ciphertext_len),
        encaps_ct, byref(encaps_ct_len),
        signature, byref(signature_len),
        msg_array, len(message),
        kyber_pk_array, len(recipient_kyber_pk),
        sphincs_sk_array, len(sender_sphincs_sk)
    ))
    
    # Convert to Python bytes
    return (bytes(ciphertext[:ciphertext_len.value]),
            bytes(encaps_ct[:encaps_ct_len.value]),
            bytes(signature[:signature_len.value]))


def verify_and_decrypt(ciphertext, encaps_ct, signature, recipient_kyber_sk, sender_sphincs_pk):
    """
    Verify and decrypt a message.
    
    Args:
        ciphertext (bytes): Encrypted message
        encaps_ct (bytes): Kyber ciphertext
        signature (bytes): SPHINCS+ signature
        recipient_kyber_sk (bytes): Recipient's Kyber secret key
        sender_sphincs_pk (bytes): Sender's SPHINCS+ public key
    
    Returns:
        bytes: The decrypted message
    """
    # Prepare buffers - assume message isn't larger than ciphertext
    max_message_len = len(ciphertext)
    message = (c_uint8 * max_message_len)()
    message_len = c_size_t(max_message_len)
    
    # Convert Python bytes to ctypes arrays
    ct_array = (c_uint8 * len(ciphertext))(*ciphertext)
    encaps_array = (c_uint8 * len(encaps_ct))(*encaps_ct)
    sig_array = (c_uint8 * len(signature))(*signature)
    kyber_sk_array = (c_uint8 * len(recipient_kyber_sk))(*recipient_kyber_sk)
    sphincs_pk_array = (c_uint8 * len(sender_sphincs_pk))(*sender_sphincs_pk)
    
    # Call the function
    _check_error(_lib.aegis_verify_and_decrypt(
        message, byref(message_len),
        ct_array, len(ciphertext),
        encaps_array, len(encaps_ct),
        sig_array, len(signature),
        kyber_sk_array, len(recipient_kyber_sk),
        sphincs_pk_array, len(sender_sphincs_pk)
    ))
    
    # Convert to Python bytes
    return bytes(message[:message_len.value])
