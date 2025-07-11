from typing import Optional, Tuple

from util import dict_to_json_str, json_str_to_dict
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
# we can assume no password is longer than this many characters
MAX_PASSWORD_LENGTH = 64

########## START CODE HERE ##########
# Add any extra constants you may need
KEYCHAIN_SALT_LEN   = 16
SALT                = get_random_bytes(KEYCHAIN_SALT_LEN)

AES_256_DKLEN       = 32
HMAC_SALT           = get_random_bytes(AES_256_DKLEN)
AES_SALT            = get_random_bytes(AES_256_DKLEN)
########### END CODE HERE ###########


class Keychain:
    def __init__(
        self,
        ########## START CODE HERE ##########
        keychain_password: str,
        ########### END CODE HERE ###########
    ):
        """
        Initializes the keychain using the provided information. Note that external users should
        likely never invoke the constructor directly and instead use either Keychain.new or
        Keychain.load.

        Args:
            You may design the constructor with any additional arguments you would like.
        Returns:
            None
        """
        ########## START CODE HERE ##########
        if (len(keychain_password) > MAX_PASSWORD_LENGTH) \
                or (len(keychain_password) == 0):
            return None

        # Derive salt for the keychain master key
        keychain_salt = SALT

        # Derive the key derivation of the input password
        keychain_master_key = PBKDF2(keychain_password, keychain_salt, MAX_PASSWORD_LENGTH, PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

        # Derive sub-key for MAC of domain name
        keychain_mac_sub_key = HMAC.new(keychain_master_key, HMAC_SALT, digestmod=SHA256).digest()
        keychain_aes_sub_key = HMAC.new(keychain_master_key, AES_SALT, digestmod=SHA256).digest()

        self.data = {
            # Store member variables that you intend to be public here
            # (i.e. information that will not compromise security if an adversary sees).
            # This data should be dumped by the Keychain.dump function.
            # You should store the key-value store (KVS) in the "kvs" item in this dictionary.
            "kvs": {},
        }
        self.secrets = {
            # Store member variables that you intend to be private here
            # (information that an adversary should NOT see).
            "keychain_salt": keychain_salt,
            "keychain_mac_sub_key": keychain_mac_sub_key,
            "keychain_aes_sub_key": keychain_aes_sub_key,
        }
        ########### END CODE HERE ###########

    ########## START CODE HERE ##########
    # Add any helper functions you may want to add here

    ########### END CODE HERE ###########

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        """
        Creates an empty keychain with the given keychain password.

        Args:
            keychain_password: the password to unlock the keychain
        Returns:
            A Keychain instance
        """
        ########## START CODE HERE ##########
        return Keychain(keychain_password)
        ########### END CODE HERE ###########

    @staticmethod
    def load(
        keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """
        Creates a new keychain from an existing key-value store.

        Loads the keychain state from the provided representation (repr). You can assume that
        the representation passed to load is well-formed (i.e., it will be a valid JSON object)
        and was generated from the Keychain.dump function.

        Use the provided `json_str_to_dict` function to convert a JSON string into a nested dictionary.

        Args:
            keychain_password: the password to unlock the keychain
            repr: a JSON-encoded serialization of the contents of the key-value store (string)
            trusted_data_check: an optional SHA-256 checksum of the KVS (bytes or None)
        Returns:
            A Keychain instance containing the data from repr
        Throws:
            ValueError: if the checksum is provided in trusted_data_check and the checksum check fails
            ValueError: if the provided keychain password is not correct for the repr (hint: this is
                thrown for you by AES.verify)
        """
        ########## START CODE HERE ##########
        new_keychain = Keychain(keychain_password)
        if new_keychain == None:
            return None

        # Verify the hash integrity of KVS loaded from disk
        repr_hash = SHA256.new(str_to_bytes(repr)).digest()
        if trusted_data_check != None:
            if repr_hash != trusted_data_check:
                raise ValueError("KVS integrity is not correct, quitting the current operation ...")

        kvs_dict = json_str_to_dict(repr)
        # Verify if the keychain password is correct for the given database
        for key in kvs_dict["kvs"]:
            stored_pw_data = kvs_dict["kvs"][key]
            decoded_data = decode_bytes(stored_pw_data)
            nonce, ciphertext, tag, key_hash = decoded_data[:16], decoded_data[16:-48], decoded_data[-48:-32], decoded_data[-32:]
            # Verify swap attack
            if key_hash != SHA256.new(decode_bytes(key)).digest():
                raise ValueError("Key and value has been interchanged, quitting ...")
            # Create AES cipher object
            aes_cipher = AES.new(new_keychain.secrets["keychain_aes_sub_key"], AES.MODE_GCM, nonce=nonce)
            # Get relevant information for encryption and decryption
            decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

        new_keychain.data.update(kvs_dict)
        return new_keychain

        ########### END CODE HERE ###########

    def dump(self) -> Tuple[str, bytes]:
        """
        Returns a JSON serialization and a checksum of the contents of the keychain that can be
        loaded back using the Keychain.load function.

        For testing purposes, please ensure that the JSON string you return contains the key
        'kvs' with your KVS dict as its value. The KVS should have one key per domain.

        Use the provided `dict_to_json_str` function to convert a nested dictionary into
        its JSON representation.

        Returns:
            A tuple consisting of (1) the JSON serialization of the contents, and (2) the SHA256
            checksum of the JSON serialization
        """
        ########## START CODE HERE ##########
        try:
            kvs_dict_str = dict_to_json_str(self.data)
            kvs_dict_hash = SHA256.new(str_to_bytes(kvs_dict_str)).digest()
            return (kvs_dict_str, kvs_dict_hash)
        except (ValueError, KeyError):
            return (None, None)
        ########### END CODE HERE ###########

    def get(self, domain: str) -> Optional[str]:
        """
        Fetches the password corresponding to a given domain from the key-value store.

        Args:
            domain: the domain for which the password is requested
        Returns:
            The password for the domain if it exists in the KVS, or None if it does not exist
        """
        ########## START CODE HERE ##########
        # Create a HMAC object for domain name
        kvs_key = HMAC.new(self.secrets["keychain_mac_sub_key"], str_to_bytes(domain), digestmod=SHA256).digest()
        encode_kvs_key = encode_bytes(kvs_key)
        if encode_kvs_key not in self.data["kvs"]:
            return None

        try:
            stored_pw_data = self.data["kvs"][encode_kvs_key]
            decoded_data = decode_bytes(stored_pw_data)
            nonce, ciphertext, tag, key_hash = decoded_data[:16], decoded_data[16:-48], decoded_data[-48:-32], decoded_data[-32:]
            # Verify swap attack
            if key_hash != SHA256.new(kvs_key).digest():
                raise ValueError("Key and value has been interchanged, quitting ...")
            # Create AES cipher object
            aes_cipher = AES.new(self.secrets["keychain_aes_sub_key"], AES.MODE_GCM, nonce=nonce)
            # Get relevant information for encryption and decryption
            decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
            password = bytes_to_str(unpad(decrypted_data, AES.block_size))
            return password
        except (ValueError, KeyError):
            return None
        ########### END CODE HERE ###########

    def set(self, domain: str, password: str):
        """
        Inserts the domain and password into the KVS. If the domain is already
        in the password manager, this will update the password for that domain.
        If it is not, a new entry in the password manager is created.

        Args:
            domain: the domain for the provided password. This domain may already exist in the KVS
            password: the password for the provided domain
        """
        ########## START CODE HERE ##########
        if (len(password) > MAX_PASSWORD_LENGTH) \
                or (len(password) == 0):
            return
        
        # Create a HMAC object for domain name
        kvs_key = HMAC.new(self.secrets["keychain_mac_sub_key"], str_to_bytes(domain), digestmod=SHA256).digest()
        encode_kvs_key = encode_bytes(kvs_key)

        # Create AES cipher object
        aes_cipher = AES.new(self.secrets["keychain_aes_sub_key"], AES.MODE_GCM)

        # Get relevant information for encryption and decryption
        nonce = aes_cipher.nonce
        ciphetext, tag = aes_cipher.encrypt_and_digest(pad(str_to_bytes(password), AES.block_size))
        # Get the hash value of the domain name
        key_hash = SHA256.new(kvs_key).digest()
        # Combine nonce, ciphertext, and tag + hash of the key to avoid swap attack
        combined_data = nonce + ciphetext + tag + key_hash
        # Encode to Base64
        password_ciphertext = encode_bytes(combined_data)
        
        # Add the KVS into the dictionary
        self.data["kvs"][encode_kvs_key] = password_ciphertext
        ########### END CODE HERE ###########

    def remove(self, domain: str) -> bool:
        """
        Removes the domain-password pair for the provided domain from the password manager.
        If the domain does not exist in the password manager, this method deos nothing.

        Args:
            domain: the domain which should be removed from the KVS, along with its password
        Returns:
            True if the domain existed in the KVS and was removed, False otherwise
        """
        ########## START CODE HERE ##########
        kvs_key = HMAC.new(self.secrets["keychain_mac_sub_key"], str_to_bytes(domain), digestmod=SHA256).digest()
        encode_kvs_key = encode_bytes(kvs_key)
        if encode_kvs_key not in self.data["kvs"]:
            return False

        del self.data["kvs"][encode_kvs_key]
        return True
        ########### END CODE HERE ###########
