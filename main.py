#!/usr/bin/env python3
import library_ecc as lib


class Person():
    def __init__(self, name):
        self.name = name
        # private_value = private_key.private_numbers().x
        self.private_key = lib.generate_private_key()
        self.public_key = lib.generate_pub_key(self.private_key)
        # stores "alice": (pub_key, shared_key, is_verified)
        self.pub_key_of = {}

    def store_pub_key_of(self, name, peer_pub_key):
        shared_key = lib.generate_shared_key(self.private_key, peer_pub_key)
        self.pub_key_of[name] = (peer_pub_key, shared_key, False)

    def share_pub_key_with(self, name): # -> (pub_key, encr_sign_hash_keys)
        if name not in self.pub_key_of.keys():
            return (self.public_key, None)

        (peer_pub_key, shared_key, _) = self.pub_key_of[name]
        (ciphertext, nonce) = lib.encrypt_aes(self.name, shared_key, self.public_key, peer_pub_key, self.private_key)
        return (self.public_key, (ciphertext, nonce))

    def verify_pub_key_of(self, name, signed_keys_nonce):
        (peer_pub_key, shared_key, is_verified) = self.get_pub_key_of(name)
        if is_verified:
            return True # already verified

        hashed_keys = lib.decrypt_dh(shared_key, signed_keys_nonce)
        is_verified = lib.verify_signed_hash(self.public_key, peer_pub_key, hashed_keys)
        self.pub_key_of[name] = (peer_pub_key, shared_key, is_verified)
        return is_verified

    def get_pub_key_of(self, name):
        try:
            return self.pub_key_of[name]
        except KeyError:
            print(f"Could not find public key of {name}")


alice = Person("alice")
bob = Person("bob")

# ##########################################
#   simulation of the modified DH protocol
# ##########################################
#
# alice sends pub key to bob
(a_pub_key, _) = alice.share_pub_key_with(bob.name)
# bob stores the pub key of alice
bob.store_pub_key_of(alice.name, a_pub_key)

# bob sends pub key to alice +
#           signed hash of their public keys
(b_pub_key, b_encry_signed_keys) = bob.share_pub_key_with(alice.name)
# alice stores pub key of bob, and verifies it
alice.store_pub_key_of(bob.name, b_pub_key)
bob_is_verified = alice.verify_pub_key_of(bob.name, b_encry_signed_keys)

print("The signed hash of bob:")
print(b_encry_signed_keys)
print(f"is verified: {bob_is_verified}")

# alice sends signed hash of their public keys
(a_pub_key, a_encry_signed_keys) = alice.share_pub_key_with(bob.name)
# bob checks if this is alice
alice_is_verified = bob.verify_pub_key_of(alice.name, a_encry_signed_keys)
print("The signed hash of alice:")
print(a_encry_signed_keys)
print(f"is verified: {alice_is_verified}")
