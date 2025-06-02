#!/usr/bin/env python3
import library_ecc as lib


class Person():
    def __init__(self, name):
        self.name = name
        self.private_key = lib.generate_private_key()
        self.public_key = lib.generate_pub_key(self.private_key)
        # stores "alice": (pub_key, shared_key, is_verified)
        self.peers = {}

    def store_pub_key_of(self, name, peer_pub_key):
        shared_key = lib.generate_shared_key(self.private_key, peer_pub_key)
        self.peers[name] = (peer_pub_key, shared_key, False)

    def encrypt_signed_hash_of_pub_keys(self, name):
        peer = self.peers.get(name)
        if peer is None:
            print(f"Could not find public key of {name}")
        else:
            peer_pub_key, shared_key, _ = peer
            ciphertext, nonce = lib.encrypt_aes(self.name, shared_key, self.public_key, peer_pub_key, self.private_key)
            return ciphertext, nonce

    def verify_pub_key_of(self, name, signed_keys_nonce):
        peer = self.peers.get(name)
        if peer is None:
            print(f"Could not find public key of {name}")
            return False

        peer_pub_key, shared_key, is_verified = peer
        if is_verified:
            return True # already verified

        hashed_keys = lib.decrypt_dh(shared_key, signed_keys_nonce)
        is_verified = lib.verify_signed_hash(self.public_key, peer_pub_key, hashed_keys)
        self.peers[name] = (peer_pub_key, shared_key, is_verified)
        return is_verified


alice = Person("alice")
bob = Person("bob")

# ##########################################
#   simulation of the modified DH protocol
# ##########################################
#
# alice sends pub key to bob
a_pub_key = alice.public_key
# bob stores the pub key of alice
bob.store_pub_key_of(alice.name, a_pub_key)

# bob sends pub key to alice +
#           signed hash of their public keys
b_pub_key = bob.public_key
b_encry_sign_keys = bob.encrypt_signed_hash_of_pub_keys(alice.name)
alice.store_pub_key_of(bob.name, b_pub_key)

# alice stores pub key of bob, and verifies it
bob_is_verified = alice.verify_pub_key_of(bob.name, b_encry_sign_keys)

print("The signed hash of bob:")
print(b_encry_sign_keys)
print(f"is verified: {bob_is_verified}")

# alice sends signed hash of their public keys
a_encry_sign_keys = alice.encrypt_signed_hash_of_pub_keys(bob.name)
# bob checks if this is alice
alice_is_verified = bob.verify_pub_key_of(alice.name, a_encry_sign_keys)
print("The signed hash of alice:")
print(a_encry_sign_keys)
print(f"is verified: {alice_is_verified}")
