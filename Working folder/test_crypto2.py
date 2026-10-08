import cryptography.hazmat.primitives.asymmetric.rsa
private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048)