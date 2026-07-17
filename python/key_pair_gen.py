"""
This file will be used to generate a public & private key file pair.
Types include: RSA, DSA, ECDSA, ED25519, SSH-1 (RSA)
"""
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair():
    # generate keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    public_key = private_key.public_key()


    # file and directory info
    ssh_directory = Path("~/test_ssh").expanduser()
    ssh_directory.mkdir(parents=True, exist_ok=True)

    private_rsa_key_filename = "id_rsa"
    public_rsa_key_filename = "id_rsa.pub"

    private_key_filepath = ssh_directory / private_rsa_key_filename
    public_key_filepath = ssh_directory / public_rsa_key_filename

    # pem
    """
    for self knowledge: pem (privacy-enhanced mail) is the standard
    file format to store and transmit crypto keys & SSL/TLS certs
    """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    # create id_rsa and id_rsa.pub
    private_key_filepath.write_bytes(private_pem)
    public_key_filepath.write_bytes(public_pem)

    # set up permissions
    private_key_filepath.chmod(0o600)

if __name__ == "__main__":
    generate_rsa_key_pair()