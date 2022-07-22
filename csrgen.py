#!/usr/bin/env python3

from OpenSSL.crypto import dump_certificate_request
from OpenSSL.crypto import dump_privatekey
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import PKey
from OpenSSL.crypto import TYPE_RSA
from OpenSSL.crypto import X509Req
from OpenSSL.crypto import X509Extension
import re

domain = input("CN: ")
org = input("Organization: ")
org_unit = input("Organizational Unit: ")
local = input("Locality: ")
state = input("State: ")
country = input("Country: ")
sans = input("SANs (ex. domain001.com,domain002.com) :")


def main():
    generate_key(TYPE_RSA, 2048)
    generate_csr()


def generate_key(type, bits):

    global key
    key = PKey()
    key.generate_key(type, bits)

    with open("private_key.key", "wb") as pkey:
        pkey.write(dump_privatekey(FILETYPE_PEM, key))

    return key


def generate_csr():

    req = X509Req()
    req.get_subject().CN = domain
    req.get_subject().O = org
    req.get_subject().OU = org_unit
    req.get_subject().L = local
    req.get_subject().ST = state
    req.get_subject().C = country

    if sans:
        altnames = str.encode(
                ", ".join([f"DNS: {san}" for san in sans.split(",")])
            )
        req.add_extensions([X509Extension(b"subjectAltName", False, altnames)])


    req.set_pubkey(key)
    req.sign(key, 'sha256')

    domain = re.sub(r'[*]',"wild",domain)

    with open(f"{domain}.csr", "wb") as csr_file:
        csr_file.write(dump_certificate_request(FILETYPE_PEM, req))


if __name__ == "__main__": main()