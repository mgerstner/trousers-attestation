#!/usr/bin/python3

# Copyright (C) 2017
# SUSE Linux GmbH
# Matthias Gerstner <matthias.gerstner@suse.com>

from __future__ import print_function
import os, sys
import argparse
import binascii
try:
	import rsa
except ImportError:
	print("rsa module required, try 'pip install --user rsa")
	raise

class VerifyQuote(object):

	def __init__(self):
		self.m_parser = argparse.ArgumentParser(
			description = "Verify a TPM quote"
		)

		self.m_parser.add_argument(
			"-k", "--key", type = str,
			help = "path to a standard PEM file containing a 2048 bit RSA public key to verify the signature with",
			required = True
		)

		self.m_parser.add_argument(
			"-m", "--message", type = str,
			help = "path to a file containing the message to check, in hexascii",
			required = True
		)

		self.m_parser.add_argument(
			"-s",  "--signature", type = str,
			help = "path to a file containing the signature to verify, in hexascii",
			required = True
		)

	def run(self):

		self.m_args = self.m_parser.parse_args()

		self.m_msg_hex = open(self.m_args.message, 'r').read().replace(' ', '').replace('\n', '').strip()
		self.m_msg_bin = binascii.unhexlify(self.m_msg_hex)

		self.m_sig_hex = open(self.m_args.signature, 'r').read().replace(' ', '').replace('\n', '').strip()
		self.m_sig_bin = binascii.unhexlify(self.m_sig_hex)

		key = rsa.PublicKey.load_pkcs1_openssl_pem(
			open(self.m_args.key, 'rb').read()
		)

		try:
			good_sig = rsa.verify(self.m_msg_bin, self.m_sig_bin, key)
		except rsa.pkcs1.VerificationError:
			good_sig = False

		if good_sig:
			print("Good signature in", self.m_args.signature, "for", self.m_args.message)
		else:
			print("Signature verification failed")

verifier = VerifyQuote()
verifier.run()
