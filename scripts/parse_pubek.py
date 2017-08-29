#!/usr/bin/python3

# Copyright (C) 2017
# SUSE Linux GmbH
# Matthias Gerstner <matthias.gerstner@suse.com>

from __future__ import print_function
import os, sys
import argparse
import textwrap
import codecs

class PubKeyParser(object):

	def __init__(self):

		self.m_parser = argparse.ArgumentParser(
			description = "parses output from tpm_getpubek and performs operations with it"
		)

		self.m_parser.add_argument("file", type = str)
		self.m_parser.add_argument("-i", "--info", action = 'store_true')
		self.m_parser.add_argument("-o", "--out", action = 'store_true',
			help = "output the rsa key in the format given in -f")
		self.m_parser.add_argument("-f", "--format", type = str,
			default = "DER",
			help = "Format for output operations, DER (default) or PEM"
		)

	def run(self):

		self.m_args = self.m_parser.parse_args()

		if self.m_args.file != "-":
			_file = open(self.m_args.file, 'r')
		else:
			_file = sys.stdin

		self.m_text = _file.read()

		self.parse()

		if self.m_args.info:
			self.printInfo()
		elif self.m_args.out:
			out_format = self.getOutFormat()
			key = self.createKey(out_format)
			print(key.decode())

	def parse(self):
		"""Parses the unstructured format output by tpm_getpubek."""

		modulus = ""

		modulus_found = False

		for line in self.m_text.splitlines():

			line = line.strip()

			if line.find(":") != -1:

				key, val = line.split(':')
				key = key.lower()

				if key == "key size":
					self.m_size = int(val.split()[0])
					continue
				elif key == "public key exponent":
					self.m_exponent = int(val, 16)
					continue
				elif key == "algorithm":
					self.m_algorithm = val.split()[1].strip('()')
				elif key == "public key modulus":
					modulus_found = True
					continue

				modulus_found = False
				continue

			elif modulus_found:

				line = line.replace(' ', '')
				modulus += line

		self.m_modulus = codecs.decode(modulus, 'hex')

		if len(self.m_modulus) != int(self.m_size / 8):
			raise Exception("Modulus length is not {} bits".format(self.m_size))

	def printInfo(self):
		hexdump = codecs.encode(self.m_modulus, "hex").decode()
		print(self.m_algorithm, "Key of size:", self.m_size)
		print("Modulus:")
		print('\t', '\n\t'.join(textwrap.wrap(hexdump)), sep = '')
		print("Exponent:",
			self.m_exponent,
			"({})".format(hex(self.m_exponent))
		)

	def getOutFormat(self):

		form = self.m_args.format.upper()

		if form in ("DER", "PEM"):
			return form

		raise Exception("Unsupported out format {}".format(form))

	def createKey(self, form):

		import Crypto.PublicKey.RSA as RSA

		# XXX is this the correct byte order?
		modulus = int.from_bytes(self.m_modulus, byteorder = "big")

		key = RSA.construct( (modulus, self.m_exponent) )

		return key.exportKey(form)

parser = PubKeyParser()
parser.run()
