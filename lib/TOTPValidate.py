#! /usr/bin/env python

import time
import struct
import hmac
import hashlib
import base64


class TOTPValidate(object):
	def __init__(self, otp):
		self.otp = otp

	def set_secret_key(self, secret_key):
		self._secret_key = secret_key
		return True

	def validate(self):
		"""Stolen from http://www.brool.com/post/using-google-authenticator-for-your-website/"""

		tm = int(time.time() / 30)
		secret_key = base64.b32decode(self._secret_key)
		# try 30 seconds behind and ahead as well
		for ix in [0, -1, 1]:
			# convert timestamp to raw bytes
			b = struct.pack(">q", tm + ix)

			# generate HMAC-SHA1 from timestamp based on secret key
			hm = hmac.HMAC(secret_key, b, hashlib.sha1).digest()

			# extract 4 bytes from digest based on LSB
			offset = ord(hm[-1]) & 0x0F
			truncatedHash = hm[offset:offset+4]

			# get the code from it
			code = struct.unpack(">L", truncatedHash)[0]
			code &= 0x7FFFFFFF;
			code %= 1000000;

			if ("%06d" % code) == str(self.otp):
				return True
		return False
