#! /usr/bin/env python

# Depends on python-bcrypt and python-pysqlite2

import bcrypt
import sqlite3

class SQLite3(object):
	def connect_db(self, db_file):
		self._conn = sqlite3.connect(db_file)
		self._c = self._conn.cursor()
		self._c.execute("PRAGMA foreign_keys = ON")
		self._conn.commit()

	def validate_user_password(self, user, password):
		password_hash = self._c.execute("SELECT password FROM users WHERE username = ? AND inactive = 0", (user,)).fetchall()[0][0].encode("utf-8")
		try:
			ga_otp_s = password[-6:]
			assert len(ga_otp_s) == 6
			ga_otp = int(ga_otp_s)
			ga = GoogleAuthenticator(ga_otp)
		else:
			ga = None
		if bcrypt.hashpw(password, password_hash) == password_hash:
			pw_status = True
		else:
			pw_status = False
		if not ga:
			return pw_status
		if not pw_status:
			ga.set_secret_key("FakeSecretKeyToPreventTimeingAttacks")
			ga.validate()
			return False
		ga_secret = self._c.execute("SELECT google_authenticator_secret FROM google_authenticator_secrets WHERE username = ?", (user,)).fetchall()[0][0]
		ga.set_secret_key(ga_secret)
		if ga.validate() and pw_status:
			return True
		else:
			return False

	def get_user_networks(self, user):
		ret = list()
		networks = self._c.execute("SELECT network FROM network_map WHERE username = ? AND inactive = 0", (user,)).fetchall()
		for network in networks:
			net,cidr = network.split("/",1)
			netmask = Helpers.netmask_from_cidr(cidr)
			ret.append((net, netmask))
		return ret


class GoogleAuthenticator(object):
	def __init__(self, otp):
		self.otp = otp

	def set_secret_key(self, secret_key):
		self._secret_key = secret_key
		return True

	def validate(self):
		"""Stolen from http://www.brool.com/post/using-google-authenticator-for-your-website/"""
		import time
		import struct
		import hmac
		import hashlib
		import base64

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


class Helpers(object):
	def __init__(self):
		raise Exception("Only static methods here")

	@staticmethod
	def netmask_from_cidr(cidr):
		import socket, struct
		return socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - int(cidr))) & 0xffffffff))


db = SQLite3()
