#! /usr/bin/env python

# Depends on python-ldap

import ldap


class ActiveDirectory(object):
	def connect_db(self, server, domain, search_base, access_group, access_group_totp, ad_user, ad_password):
		self._domain = domain
		self._search_base = search_base
		self._access_group = access_group
		self._access_group_totp = access_group_totp
		self._user = ad_user
		self._password = ad_password

		self._ad = ldap.open(server)
		self._ad.set_option(ldap.OPT_REFERRALS, 0)

	def validate_user_password(self, user, password):
		assert password # Actually requre a password since AD accepts simple bind without it
		self._ad_bind()
		user_groups = self._ad_lookup(user)["memberOf"]
		if self._access_group_totp in user_groups:
			totp_secret = password[-6:]
			assert len(totp_secret) == 6
			int(totp_secret)
			ga = GoogleAuthenticator(totp_secret)
			try:
				self._ad_bind(user, password[:-6])
			except ldap.INVALID_CREDENTIALS:
				return False
			ad_obj = self._ad_lookup(user)
			totp_status = 0
			for totpsecret in ad_obj["totpsecret"]:
				ga.set_secret_key(totpsecret)
				if ga.validate(): totp_status+=1
			return totp_status > 0
		elif self._access_group in user_groups:
			try:
				self._ad_bind(user, password)
				return True
			except ldap.INVALID_CREDENTIALS:
				return False
		else:
			return False

	def get_user_networks(self, user):
		self._ad_bind()
		ad_obj = self._ad_lookup(user)
		ret = list()
		for network_data in ad_obj["msRADIUSFramedRoute"]:
			network, _ = network_data.split(" ", 1)
			net, cidr = network.split("/",1)
			netmask = Helpers.netmask_from_cidr(cidr)
			ret.append((net, netmask))
		return ret

	def _ad_bind(self, user=None, password=None, domain=None):
		if not user: user = self._user
		if not password: password = self._password
		if not domain: domain = self._domain
		self._ad.bind_s("%s@%s" % (user, domain), password, ldap.AUTH_SIMPLE)

	def _ad_lookup(self, user):
		return self._ad.search_s(self._search_base, ldap.SCOPE_SUBTREE,
			"(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))" % user)[0][1]


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


db = ActiveDirectory()
