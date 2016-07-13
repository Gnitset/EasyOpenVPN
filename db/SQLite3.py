#! /usr/bin/env python

# Depends on python-bcrypt and python-pysqlite2

import bcrypt
import sqlite3
from lib.Helpers import Helpers
from lib.TOTPValidate import TOTPValidate

class SQLite3(object):
	def connect_db(self, db_file):
		self._conn = sqlite3.connect(db_file)
		self._c = self._conn.cursor()
		self._c.execute("PRAGMA foreign_keys = ON")
		self._conn.commit()

	def validate_user_password(self, user, password):
		db_result = self._c.execute("SELECT password, totp_secret FROM users
			LEFT JOIN totp_secrets USING (username)
			WHERE username = ? AND inactive = 0", (user,)).fetchall()
		if len(db_result) == 0:
			return False
		password_hash = db_result[0][0].encode("utf-8")
		elif db_result[0][1]:
			totp_secret = password[-6:]
			assert len(totp_secret) == 6
			try:
				int(totp_secret)
			ValueError:
				return False
			totp = TOTPValidate(totp_secret)
			if bcrypt.hashpw(password[:-6], password_hash) != password_hash:
				return False
			totp_status = 0
			for (_,totpsecret) in db_result:
				totp.set_secret_key(totpsecret)
				if totp.validate(): totp_status+=1
			return totp_status > 0
		else:
			if bcrypt.hashpw(password[:-6], password_hash) == password_hash:
				return True
		return False

	def get_user_networks(self, user):
		ret = list()
		networks = self._c.execute("SELECT network FROM network_map WHERE username = ? AND inactive = 0", (user,)).fetchall()
		for network in networks:
			net,cidr = network.split("/",1)
			netmask = Helpers.netmask_from_cidr(cidr)
			ret.append((net, netmask))
		return ret


db = SQLite3()
