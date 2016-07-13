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
		password_hash = self._c.execute("SELECT password FROM users WHERE username = ? AND inactive = 0", (user,)).fetchall()[0][0].encode("utf-8")
		try:
			ga_otp_s = password[-6:]
			assert len(ga_otp_s) == 6
			ga_otp = int(ga_otp_s)
			ga = TOTPValidate(ga_otp)
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


db = SQLite3()
