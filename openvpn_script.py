#! /usr/bin/env python

# deps on python-bcrypt python-pysqlite2

import os
import sys
import sqlite3

try:
	from config import db_file
except ImportError:
	db_file = 'access.sqlite3'


class User(object):
	def __init__(self, username):
		assert username != None
		self.username = username

	def use_two_factor_auth(self):
		if c.execute("SELECT two_factor_id FROM users WHERE username = ?", (self.username,)).fetchall()[0][0]:
			return True
		else:
			return False

	def get_google_authenticator_secrets(self):
		return zip(*c.execute("SELECT google_authenticator_secret FROM google_authenticator_secrets WHERE username = ? AND inactive = 0", (self.username,)).fetchall())[0]

	def validate_password(self, password, only_if_active = True):
		import bcrypt
		if only_if_active:
			password_hash = c.execute('SELECT password FROM users WHERE username = ? AND inactive = 0', (self.username,)).fetchall()[0][0].encode('utf-8')
		else:
			password_hash = c.execute('SELECT password FROM users WHERE username = ?', (self.username,)).fetchall()[0][0].encode('utf-8')
		if bcrypt.hashpw(password, password_hash) == password_hash:
			return True
		else:
			return False


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


class DummyFirewall(object):
	def __init__(self, namespace):
		self._namespace = namespace
		self._rules = list()

	def add_rule(self, ip, net):
		self._rules.append((ip, net))

	def delete_rule(self, ip, net):
		try:
			self._rules.remove((ip, net))
		except ValueError:
			pass

	def commit(self):
		pass

	@staticmethod
	def delete_namespace(namespace):
		pass


class PacketFilter(DummyFirewall):
	def commit(self):
		import subprocess
		pfctl = subprocess.Popen(["pfctl", "-a", "easyopenvpn/%s" % self._namespace, "-f", "-"], executable="/sbin/pfctl", stdin=subprocess.PIPE)
		for ip, net in self._rules:
			pfctl.stdin.write("pass from %s to %s\n" % (ip, net))
			pfctl.stdin.write("pass from %s to %s\n" % (net, ip))
		pfctl.stdin.close()
		pfctl.wait()

	@staticmethod
	def delete_namespace(namespace):
		os.spawnv(os.P_WAIT, "/sbin/pfctl", ["pfctl", "-a", "easyopenvpn/%s" % namespace, "-F", "rules"])


class IpTables(DummyFirewall):
	def commit(self):
		self._iptables(["-N", self._namespace])
		for ip, net in self._rules:
			self._iptables(["-A", ip, "-s", ip, "-d", net, "-j", "ACCEPT"])
			self._iptables(["-A", ip, "-s", net, "-d", ip, "-j", "ACCEPT"])
		self._iptables(["-A", "FORWARD", "-j", self._namespace])

	@staticmethod
	def _iptables(args):
		os.spawnv(os.P_WAIT, "/sbin/iptables", ["iptables"] + args)

	@classmethod
	def delete_namespace(cls, namespace):
		cls._iptables(["-D", "FORWARD", "-j", namespace])
		cls._iptables(["-F", namespace])
		cls._iptables(["-X", namespace])


class Script(object):
	def __init__(self, script_type):
		getattr(self, "_%s" % script_type.replace("-", "_"))()

	def _user_pass_verify(self):
		user = User(os.environ['username'])
		input_password = os.environ['password']
		if user.use_two_factor_auth():
			try:
				ga_otp_s = input_password[-6:]
				assert len(ga_otp_s) == 6
				ga_otp = int(ga_otp_s)
				ga = GoogleAuthenticator(ga_otp)
				valid_ga_secrets = set()
				for secret in user.get_google_authenticator_secrets():
					if user.validate_password(input_password[:-6]) and ga.set_secret_key(secret) and ga.validate():
						valid_ga_secrets.add(secret)
				if len(valid_ga_secrets) == 1:
					sys.exit(0)
				else:
					sys.exit(1)
			except ValueError, ve:
				sys.exit(1)
		else:
			password = os.environ['password']
			if user.validate_password(password):
				sys.exit(0)
			else:
				sys.exit(1)

	def _client_connect(self):
		networks = c.execute('SELECT network FROM network_map WHERE username = ?', (os.environ['username'],)).fetchall()
		if networks:
			if os.geteuid() == 0 and os.path.isfile("/sbin/iptables"):
				firewall = IpTables
			elif os.geteuid() == 0 and os.path.isfile("/sbin/pfctl"):
				firewall = PacketFilter
			else:
				firewall = DummyFirewall
			fw = firewall(os.environ['ifconfig_pool_remote_ip'])
			c_conf=open(sys.argv[1], "a+")
			for network in networks:
				try:
					net,cidr = network[0].split("/",1)
					netmask = Helpers.netmask_from_cidr(cidr)
					c_conf.write('push "route %s %s"\n'%(net,netmask))
					fw.add_rule(os.environ['ifconfig_pool_remote_ip'], network[0])
				except ValueError:
					continue
			fw.commit()
		sys.exit(0)

	def _client_disconnect(self):
		if os.geteuid() == 0 and os.path.isfile("/sbin/iptables"):
			firewall = IpTables
		elif os.geteuid() == 0 and os.path.isfile("/sbin/pfctl"):
			firewall = PacketFilter
		else:
			firewall = DummyFirewall
		firewall.delete_namespace(os.environ['ifconfig_pool_remote_ip'])
		sys.exit(0)


class Helpers(object):
	def __init__(self):
		raise Exception("Only static methods here")

	@staticmethod
	def netmask_from_cidr(cidr):
		import socket, struct
		return socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - int(cidr))) & 0xffffffff))

	@staticmethod
	def connect_db(db_file):
		global conn, c
		conn = sqlite3.connect(db_file)
		c = conn.cursor()
		c.execute("PRAGMA foreign_keys = ON")
		conn.commit()


if __name__ == "__main__":
	Helpers.connect_db(db_file)

	if os.environ.has_key('script_type'):
		Script(os.environ['script_type'])
	else:
		Manage()

	sys.exit(1)
