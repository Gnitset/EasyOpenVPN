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

	def exists(self):
		if c.execute("SELECT count(*) FROM users WHERE username = ?", (self.username,)).fetchall()[0][0] == 1:
			return True
		else:
			return False

	def create(self):
		c.execute("INSERT INTO users (username) VALUES (?)", (self.username,))
		conn.commit()

	def remove(self):
		c.execute("DELETE FROM network_map WHERE username = ?", (self.username,))
		c.execute("DELETE FROM users WHERE username = ?", (self.username,))
		conn.commit()

	def add_network(self, network):
		c.execute("INSERT INTO network_map (username, network) VALUES (?, ?)", (self.username, network))
		conn.commit()

	def remove_network(self, network):
		c.execute("DELETE FROM network_map WHERE username = ? AND network = ?", (self.username, network))
		conn.commit()

	def enable(self):
		c.execute("UPDATE users SET inactive = 0 WHERE username = ?", (self.username,))
		conn.commit()

	def disable(self):
		c.execute("UPDATE users SET inactive = 1 WHERE username = ?", (self.username,))
		conn.commit()

	def set_two_factor_id(self, two_factor_id):
		c.execute("UPDATE users SET two_factor_id = ? WHERE username = ?", (two_factor_id, self.username,))
		conn.commit()

	def get_maps(self):
		return c.execute("SELECT network FROM network_map WHERE username = ? ORDER BY network", (self.username,))

	def use_two_factor_auth(self):
		if c.execute("SELECT two_factor_id FROM users WHERE username = ?", (self.username,)).fetchall()[0][0]:
			return True
		else:
			return False

	def get_yubikey_identites(self):
		return zip(*c.execute("SELECT yubikey_identity FROM yubikeys WHERE username = ? AND inactive = 0", (self.username,)).fetchall())[0]

	def set_password(self):
		import bcrypt
		import getpass
		while True:
			password1 = getpass.getpass("Password: ")
			password2 = getpass.getpass("Password again: ")
			if password1 == password2:
				break
			else:
				print "Passwords didn't match, try again"
		hashed_password = bcrypt.hashpw(password1, bcrypt.gensalt())
		c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, self.username))
		conn.commit()

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


class Network(object):
	def __init__(self, network):
		assert network != None
		self.network = network

	def exists(self):
		if c.execute("SELECT count(*) FROM networks WHERE network = ?", (self.network,)).fetchall()[0][0] == 1:
			return True
		else:
			return False

	def create(self):
		c.execute("INSERT INTO networks (network) VALUES (?)", (self.network,))
		conn.commit()

	def remove(self):
		c.execute("DELETE FROM network_map WHERE network = ?", (self.network,))
		c.execute("DELETE FROM networks WHERE network = ?", (self.network,))
		conn.commit()

	def get_maps(self):
		return c.execute("SELECT network FROM network_map WHERE network = ? ORDER BY username", (self.network,))


class Manage(object):
	def __init__(self):
		import argparse
		parser = argparse.ArgumentParser(description='Manage the user/access-db for openvpn')
		mode = parser.add_mutually_exclusive_group()
		mode.add_argument('-a', '--add', action='store_true')
		mode.add_argument('-r', '--remove', action='store_true')
		mode.add_argument('-l', '--list', action='store_true')
		mode.add_argument('-e', '--enable', action='store_true')
		mode.add_argument('-d', '--disable', action='store_true')
		parser.add_argument('-m', '--map', action='store_true')
		parser.add_argument('--chpass', action='store_true')
		parser.add_argument('--initdb', action='store_true')
		parser.add_argument('-u', '--user', nargs='?', const=False)
		parser.add_argument('-n', '--network', nargs='?', const=False)
		parser.add_argument('-y', '--yubikey', nargs='?', const=False)
		args = parser.parse_args()

		if len(sys.argv) < 2:
			parser.print_help()
			sys.exit(1)

		if args.initdb:
			if Helpers.input("Really initialize db and remove all in it?", "y/N").lower() != 'y':
				sys.exit(1)
			else:
				print "OK, wiping DB"
				self.init_db()
				sys.exit(0)
		elif args.user:
			user = User(args.user)
			if args.add and not args.map and args.yubikey == None:
				if user.exists():
					print "User %s already exist" % user.username
					sys.exit(1)
				user.create()
				user.set_password()
			else:
				if not user.exists():
					print "User %s doesn't exist" % user.username
					sys.exit(1)
				elif args.yubikey or args.yubikey == '':
					user.set_two_factor_id(args.yubikey)
				elif args.chpass:
					user.set_password()
				elif args.enable:
					user.enable()
				elif args.disable:
					user.disable()
				elif args.map:
					if args.list:
						for (network,) in user.get_maps():
							print network
					elif args.network and args.add:
						user.add_network(args.network)
					elif args.network and args.remove:
						user.remove_network(args.network)
					else:
						print "Don't know how to map"
						sys.exit(1)
				elif args.remove: # and not args.map:
					user.remove()
				else:
					raise Exception("Should not happen (%s)", args)
		elif args.network:
			network = Network(args.network)
			if args.add and not args.map:
				if network.exists():
					print "Network %s already exist" % network.network
					sys.exit(1)
				network.create()
			else:
				if not network.exists():
					print "Network %s doesn't exist" % network.network
					sys.exit(1)
				elif args.map:
					if args.list:
						for (user,) in network.get_maps():
							print user
					else:
						print "Missing user argument, don't know how to map"
						sys.exit(1)
				elif args.remove: # and not args.map:
					network.remove()
				else:
					raise Exception("Should not happen (%s)", args)
		elif args.list:
			if args.user == False and args.network != False:
				self.list_all_users()
			elif args.user != False and args.network == False:
				self.list_all_networks()
			elif args.map:
				self.list_all_maps()
			elif args.yubikey == False:
				self.list_all_yubikey_servers()
			else:
				print "List what?"
				sys.exit(1)
		elif args.yubikey:
			if args.add:
				YubikeyOTP.add_server(args.yubikey)
			if args.remove:
				YubikeyOTP.remove_server(args.yubikey)
			if args.enable:
				YubikeyOTP.enable_server(args.yubikey)
			if args.disable:
				YubikeyOTP.disable_server(args.yubikey)
		else:
			raise Exception("Should not happen (%s)", args)
		sys.exit(0)

	def list_all_users(self):
		table = [("Username","Status","Yubikey identity")]
		for (user, status, two_factor_id) in c.execute("SELECT username, inactive, two_factor_id FROM users ORDER BY inactive, username"):
			if status == 0:
				table.append((user,"Active",two_factor_id))
			else:
				table.append((user,"Inactive",two_factor_id))
		Helpers.print_table(table)

	def list_all_networks(self):
		table = [("Network", "Description")]
		for (network, description) in c.execute("SELECT network, description FROM networks"):
			table.append((network, description))
		Helpers.print_table(table)

	def list_all_maps(self):
		table = [("Username", "Network")]
		for (username, network) in c.execute("SELECT username, network FROM network_map ORDER BY username, network"):
			table.append((username, network))
		Helpers.print_table(table)

	def list_all_yubikey_servers(self):
		table = [("Yubiserver", "Status")]
		for (yubiserver, status) in c.execute("SELECT yubiserver, inactive FROM yubiservers ORDER BY inactive, yubiserver"):
			if status == 0:
				table.append((yubiserver, "Active"))
			else:
				table.append((yubiserver, "Inactive"))
		Helpers.print_table(table)

	def init_db(self):
		c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, two_factor_id TEXT DEFAULT NULL, inactive INTEGER DEFAULT 0)")
		c.execute("CREATE TABLE IF NOT EXISTS networks (network TEXT PRIMARY KEY CHECK ( LIKE('%/%', network) ), description TEXT)")
		c.execute("CREATE TABLE IF NOT EXISTS network_map (username TEXT REFERENCES users(username), network TEXT REFERENCES networks(network), CONSTRAINT pk PRIMARY KEY (username, network))")
		c.execute("CREATE TABLE IF NOT EXISTS yubiserver_groups (yubiserver_group TEXT PRIMARY KEY)")
		c.execute("INSERT OR IGNORE INTO yubiserver_groups (yubiserver_group) VALUES ('default_group')")
		c.execute("CREATE TABLE IF NOT EXISTS yubiservers (yubiserver TEXT CHECK ( LIKE('http%://%/%', yubiserver) ), yubiserver_group TEXT REFERENCES yubiserver_groups(yubiserver_group) DEFAULT 'default_group', inactive INTEGER DEFAULT 0, CONSTRAINT pk PRIMARY KEY (yubiserver, yubiserver_group))")
		c.execute("CREATE TABLE IF NOT EXISTS yubikeys (yubikey_identity TEXT PRIMARY KEY, username TEXT REFERENCES users(username), yubiserver_group TEXT REFERENCES yubiserver_groups(yubiserver_group) DEFAULT 'default_group', inactive INTEGER DEFAULT 0)")
		conn.commit()


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


class YubikeyOTP(object):
	def __init__(self, otp):
		self.response = {}
		self.full_otp = otp
		self._identity = otp[:-32]
		self._otp = otp[-32:]
		self.acceptable_statuses = ("OK",)

	@staticmethod
	def add_server(server):
		c.execute("INSERT INTO yubiservers (yubiserver) VALUES (?)", (server,))
		conn.commit()

	@staticmethod
	def remove_server(server):
		c.execute("DELETE FROM yubiservers WHERE yubiserver = ?", (server,))
		conn.commit()

	@staticmethod
	def enable_server(server):
		c.execute("UPDATE yubiservers SET inactive = 0 WHERE yubiserver = ?", (server,))
		conn.commit()

	@staticmethod
	def disable_server(server):
		c.execute("UPDATE yubiservers SET inactive = 1 WHERE yubiserver = ?", (server,))
		conn.commit()

	def _request(self):
		import urllib
		if self.response:
			return
		url = c.execute("SELECT yubiserver FROM yubikeys JOIN yubiservers USING (yubiserver_group) WHERE yubikey_identity = ? AND yubiservers.inactive = 0 ORDER BY RANDOM() LIMIT 1", self._identity).fetchall()[0][0]
		for row in urllib.urlopen("%s?otp=%s" % (url, self.full_otp)):
			k,v = row.split("=",1)
			self.response[k.strip()] = v.strip()
		assert self.response["otp"] == self.full_otp

	def set_acceptable_status(self, acceptable_statuses):
		self._acceptable_statuses = acceptable_statuses

	def validate(self):
		self._request()
		if self.response["status"] in self._acceptable_statuses:
			return True
		else:
			return False


class IpTables(object):
	@staticmethod
	def _iptables(add_delete, ip, net):
		os.spawnv(os.P_WAIT, "/sbin/iptables", ["iptables", "-%s"%add_delete, "FORWARD", "-s", ip, "-d", net, "-j", "ACCEPT"])
		os.spawnv(os.P_WAIT, "/sbin/iptables", ["iptables", "-%s"%add_delete, "FORWARD", "-s", net, "-d", ip, "-j", "ACCEPT"])

	@classmethod
	def add(cls, ip, net):
		cls._iptables("A", ip, net)

	@classmethod
	def delete(cls, ip, net):
		cls._iptables("D", ip, net)


class Script(object):
	def __init__(self, script_type):
		getattr(self, "_%s" % script_type.replace("-", "_"))()

	def _user_pass_verify(self):
		user = User(os.environ['username'])
		input_password = os.environ['password']
		if user.use_two_factor_auth()
			if len(input_password) > 44:
				password_yk_identity = input_password[:-32]
				valid_yk_identities = set()
				for yk_identity in user.get_yubikey_identites():
					if user.validate_password(password_yk_identity[:-len(yk_identity)] and password_yk_identity.endswith(yk_identity):
						valid_yk_identities.add(yk_identity)
				assert len(valid_yk_identities) == 1
				yk_otp = "%s%s" % (valid_yk_identities.pop(), input_password[-32:])
				yv = YubikeyOTP(yk_otp)
				if yv.validate():
					sys.exit(0)
				else:
					sys.exit(1)
			else:
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
			c_conf=open(sys.argv[1], "a+")
			for network in networks:
				try:
					net,cidr = network[0].split("/",1)
					netmask = Helpers.netmask_from_cidr(cidr)
					c_conf.write('push "route %s %s"\n'%(net,netmask))
					IpTables.add(os.environ['ifconfig_pool_remote_ip'], network[0])
				except ValueError:
					continue
		sys.exit(0)

	def _client_disconnect(self):
		for network in c.execute('SELECT network FROM network_map WHERE username = ?', (os.environ['username'],)):
			IpTables.delete(os.environ['ifconfig_pool_remote_ip'], network[0])
		sys.exit(0)


class Helpers(object):
	def __init__(self):
		raise Exception("Only static methods here")

	@staticmethod
	def input(message, default_value):
		if default_value:
			return raw_input("%s [%s]: "%(message, default_value)) or default_value
		else:
			return raw_input("%s "%(message))

	@staticmethod
	def netmask_from_cidr(cidr):
		import socket, struct
		return socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - int(cidr))) & 0xffffffff))

	@staticmethod
	def print_table(table):
		max_width = {}
		for row in table:
			for cell, data in enumerate(row):
				if not data:
					continue
				data_len = len(data)
				try:
					if data_len > max_width[cell]:
						max_width[cell] = data_len
				except KeyError:
					max_width[cell] = data_len
		for row in table:
			for cell, data in enumerate(row):
				if data is None:
					data = ''
				print "|",data.ljust(max_width[cell]),
			print "|"

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
