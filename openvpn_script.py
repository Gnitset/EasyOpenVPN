#! /usr/bin/env python

# deps on python-bcrypt python-pysqlite2

import os
import sys
import sqlite3

#db_file = '/etc/openvpn/access.sqlite3'
db_file = 'access.sqlite3'

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
		parser.add_argument('-u', '--user', nargs='?', const=None)
		parser.add_argument('-n', '--network', nargs='?', const=None)
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
		elif args.chpass:
			self.update_password(args.user)
			print "Password changed"
			sys.exit(0)

		if args.list and not args.map:
			if args.user == None:
				self.list_users()
			if args.network == None:
				self.list_networks()
		elif args.list and args.map:
			self.list_maps()

		if args.add:
			if args.user and not args.network:
				self.add_user(args.user)
				self.update_password(args.user)
			elif args.network and not args.user:
				self.add_network(args.network)
			elif args.map and args.user and args.network:
				self.add_map(args.user, args.network)
			else:
				print "Add users and networks one at the time or add a map"
		elif args.remove:
			if args.user and not args.network:
				self.remove_user(args.user, password)
			elif args.network and not args.user:
				self.remove_network(args.network)
			elif args.map and args.user and args.network:
				self.remove_map(args.user, args.network)
			else:
				print "Remove users or networks one at the time or remove a map"
		elif args.enable:
			if args.user:
				self.enable_user(args.user)
			else:
				print "Please specify user to enable"
		elif args.disable:
			if args.user:
				self.disable_user(args.user)
			else:
				print "Please specify user to disable"

	def add_user(self, user):
		c.execute("INSERT INTO users (username) VALUES (?)", (user,))
		conn.commit()

	def remove_user(self, user,password):
		c.execute("DELETE FROM network_map WHERE username = ?", (user,))
		c.execute("DELETE FROM users WHERE username = ?", (user,))
		conn.commit()

	def list_users(self):
		for (user, status) in c.execute("SELECT username, inactive FROM users"):
			if status == 0:
				print "%s\tACTIVE"%user
			else:
				print "%s\tInactive"%user

	def add_network(self, network):
		c.execute("INSERT INTO networks (network) VALUES (?)", (network,))
		conn.commit()

	def remove_network(self, network):
		c.execute("DELETE FROM network_map WHERE network = ?", (network,))
		c.execute("DELETE FROM networks WHERE network = ?", (network,))
		conn.commit()

	def list_networks(self):
		for (network, description) in c.execute("SELECT network, description FROM networks"):
			print "%s\t%s"%(network, description)

	def add_map(self, user, network):
		c.execute("INSERT INTO network_map (username, network) VALUES (?, ?)", (user, network))
		conn.commit()

	def remove_map(self, user, network):
		c.execute("DELETE FROM network_map WHERE username = ? AND network = ?", (user, network))
		conn.commit()

	def list_maps(self):
		for (username, network) in c.execute("SELECT username, network FROM network_map ORDER BY username, network"):
			print "%s\t%s"%(username, network)

	def enable_user(self, user):
		c.execute("UPDATE users SET inactive = 0 WHERE username = ?", (user,))
		conn.commit()

	def disable_user(self, user):
		c.execute("UPDATE users SET inactive = 1 WHERE username = ?", (user,))
		conn.commit()

	def init_db(self):
		c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, two_factor_id TEXT DEFAULT NULL, inactive INTEGER DEFAULT 0)")
		c.execute("CREATE TABLE IF NOT EXISTS networks (network TEXT PRIMARY KEY CHECK ( LIKE('%/%', network) ), description TEXT)")
		c.execute("CREATE TABLE IF NOT EXISTS network_map (username TEXT REFERENCES users(username), network TEXT REFERENCES networks(network), CONSTRAINT pk PRIMARY KEY (username, network))")
		conn.commit()

	def update_password(self, user):
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
		c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, user))
		conn.commit()


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
		getattr(self, "_%s"%script_type)()

	def _user_pass_verify(self):
		import bcrypt
		user = os.environ['username']
		password = os.environ['password']
		password_hash = c.execute('SELECT password FROM users WHERE username = ? AND inactive = 0', (user,)).fetchall()[0][0]
		if bcrypt.hashpw(password, password_hash) == password_hash:
			sys.exit(0)
		else:
			sys.exit(1)

	def _client_connect(self):
		networks = c.execute('SELECT network FROM network_map WHERE username = ?', (os.environ['username'],)).fetchall()
		if networks:
			import socket, struct
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

	if not os.environ.has_key('script_type'):
		Manage()
		sys.exit(1)
	else:
		Script(os.environ['script_type'])

	sys.exit(1)
