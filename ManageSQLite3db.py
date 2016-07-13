#! /usr/bin/env python

# deps on python-bcrypt python-pysqlite2

import os
import sys
import sqlite3
from lib.Helpers import Helpers

try:
	from config import db_config
	db_file = db_config["db_file"]
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

	def get_maps(self):
		return c.execute("SELECT network FROM network_map WHERE username = ? ORDER BY network", (self.username,))

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
		parser.add_argument('-g', '--ga-secret', nargs='?', const=False)
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
			if args.add and not args.map and args.ga_secret == None:
				if user.exists():
					print "User %s already exist" % user.username
					sys.exit(1)
				user.create()
				user.set_password()
			else:
				if not user.exists():
					print "User %s doesn't exist" % user.username
					sys.exit(1)
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
			else:
				print "List what?"
				sys.exit(1)
		else:
			raise Exception("Should not happen (%s)", args)
		sys.exit(0)

	def list_all_users(self):
		table = [("Username","Status","2fa")]
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

	def init_db(self):
		c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, two_factor_id TEXT DEFAULT NULL, inactive INTEGER DEFAULT 0)")
		c.execute("CREATE TABLE IF NOT EXISTS networks (network TEXT PRIMARY KEY CHECK ( LIKE('%/%', network) ), description TEXT)")
		c.execute("CREATE TABLE IF NOT EXISTS network_map (username TEXT REFERENCES users(username), network TEXT REFERENCES networks(network), CONSTRAINT pk PRIMARY KEY (username, network))")
		c.execute("CREATE TABLE IF NOT EXISTS google_authenticator_secrets (google_authenticator_secret TEXT, username TEXT REFERENCES users(username), inactive INTEGER DEFAULT 0, CONSTRAINT pk PRIMARY KEY (google_authenticator_secret, username))")
		conn.commit()


if __name__ == "__main__":
	Helpers.connect_db(db_file)

	Manage()
