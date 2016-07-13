#! /usr/bin/env python

import os

from string import Template


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
	def netmask_from_cidr(cidr):
		import socket, struct
		return socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - int(cidr))) & 0xffffffff))

	@staticmethod
	def cidr_from_netmask(netmask):
		return sum([bin(int(x)).count('1') for x in netmask.split('.')])

	@staticmethod
	def connect_db(db_file):
		global conn, c
		conn = sqlite3.connect(db_file)
		c = conn.cursor()
		c.execute("PRAGMA foreign_keys = ON")
		conn.commit()
