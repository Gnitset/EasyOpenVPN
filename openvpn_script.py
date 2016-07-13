#! /usr/bin/env python

import os
import sys

try:
	from config import db, db_config
	db.connect_db(**db_config)
except ImportError:
	from db.sqlite3 import db
	db.connect_db(db_file = "access.sqlite3")


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
		if db.validate_user_password(os.environ["username"], os.environ["password"]):
			sys.exit(0)
		else:
			sys.exit(1)

	def _client_connect(self):
		networks = db.get_user_networks(os.environ["username"])
		if networks:
			if os.geteuid() == 0 and os.path.isfile("/sbin/iptables"):
				firewall = IpTables
			elif os.geteuid() == 0 and os.path.isfile("/sbin/pfctl"):
				firewall = PacketFilter
			else:
				firewall = DummyFirewall
			fw = firewall(os.environ['ifconfig_pool_remote_ip'])
			c_conf=open(sys.argv[1], "a+")
			for (network, netmask) in networks:
				try:
					c_conf.write("push \"route %s %s\"\n" % (network, netmask))
					fw.add_rule(os.environ["ifconfig_pool_remote_ip"], "%s/%s" %
						(network, sum([bin(int(x)).count('1') for x in netmask.split('.')])))
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


if __name__ == "__main__":
	if os.environ.has_key('script_type'):
		Script(os.environ['script_type'])
	else:
		print "Not called from openvpn"

	sys.exit(1)
