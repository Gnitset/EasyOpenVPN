#! /usr/bin/env python

import os

from string import Template
from socket import gethostname as socket_gethostname
from openvpn_script import Helpers

def get_parameters():
	parameters=dict()

	parameters['script_path'] = Helpers.input("Installation path", os.path.dirname(os.path.realpath(__file__)))
	parameters['vpn_server_host'] = Helpers.input("Domain or IP for vpn server", socket_gethostname())
	parameters['vpn_server_port'] = Helpers.input("Port for the vpn server", 1194)
	parameters['client_network_address'] = Helpers.input("Network address for client network", '10.31.8.0')
	parameters['client_network_netmask'] = Helpers.input("Netmask for client network", '255.255.255.0')
	parameters['cipher'] = Helpers.input("Encryption cipher for the vpn", 'AES-256-CBC')

	parameters['ca_certificate'] = open(Helpers.input("Filename for CA-certificate", "HOSTNAME.crt")).read().strip()
	parameters['server_certificate'] =  open(Helpers.input("Filename for server certificate", "HOSTNAME.crt")).read().strip()
	parameters['server_key'] = open(Helpers.input("Filename for server certificate key file", "HOSTNAME.key")).read().strip()
	parameters['ta_key'] = open(Helpers.input("Filename for tls-auth key", "ta.key")).read().strip()
	parameters['dhparam'] = open(Helpers.input("Filename for Diffie-Hellman key", "dh2048.pem")).read().strip()

	return parameters

def read_templates(**templates):
	ret = dict()

	for conf,filename in templates.iteritems():
		ret[conf] = Template(open(filename).read())

	return ret

def write_generated_configs(templates, parameters):
	for conf,template in templates.iteritems():
		open("%s-generated.conf"%conf, "w+").write(template.substitute(parameters))

if __name__ == "__main__":
	parameters = get_parameters()

	templates = read_templates(server="configs/server.conf", client="configs/client.conf")

	write_generated_configs(templates, parameters)

	open("config.py", "w").write("""db_file = "%s/access.sqlite3"\n""" % parameters['script_path'])
