#! /usr/bin/env python

from string import Template

parameters=dict()

parameters['vpn_server_host'] = 'vpn.example.com'
parameters['vpn_server_port'] = 1194
parameters['client_network_address'] = '10.31.8.0'
parameters['client_network_netmask'] = '255.255.255.0'
parameters['ca_certificate'] = open("HOSTNAME.crt").read().strip()
parameters['server_certificate'] =  open("HOSTNAME.crt").read().strip()
parameters['server_key'] = open("HOSTNAME.key").read().strip()
parameters['ta_key'] = open("ta.key").read().strip()
parameters['dhparam'] = open("dh2048.pem").read().strip()
parameters['cipher'] = 'AES-256-CBC'
parameters['script_path'] = '/opt/EasyOpenVPN'

server_config_template = Template(open("configs/server.conf").read())
client_config_template = Template(open("configs/client.ovpn").read())

open("server-generated.conf", "w+").write(server_config_template.substitute(parameters))
open("client-generated.conf", "w+").write(client_config_template.substitute(parameters))
