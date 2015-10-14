#! /usr/bin/env python

# deps on python-bcrypt python-pysqlite2

import os
import sys
import sqlite3
import BaseHTTPServer
import cgi
import base64

import openvpn_script
Helpers = openvpn_script.Helpers

try:
	from config import db_file
except ImportError:
	db_file = "access.sqlite3"
try:
	from config import static_files_path
except ImportError:
	static_files_path = "static"
try:
	from config import vpn_network_netmask, vpn_network_address
except ImportError:
	vpn_network_netmask = "255.255.255.0"
	vpn_network_address = "10.31.8.0"


def public_method(original_function):
	original_function.public = True
	return original_function


class WebUIRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_GET(self):
		if self.authenticate():
			self.path_lookup()

	def do_POST(self):
		if self.authenticate():
			ctype, pdict = cgi.parse_header(self.headers.getheader("content-type"))
			if ctype == "multipart/form-data":
				self._postvars = cgi.parse_multipart(self.rfile, pdict)
			elif ctype == "application/x-www-form-urlencoded":
				length = int(self.headers.getheader("content-length"))
				self._postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
			else:
				self._postvars = {}
			self.path_lookup()

	def authenticate(self):
		if self.headers.getheader("Authorization"):
			username, password = base64.b64decode(self.headers.getheader("Authorization")[len("Basic "):]).split(":", 1)
			user = openvpn_script.User(username)
			if user.exists() and user.validate_password(password):
				self.user = user
				if Helpers.net_from_ip_and_mask(self.client_address[0], vpn_network_netmask) == vpn_network_address:
					self.connection_source = "vpn"
				else:
					self.connection_source = "internet"
				return True
		self.send_response(401)
		self.send_header("WWW-Authenticate", "Basic realm='EasyOpenVPN Web interface'")
		self.send_header("Content-type", "text/html")
		self.end_headers()
		self.wfile.write("not authenticated\n")
		return False

	def get_menu(self):
		menu = list()
		if self.connection_source == "vpn":
			menu.append(("/chpass", "Change password"))
		if self.user.is_admin():
			menu.append(("/admin", "Admin"))
		menu.append(("/config", "Download client config file"))
		return menu

	def path_lookup(self):
		exploded_path = filter(len, self.path.split("/"))
		if not exploded_path:
			exploded_path.append("index")
		try:
			path_method = getattr(self, "path_%s" % exploded_path[0])
		except AttributeError:
			path_method = self.path_404
		if path_method.public:
			path_method(exploded_path[1:])

	@public_method
	def path_404(self, sub_path):
		self.send_response(404)
		self.send_header("Content-type", "text/plain")
		self.end_headers()
		self.wfile.write("404; PATH %s not found\n" % self.path)

	@public_method
	def path_index(self, sub_path):
		self.send_response(200)
		self.send_header("Content-type", "text/html")
		self.end_headers()
		self.wfile.write("""<html><head><title>EasyOpenVPN Web interface</title></head><body>
<h2>EasyOpenVPN Web interface</h2>
<ul>""")
		for link, text in self.get_menu():
			self.wfile.write("""<li><a href="%s">%s</a>""" % (link, text))
		self.wfile.write("""</ul>
</body></html>""")

	@public_method
	def path_static(self, sub_path):
		file_path = "%s/%s" % (static_files_path, "/".join(sub_path))
		if ".." in file_path or not os.path.isfile(file_path):
			print file_path
			self.path_404(sub_path)
			return
		self.send_response(200)
		mime_types = { ".jpg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".css": "text/css" }
		files_sufix = file_path[-4:]
		self.send_header("Content-type", mime_types[files_sufix])
		self.end_headers()
		self.wfile.write(open(file_path).read())

	@public_method
	def path_rdr(self, sub_path=list()):
		self.send_response(301)
		self.send_header("Location", "/%s" % "/".join(sub_path))
		self.end_headers()
		self.wfile.write("Redirecting...\n")

	@public_method
	def path_config(self, sub_path):
		self.send_response(200)
		self.send_header("Content-type", "application/octet-stream")
		self.send_header("Content-Disposition:", "attachment; filename=client_vpn.ovpn")
		self.end_headers()
		self.wfile.write(open("client-generated.conf").read())

	@public_method
	def path_chpass(self, sub_path):
		if self.connection_source == 'vpn':
			if self.command == "GET":
				self.send_response(200)
				self.send_header("Content-type", "text/html")
				self.end_headers()
				self.wfile.write("""<html><head><title>EasyOpenVPN Web interface</title></head><body>
<h2>EasyOpenVPN Web interface</h2>
<form method=post>
<input type=password name=password1>
<input type=password name=password2>
<input type=submit value="Change Password">
</form>
</body></html>""")
			elif self.command == "POST" and self._postvars:
				if self._postvars['password1'][0] == self._postvars['password2'][0]:
					self.user.set_password(self._postvars['password1'][0])
				self.send_response(200)
				self.send_header("Content-type", "text/html")
				self.end_headers()
				self.wfile.write("""<html><head><title>EasyOpenVPN Web interface</title></head><body>
<h2>EasyOpenVPN Web interface</h2>
<h3>changed password</h3>
<form method=post>
<input type=password name=password1>
<input type=password name=password2>
<input type=submit value="Change Password">
</form>
</body></html>""")
		else:
			self.send_response(403)
			self.send_header("Content-type", "text/plain")
			self.end_headers()
			self.wfile.write("403; You are not connected over the VPN, please try again while connected.\n")

	@public_method
	def path_admin(self, sub_path):
		if self.user.is_admin():
			wa = WebAdmin(self, sub_path)
		else:
			self.send_response(403)
			self.send_header("Content-type", "text/plain")
			self.end_headers()
			self.wfile.write("403; You are not admin.\n")


class WebAdmin(object):
	def __init__(self, request_handler, path):
		self._request_handler = request_handler
		self.path = path
		self._request_handler.send_response(200)


if __name__ == "__main__":
	Helpers.connect_db(db_file)

	httpd = BaseHTTPServer.HTTPServer(("", 8000), WebUIRequestHandler)
	httpd.serve_forever()

# User access
#  Change password
#  Download config file
#  Link to client
# Admin access
#  Create/enable/disable/remove user
#  Change user password
#  Change user access
#  Add networks

# /static
# /login
# /logout
# /configs/
# /user/chpass
