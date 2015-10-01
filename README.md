EasyOpenVPN
===========

A set of scripts and configs to easily set up [openvpn](https://openvpn.net/) with basic user/password autentication.

### Prerequisites

- python2
- python-bcrypt
- python-pysqlite2
- openvpn
- openssl

### Getting started

Generate certificate for the vpn server, can optionally be used as CA.
```sh
$ openssl req -x509 -nodes -days 1825 -newkey rsa:2048 -keyout HOSTNAME.key -out HOSTNAME.crt
```

Generate openvpn tls-auth key
```sh
$ openvpn --genkey --secret ta.key
```

Generate Diffie-Hellman key
```sh
$ openssl dhparam -out dh2048.pem 2048
```

Generate vpn configs
```sh
$ python ./generate_configs.py
```

Start openvpn
```sh
$ sudo openvpn --config server-generated.conf
```
