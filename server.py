#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import sys
import select

def encrypt(data):
    return data.encode("hex")

def decrypt(data):
    return data.decode("hex")

def robust_send(fd, data):
    sent = fd.send(data)
    while True:
        sent += fd.send(data[sent:])
        if sent >= len(data):
            return sent

def transfer(src_socket, dst_socket):
    fd_set = [src_socket, dst_socket]
    BUFFER_SIZE = 0x400
    while True:
        r, w, e = select.select(fd_set, [], [])
        if src_socket in r:
            data = decrypt(src_socket.recv(BUFFER_SIZE))
            if len(data) <= 0:
                break
            if robust_send(dst_socket, data) < len(data):
                return error(src_socket, "Send data size error!") or error(dst_socket, "Send data size error!")
        if dst_socket in r:
            data = dst_socket.recv(BUFFER_SIZE)
            if robust_send(src_socket, encrypt(data)) < len(data):
                return error(src_socket, "Send data size error!") or error(dst_socket, "Send data size error!")
            if len(data) <= 0:
                break
    return error(src_socket, "Receive data error, Breaking!") or error(dst_socket, "Receive data error, Breaking!")

def handle_socks5(connection_socket):
    address_type = connection_socket.recv(1)
    if address_type == "\x01":
        # IPv4
        target_host = socket.inet_ntoa(connection_socket.recv(4))
        print "[+] Client send target host(IPv4) : %s" % (target_host)
        socket_family = socket.AF_INET
    elif address_type == "\x03":
        # Domain name
        target_host = connection_socket.recv(ord(connection_socket.recv(1)))
        print "[+] Client send target host(Domain name) : %s" % (target_host)
        socket_family = socket.AF_INET
    elif address_type == "\x04":
        # IPv6
        target_host = socket.inet_ntoa(connection_socket.recv(16))
        print "[+] Client send target host(IPv6) : %s" % (target_host)
        socket_family = socket.AF_INET6
    else:
        return error(connection_socket, "Address type is not supported!")
    target_port = (ord(connection_socket.recv(1)) << 8) + ord(connection_socket.recv(1))
    print "[+] Client send target port : %s" % (target_port)
    print "[+] Connecting : %s:%d" % (target_host, target_port)
    target_socket = socket.socket(socket_family, socket.SOCK_STREAM)
    try:
        target_socket.connect((target_host, target_port))
    except Exception as e:
        return error(target_socket, str(e)) or error(connection_socket, str(e))
    transfer(connection_socket, target_socket)

def error(fd, msg):
    print "[-] %s" % (msg)
    try:
        fd.shutdown(socket.SHUT_RDWR)
        fd.close()
    except Exception as e:
        print "[-] Exception : %s" % (str(e))
    return False

def run(host, port):
    print "[+] Starting server at %s:%d" % (host, port)
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    listen_socket.bind((host, port))
    listen_socket.listen(0)
    read_fds = [listen_socket]
    write_fds = []
    error_fds = []
    while True:
        r, w, e = select.select(read_fds, write_fds,  error_fds)
        for i in r:
            if i == listen_socket:
                connection_socket, connection_address = listen_socket.accept()
                print "[+] Connected from %s:%d" % (connection_address[0], connection_address[1])
                handle_socks5(connection_socket)

def main():
    host = "0.0.0.0"
    port = 4444
    run(host, port)

if __name__ == "__main__":
    main()
