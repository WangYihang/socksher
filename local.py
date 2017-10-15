#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import sys
import select

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080


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
            data = src_socket.recv(BUFFER_SIZE)
            if len(data) <= 0:
                break
            if robust_send(dst_socket, encrypt(data)) < len(data):
                return error(src_socket, "Send data size error!") or error(dst_socket, "Send data size error!")
        if dst_socket in r:
            data = decrypt(dst_socket.recv(BUFFER_SIZE))
            if robust_send(src_socket, data) < len(data):
                return error(src_socket, "Send data size error!") or error(dst_socket, "Send data size error!")
            if len(data) <= 0:
                break
    return error(src_socket, "Receive data error, Breaking!") or error(dst_socket, "Receive data error, Breaking!")


def handle_socks5(connection_socket):
    server_supported_auth_methods = ["\x00"]
    server_socks_version = "\x05"
    # 1. HELO and Select Auth method
    # send version
    client_socks_version = connection_socket.recv(1)
    print "[+] Client socks version : %d" % (ord(client_socks_version))
    if not client_socks_version == server_socks_version:
        return error(connection_socket, "Socks protrol version is not supported!")
    auth_method = None
    client_supported_auth_methods = []
    for i in range(ord(connection_socket.recv(1))):
        client_supported_auth_methods.append(connection_socket.recv(1))
    for client_supported_auth_method in client_supported_auth_methods:
        if client_supported_auth_method in server_supported_auth_methods:
            auth_method = client_supported_auth_method
            print "[+] Selected auth method : %d" % (ord(auth_method))
            break
    if auth_method == None:
        return error(connection_socket, "Auth method is not supported!")
    connection_socket.send(server_socks_version + auth_method)
    # 2. Select cmd
    server_supported_cmd = ["\x01"]
    # \x01 => CONNECT
    # \x02 => BIND
    # \x03 => UDP_ASSOCIATE
    # send version
    client_socks_version = connection_socket.recv(1)
    if not client_socks_version == server_socks_version:
        return error(connection_socket, "Socks protrol version is not supported!")
    client_command = connection_socket.recv(1)
    if client_command in server_supported_cmd:
        command = client_command
        print "[+] Client command : %d => CONNECT" % (ord(command))
    else:
        return error(connection_socket, "Command is not supported!")
    reserve = connection_socket.recv(1)
    if reserve != "\x00":
        return error(connection_socket, "Reserve is not equals to '\\x00'!")
    address_type = connection_socket.recv(1)
    target_info = address_type
    if address_type == "\x01":
        # IPv4
        target_host = connection_socket.recv(4)
        target_info += target_host
        target_host = socket.inet_ntoa(target_host)
        print "[+] Client send target host(IPv4) : %s" % (target_host)
        socket_family = socket.AF_INET
    elif address_type == "\x03":
        # Domain name
        target_host = connection_socket.recv(ord(connection_socket.recv(1)))
        target_info += chr(len(target_host)) + target_host
        print "[+] Client send target host(Domain name) : %s" % (target_host)
        socket_family = socket.AF_INET
    elif address_type == "\x04":
        # IPv6
        target_host = connection_socket.recv(16)
        target_info += target_host
        target_host = socket.inet_ntoa(target_host)
        print "[+] Client send target host(IPv6) : %s" % (target_host)
        socket_family = socket.AF_INET6
    else:
        return error(connection_socket, "Address type is not supported!")
    target_port = connection_socket.recv(2)
    target_info += target_port
    target_port = (ord(target_port[0]) << 8) + ord(target_port[1])
    print "[+] Client send target port : %s" % (target_port)
    target_socket = socket.socket(socket_family, socket.SOCK_STREAM)
    # print "[+] Connecting : %s:%d" % (target_host, target_port)
    try:
        # target_socket.connect((target_host, target_port))
        print "[+] Trying to connect to server : %s:%d" % (SERVER_HOST, SERVER_PORT)
        target_socket.connect((SERVER_HOST, SERVER_PORT))
        print "[+] Connected!"
    except Exception as e:
        return error(target_socket, str(e)) or error(connection_socket, str(e))
    msg_to_client = ""
    msg_to_client += server_socks_version
    msg_to_client += "\x00"  # Connect success
    msg_to_client += "\x00"  # Reserve
    msg_to_client += address_type
    if address_type == "\x04":
        msg_to_client += "\x00" * 6
        msg_to_client += "\x00" * 2
    else:
        msg_to_client += "\x00" * 4
        msg_to_client += "\x00" * 2
    print "[+] Sending data to client..."
    connection_socket.send(msg_to_client)
    print "[+] Info to send to server : %s" % (repr(target_info))
    target_socket.send(target_info)
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
        r, w, e = select.select(read_fds, write_fds, error_fds)
        for i in r:
            if i == listen_socket:
                connection_socket, connection_address = listen_socket.accept()
                print "[+] Connected from %s:%d" % (connection_address[0], connection_address[1])
                handle_socks5(connection_socket)

def main():
    host = "127.0.0.1"
    port = 1080
    run(host, port)


if __name__ == "__main__":
    main()
