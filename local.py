#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 一个简单的 Socks5 代理服务器 , 只有 server 端 , 而且代码比较乱
# 不是很稳定 , 而且使用多线程并不是 select 模型
# Author : WangYihang <wangyihanger@gmail.com>


import socket
import threading
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080

def encrypt(data):
    return data.encode("hex")

def decrypt(data):
    return data.decode("hex")

def handle(buffer):
    return buffer

def transfer(src, dst, direction):
    src_name = src.getsockname()
    src_address = src_name[0]
    src_port = src_name[1]
    dst_name = dst.getsockname()
    dst_address = dst_name[0]
    dst_port = dst_name[1]
    print("[+] Starting transfer [%s:%d] => [%s:%d]" % (src_name, src_port, dst_name, dst_port))
    while True:
        buffer = src.recv(0x1000)
        # print("[+] Buffer: %s" %  (repr(buffer)))
        if not buffer:
            print("[-] No data received! Breaking...")
            break
        if direction:
            buffer = encrypt(buffer)
            print("[+] %s:%d => %s:%d => Length : [%s]" % (src_address, src_port, dst_address, dst_port, repr(buffer)))
        else:
            buffer = decrypt(buffer)
            print("[+] %s:%d <= %s:%d => Length : [%s]" % (src_address, src_port, dst_address, dst_port, repr(buffer)))
        # print("[+] %s:%d => %s:%d [%s]" % (src_address, src_port, dst_address, dst_port, repr(buffer)))
        dst.send(handle(buffer))
    print("[+] Closing connecions! [%s:%d]" % (src_address, src_port))
    src.close()
    print("[+] Closing connecions! [%s:%d]" % (dst_address, dst_port))
    dst.close()


SOCKS_VERSION = 5

ERROR_VERSION = "[-] Client version error!"
ERROR_METHOD = "[-] Client method error!"

# ALLOWED_METHOD = [0, 2]
ALLOWED_METHOD = [0]

def socks_selection(connection_socket):
    client_version = ord(connection_socket.recv(1))
    print("[+] client version : %d" % (client_version))
    if not client_version == SOCKS_VERSION:
        connection_socket.shutdown(socket.SHUT_RDWR)
        connection_socket.close()
        return (False, ERROR_VERSION)
    support_method_number = ord(connection_socket.recv(1))
    print("[+] Client Supported method number : %d" % (support_method_number))
    support_methods = []
    for i in range(support_method_number):
        method = ord(connection_socket.recv(1))
        print("[+] Client Method : %d" % (method))
        support_methods.append(method)
    selected_method = None
    for method in ALLOWED_METHOD:
        if method in support_methods:
            selected_method = 0
    if selected_method == None:
        connection_socket.shutdown(socket.SHUT_RDWR)
        connection_socket.close()
        return (False, ERROR_METHOD)
    print("[+] Server select method : %d" % (selected_method))
    response = chr(SOCKS_VERSION) + chr(selected_method)
    connection_socket.send(response)
    return (True, connection_socket)


CONNECT = 1
BIND = 2
UDP_ASSOCIATE = 3

IPV4 = 1
DOMAINNAME = 3
IPV6 = 4

CONNECT_SUCCESS = 0

ERROR_ATYPE = "[-] Client address error!"

RSV = 0
BNDADDR = "\x00" * 4
BNDPORT = "\x00" * 2

def socks_request(local_socket):
    data_to_send = ""
    client_version = ord(local_socket.recv(1))
    data_to_send += chr(client_version)
    data_to_send += "\x01\x00" # auth method number ; noauth request
    data_to_send += chr(client_version)
    print("[+] client version : %d" % (client_version))
    if not client_version == SOCKS_VERSION:
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_VERSION)
    cmd = ord(local_socket.recv(1))
    data_to_send += chr(cmd)
    if cmd == CONNECT:
        print("[+] CONNECT request from client")
        rsv  = ord(local_socket.recv(1))
        data_to_send += chr(rsv)
        if rsv != 0:
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, ERROR_RSV)
        atype = ord(local_socket.recv(1))
        data_to_send += chr(atype)
        if atype == IPV4:
            dst_address = local_socket.recv(4)
            data_to_send += dst_address
            dst_address = ("".join(["%d." % (ord(i)) for i in dst_address]))[0:-1]
            print("[+] IPv4 : %s" % (dst_address))
            dst_port = local_socket.recv(2)
            data_to_send += dst_port
            dst_port = ord(dst_port[0]) * 0x100 + ord(dst_port[1])
            print("[+] Port : %s" % (dst_port))
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                print("[+] Connecting : %s:%s" % (dst_address, dst_port))
                remote_socket.connect((SERVER_HOST, SERVER_PORT))
                response = ""
                response += chr(SOCKS_VERSION)
                response += chr(CONNECT_SUCCESS)
                response += chr(RSV)
                response += chr(IPV4)
                response += BNDADDR
                response += BNDPORT
                local_socket.send(response)
                remote_socket.send(data_to_send)
                remote_socket.recv(2)
                remote_socket.recv(10)
                print("[+] Tunnel connected! Tranfering data...")
                s = threading.Thread(target=transfer, args=(
                    remote_socket, local_socket, False))
                s.start()
                r = threading.Thread(target=transfer, args=(
                    local_socket, remote_socket, True))
                r.start()
                return (True, (local_socket, remote_socket))
            except socket.error as e:
                print(e)
                remote_socket.shutdown(socket.SHUT_RDWR)
                remote_socket.close()
                local_socket.shutdown(socket.SHUT_RDWR)
                local_socket.close()
        elif atype == DOMAINNAME:
            domainname_length = ord(local_socket.recv(1))
            data_to_send += chr(domainname_length)
            domainname = ""
            for i in range(domainname_length):
                domainname += (local_socket.recv(1))
            data_to_send += domainname
            print("[+] Domain name : %s" % (domainname))
            dst_port = local_socket.recv(2)
            data_to_send += dst_port
            dst_port = ord(dst_port[0]) * 0x100 + ord(dst_port[1])
            print("[+] Port : %s" % (dst_port))
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                print("[+] Connecting : %s:%s" % (domainname, dst_port))
                remote_socket.connect((domainname, dst_port))
                response = ""
                response += chr(SOCKS_VERSION)
                response += chr(CONNECT_SUCCESS)
                response += chr(RSV)
                response += chr(IPV4)
                response += BNDADDR
                response += BNDPORT
                local_socket.send(response)
                print("[+] Tunnel connected! Tranfering data...")
                s = threading.Thread(target=transfer, args=(
                    remote_socket, local_socket, False))
                s.start()
                r = threading.Thread(target=transfer, args=(
                    local_socket, remote_socket, True))
                r.start()
                return (True, (local_socket, remote_socket))
            except socket.error as e:
                print(e)
                remote_socket.shutdown(socket.SHUT_RDWR)
                remote_socket.close()
                local_socket.shutdown(socket.SHUT_RDWR)
                local_socket.close()
        elif atype == IPV6:
            dst_address = int(local_socket.recv(4).encode("hex"), 16)
            print("[+] IPv6 : %x" % (dst_address))
            dst_port = local_socket.recv(2)
            data_to_send += dst_port
            dst_port = ord(dst_port[0]) * 0x100 + ord(dst_port[1])
            print("[+] Port : %s" % (dst_port))
            remote_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            remote_socket.connect((dst_address, dst_port))
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, ERROR_ATYPE)
        else:
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, ERROR_ATYPE)
    elif cmd == BIND:
        # TODO
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_CMD)
    elif cmd == UDP_ASSOCIATE:
        # TODO
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_CMD)
    else:
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, ERROR_CMD)
    return (True, local_socket)

def server(local_host, local_port, max_connection):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((local_host, local_port))
        server_socket.listen(max_connection)
        print('[+] Server started [%s:%d]' % (local_host, local_port))
        while True:
            local_socket, local_address = server_socket.accept()
            print('[+] Detect connection from [%s:%s]' % (local_address[0], local_address[1]))
            result = socks_selection(local_socket)
            if not result[0]:
                print("[-] socks selection error!")
                break
            result = socks_request(result[1])
            if not result[0]:
                print("[-] socks request error!")
                break
            # local_socket, remote_socket = result[1]
            # TODO : loop all socket to close...
        print("[+] Releasing resources...")
        local_socket.close()
        print("[+] Closing server...")
        server_socket.close()
        print("[+] Server shuted down!")
    except  KeyboardInterrupt:
        print(' Ctl-C stop server')
        try:
            remote_socket.close()
        except:
            pass
        try:
            local_socket.close()
        except:
            pass
        try:
            server_socket.close()
        except:
            pass
        return


def main():
    if len(sys.argv) != 3:
        print("Usage : ")
        print("\tpython %s [L_HOST] [L_PORT]" % (sys.argv[0]))
        print("Example : ")
        print("\tpython %s 127.0.0.1 1080" % (sys.argv[0]))
        print("Author : ")
        print("\tWangYihang <wangyihanger@gmail.com>")
        exit(1)
    LOCAL_HOST = sys.argv[1]
    LOCAL_PORT = int(sys.argv[2])
    #REMOTE_HOST = sys.argv[3]
    #REMOTE_PORT = int(sys.argv[4])
    MAX_CONNECTION = 0x10
    server(LOCAL_HOST, LOCAL_PORT, MAX_CONNECTION)


if __name__ == "__main__":
    main()
