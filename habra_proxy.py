#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

import socket
from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler

import http.client
from urllib.parse import urlparse
import gzip
import zlib

import threading
import select
from io import BytesIO

PROXY_IP = '127.0.0.1'
PROXY_PORT = 8888
TIMEOUT = 7
ALLOWED_ENCODINGS = {'identity', 'gzip', 'x-gzip', 'deflate'}
ZIP_DECODERS = {'gzip', 'x-gzip'}
HTTP_ver = "HTTP/1.1"
HTTP_VERSIONS = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
IGNORED_HOP_BY_HOP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
                              'transfer-encoding', 'upgrade'}  # http://tools.ietf.org/html/rfc2616#section-13.5.1
BLOCK_LENGTH = 4096

ALLOWED_URLS = ['habrastorage.org', 'habrahabr.ru', 'hsto.org', 'habracdn.net']


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True


class ProxyRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.tread_value = threading.local()
        self.tread_value.connections = {}
        super(ProxyRequestHandler, self).__init__(*args, **kwargs)

    def destination_url_is_not_allowed(self, full_url_to_check: "str") -> "bool":
        for pattern in ALLOWED_URLS:
            if pattern in full_url_to_check:
                return False
        self.send_error(403)
        # print("Method: {} blocked URL: {}".format(self.command, full_url_to_check))
        return True

    def do_CONNECT(self):
        incoming_request = self
        url_and_port = incoming_request.path.split(':', 1)
        url_and_port[1] = int(url_and_port[1]) or 443  # use port 443 - https protocol

        if incoming_request.destination_url_is_not_allowed(url_and_port[0]):
            return None

        try:
            outgoing_connection = socket.create_connection(url_and_port, timeout=TIMEOUT)
        except socket.error:
            incoming_request.send_error(502)
            return None
        else:
            incoming_request.send_response(200, 'OK')
            incoming_request.end_headers()
        paired_connections = [incoming_request.connection, outgoing_connection]
        connection_is_open = True
        while connection_is_open:
            readable_sockets, writable_sockets, exceptions = select.select(paired_connections, [], paired_connections,
                                                                           TIMEOUT)
            if exceptions or (not readable_sockets):
                break
            for in_socket in readable_sockets:
                out_socket = paired_connections[1] if in_socket is paired_connections[0] else paired_connections[0]
                data = in_socket.recv(BLOCK_LENGTH)
                if data:
                    out_socket.sendall(data)
                else:
                    connection_is_open = False

    def do_GET(self):
        get_request = self
        parsed_url = urlparse(get_request.path)
        scheme, netloc, path = parsed_url.scheme, parsed_url.netloc, parsed_url.path

        if get_request.destination_url_is_not_allowed(netloc):
            return None

        if netloc:
            get_request.headers['Host'] = netloc
        setattr(get_request, 'headers', get_request.filter_headers(get_request.headers))
        get_origin = (scheme, netloc)
        try:
            if get_origin not in get_request.tread_value.connections:
                if scheme == 'https':
                    get_request.tread_value.connections[get_origin] = http.client.HTTPSConnection(netloc,
                                                                                                  timeout=TIMEOUT)
                elif scheme == 'http':
                    get_request.tread_value.connections[get_origin] = http.client.HTTPConnection(netloc,
                                                                                                 timeout=TIMEOUT)
                else:
                    print("GET - unsupported scheme:", scheme)
                    get_request.send_error(403)
                    return None
            out_connection = get_request.tread_value.connections[get_origin]
            out_connection.request("GET", path, body=None, headers=dict(get_request.headers))
            response = out_connection.getresponse()
            setattr(response, 'headers', response.msg)
            setattr(response, 'response_version', HTTP_VERSIONS[response.version])
            response_body = response.read()
        except socket.error:
            if get_origin in get_request.tread_value.connections:
                del get_request.tread_value.connections[get_origin]
            get_request.send_error(502)
            return None

        content_encoding = response.headers.get('Content-Encoding', 'identity')
        decoded_response_body = get_request.decode_content_body(response_body, content_encoding)
        response.headers['Content-Length'] = str(len(response_body))
        setattr(response, 'headers', get_request.filter_headers(response.headers))
        get_request.wfile.write(
            "{} {} {}\r\n".format(get_request.protocol_version, response.status, response.reason).encode())

        for header in response.headers:
            get_request.wfile.write(header.encode())
        get_request.wfile.write(b'\r\n\r\n')
        get_request.wfile.write(decoded_response_body)
        get_request.wfile.flush()

    @staticmethod
    def filter_headers(headers):
        for header in IGNORED_HOP_BY_HOP_HEADERS:
            del headers[header]
        if 'Accept-Encoding' in headers:  # accept only supported encodings
            filtered_encodings = [encoding for encoding in re.split(r',\s*', headers['Accept-Encoding'])
                                  if encoding in ALLOWED_ENCODINGS]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)
        return headers

    @staticmethod
    def encode_content_body(text_to_encode, encoding):
        if encoding == 'identity':
            encoded_data = text_to_encode
        elif encoding in ZIP_DECODERS:
            bytes_stream = BytesIO()
            with gzip.GzipFile(fileobj=bytes_stream, mode='wb') as io:
                io.write(text_to_encode)
            encoded_data = bytes_stream.getvalue()
        elif encoding == 'deflate':
            encoded_data = zlib.compress(text_to_encode)
        else:
            raise Exception("unsupported content-encoding: {}".format(encoding))
        return encoded_data

    @staticmethod
    def decode_content_body(encoded_data, encoding):
        if encoding == 'identity':
            decoded_text = encoded_data
        elif encoding in ZIP_DECODERS:
            bytes_stream = BytesIO(encoded_data)
            with gzip.GzipFile(fileobj=bytes_stream) as io:
                decoded_text = io.read()
        elif encoding == 'deflate':
            try:
                decoded_text = zlib.decompress(encoded_data)
            except zlib.error:
                decoded_text = zlib.decompress(encoded_data, -zlib.MAX_WBITS)
        else:
            raise Exception("unsupported content-encoding: {}".format(encoding))
        return decoded_text


def proxy_server(handler_class=ProxyRequestHandler, server_class=ThreadingHTTPServer):
    server_address = (PROXY_IP, PROXY_PORT)
    handler_class.protocol_version = HTTP_ver
    proxy_handler = server_class(server_address, handler_class)
    socket_address = proxy_handler.socket.getsockname()
    print("Habra HTTP proxy server is running on {}:{}".format(socket_address[0], socket_address[1]))
    proxy_handler.serve_forever()


if __name__ == '__main__':
    proxy_server()
