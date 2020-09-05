#!/usr/bin/env python3

"""
    torxy - Rules-based transparent HTTP/HTTPS proxy for the TOR server.
    It allows you to access the chosen sites via TOR.

    Copyright (C) 2020 Vadim Kuznetsov <vimusov@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
from argparse import ArgumentParser
from asyncio import (
    CancelledError,
    IncompleteReadError,
    StreamReader,
    StreamWriter,
    TimeoutError as AsyncTimeoutError,  # Conflicts with `TimeoutError' inherited from `OSError'.
    ensure_future,
    gather,
    get_event_loop,
    open_connection,
    start_server,
    wait_for,
)
from dataclasses import dataclass
from errno import EAFNOSUPPORT, EHOSTDOWN, EHOSTUNREACH, ENETUNREACH, EPFNOSUPPORT
from ipaddress import AddressValueError, IPv4Address
from os import _exit, getenv
from pathlib import Path
from signal import SIGHUP, SIGINT, SIGTERM
from socket import EAI_AGAIN, SOL_IP, gaierror
from struct import unpack, calcsize
from typing import Dict, Tuple, Union

from dpkt.ssl import TLS, TLSClientHello, TLSHandshake
from systemd.daemon import notify
from systemd.journal import JournalHandler

log = logging.getLogger(__name__)

IO_TIMEOUT = 5 * 60  # Send/receive timeout, seconds.
CONNECT_TIMEOUT = 5 * 60  # Connect timeout, seconds.
SOCKS_SERVER_STATUSES = {
    0x01: 'General failure',
    0x02: 'Connection not allowed by ruleset',
    0x03: 'Network unreachable',
    0x04: 'Host unreachable',
    0x05: 'Connection refused by destination host',
    0x06: 'TTL expired',
    0x07: 'Command not supported / protocol error',
    0x08: 'Address type not supported',
}
HTTP_HEADERS_SEPARATOR = b'\r\n'


class HttpProtocolError(Exception):
    pass


class TlsProtocolError(Exception):
    pass


class SocksProtocolError(Exception):
    pass


class InvalidClientAddress(Exception):
    pass


@dataclass(frozen=True)
class DstAddress:
    ip: str
    port: int

    def __str__(self) -> str:
        return f'{self.ip}:{self.port}'

    def as_dict(self) -> Dict[str, Union[int, str]]:
        return dict(host=self.ip, port=self.port)


@dataclass(frozen=True)
class SocksServer:
    host: str
    port: int

    def __str__(self) -> str:
        return f'{self.host}:{self.port}'

    @classmethod
    def from_address(cls, address: str):
        host, port = address.split(':')
        return cls(host=host, port=port)

    def as_dict(self) -> Dict[str, Union[int, str]]:
        return dict(host=self.host, port=self.port)


class RedirectRules:
    def __init__(self, file_path: Path):
        self.__rules = set()
        self.__file_path = file_path
        self.reload()

    def reload(self):
        rules = set()
        for line in self.__file_path.read_text().splitlines():
            rule = line.strip().lower()
            if not rule:
                continue
            if rule.startswith('#'):
                continue
            rules.add(rule)
        self.__rules = rules
        log.info('Loaded %d rules from %r.', rules, str(self.__file_path))

    def redirect_to_socks(self, host: str) -> bool:
        host = host.lower()
        for rule in self.__rules:
            if rule in host:
                log.debug('Host %r matched with rule %r.', host, rule)
                return True
        return False


class TorxyServer:
    def __init__(self, listen_on: str, rules: RedirectRules, socks_server: SocksServer):
        ip, port = listen_on.split(':')
        self.__ip = ip
        self.__port = int(port)
        self.__rules = rules
        self.__socks_server = socks_server
        self.__server = None

    async def start(self):
        if self.__server is not None:
            raise RuntimeError('Server has been started already:')
        self.__server = await start_server(self.__process_request, host=self.__ip, port=self.__port)

    async def stop(self):
        server = self.__server
        if server is not None:
            self.__server = None
            server.close()
            await server.wait_closed()

    async def __process_request(self, reader: StreamReader, writer: StreamWriter):
        try:
            dst_address = self.__get_dst_address(writer)
        except InvalidClientAddress as error:
            log.debug('Error %r occurred getting client address.', str(error))
            writer.transport.abort()
            return
        except Exception as error:
            log.exception('Unexpected error %r occurred getting client information.', str(error))
            return
        log.debug('Got destination address %s.', dst_address)
        try:
            first_chunk = await wait_for(reader.read(n=1), IO_TIMEOUT)
            log.debug('First chunk %r.', first_chunk)
            if first_chunk == b'\x16':
                await self.__process_https(dst_address, first_chunk, reader, writer)
            elif first_chunk.isalpha():
                await self.__process_http(first_chunk, reader, writer)
            else:
                log.debug('Unknown protocol, first chunk %r.', first_chunk)
                await self.__process_unknown(dst_address, first_chunk, reader, writer)
        except CancelledError:
            log.debug('Task has been cancelled.')
            writer.transport.abort()
            raise
        except (AsyncTimeoutError, TimeoutError):
            log.debug('Timeout for request is over.')
            writer.transport.abort()
        except (BrokenPipeError, ConnectionResetError, IncompleteReadError):
            log.debug('Connection has been closed unexpectedly.')
            writer.transport.abort()
        except (OSError, gaierror) as error:
            if error.errno in (EAFNOSUPPORT, EPFNOSUPPORT):
                log.debug('Unsupported protocol family.')
            elif error.errno in (EAI_AGAIN, EHOSTDOWN, EHOSTUNREACH, ENETUNREACH):
                log.debug('Network or host is temporary unavailable.')
            else:
                log.exception('Unexpected OS error occurred processing request.')
            writer.transport.abort()
        except Exception:
            log.exception('Unexpected error occurred processing request.')
            writer.transport.abort()
        finally:
            writer.close()

    @staticmethod
    def __get_dst_address(writer: StreamWriter) -> DstAddress:
        peer = writer.get_extra_info('peername')
        if isinstance(peer, (tuple, list)):
            client_ip, unused = peer
        else:
            client_ip = peer
        if client_ip is None:
            raise InvalidClientAddress('Unable to determine client IP:')

        sock = writer.get_extra_info('socket')
        addr_info = sock.getsockopt(SOL_IP, 80, 16)  # 80 = SO_ORIGINAL_DST - `linux/netfilter_ipv4.h'.
        port, addr = unpack('!H4s', addr_info[2:8])
        ip = str(IPv4Address(addr))

        if client_ip == ip:
            raise InvalidClientAddress(f'Client IP {client_ip!r} matches with destination address:')
        return DstAddress(ip=ip, port=port)

    @staticmethod
    async def __pump_traffic(up_reader: StreamReader, up_writer: StreamWriter, down_reader: StreamReader, down_writer: StreamWriter, *first_chunks):
        async def upstream_channel():
            log.debug('Starting upstream channel.')
            while True:
                log.debug('Waiting for data from client.')
                data = await wait_for(down_reader.read(n=65536), IO_TIMEOUT)
                log.debug('Got %r[...] from client.', data[:16])
                if not data:
                    log.debug('No more data from client.')
                    up_writer.close()
                    break
                log.debug('Sending data to upstream.')
                up_writer.write(data)
                await wait_for(up_writer.drain(), IO_TIMEOUT)

        async def downstream_channel():
            log.debug('Starting downstream channel.')
            while True:
                log.debug('Waiting for data from upstream.')
                data = await wait_for(up_reader.read(n=65536), IO_TIMEOUT)
                log.debug('Got %r[...] from upstream.', data[:16])
                if not data:
                    log.debug('No more data from upstream.')
                    break
                log.debug('Sending data to client.')
                down_writer.write(data)
                await wait_for(down_writer.drain(), IO_TIMEOUT)

        log.debug('Sending first chunks.')
        for chunk in first_chunks:
            up_writer.write(chunk)
        await wait_for(up_writer.drain(), IO_TIMEOUT)

        log.debug('Start pumping traffic.')
        await gather(upstream_channel(), downstream_channel())

        log.debug('Client connection has been processed.')

    async def __connect_socks_server(self, host: str, port: int) -> Tuple[StreamReader, StreamWriter]:
        host = host[:255].encode('ascii')
        fields = [
            # Authentication packet.
            b'\x05',  # Version 5.
            b'\x01',  # Client Authentication Methods count.
            b'\x00',  # No authentication.
            # Request packet.
            b'\x05',  # Version 5.
            b'\x01',  # Command: Connect.
            b'\x00',  # Reserved.
        ]
        try:
            ip = IPv4Address(host)
        except (AddressValueError, TypeError, ValueError):
            fields.extend([
                b'\x03',  # Address type: Domain name.
                len(host).to_bytes(1, 'big', signed=False),
                host,
            ])
        else:
            fields.extend([
                b'\x01',  # Address type: IPv4.
                int(ip).to_bytes(4, 'big', signed=False),
            ])
        fields.extend([
            port.to_bytes(2, 'big', signed=False),
        ])
        request = b''.join(fields)

        log.debug('Sending request %r[...] to SOCKS server %s.', request[:32], self.__socks_server)
        reader, writer = await wait_for(open_connection(**self.__socks_server.as_dict()), CONNECT_TIMEOUT)
        writer.write(request)
        await wait_for(writer.drain(), IO_TIMEOUT)

        auth_result = await wait_for(reader.read(n=2), IO_TIMEOUT)
        log.debug('Got authentication response %r[...] from SOCKS server.', auth_result[:32])
        if auth_result != b'\x05\x00':
            raise SocksProtocolError(f'Authentication failed on SOCKS server:')

        response = await wait_for(reader.read(n=1024), IO_TIMEOUT)
        log.debug('Got response %r[...] from SOCKS server.', response[:32])
        version, status = unpack('BB', response[0:2])
        if version != 5:
            raise SocksProtocolError(f'Unsupported SOCKS version {version!r}:')
        if status:
            raise SocksProtocolError('SOCKS server returned status %r:' % SOCKS_SERVER_STATUSES.get(status, 'Unknown error'))

        log.debug('Connection to SOCKS server established.')
        return reader, writer

    async def __process_http(self, first_chunk: bytes, down_reader: StreamReader, down_writer: StreamWriter):
        request = await wait_for(down_reader.readuntil(separator=HTTP_HEADERS_SEPARATOR), IO_TIMEOUT)
        headers = []
        host, port = None, 80
        while True:
            line = await wait_for(down_reader.readuntil(separator=HTTP_HEADERS_SEPARATOR), IO_TIMEOUT)
            headers.append(line)
            if line == HTTP_HEADERS_SEPARATOR:
                log.debug('End of HTTP headers.')
                break
            log.debug('Got HTTP header line %r[...].', line[:32])
            key, value = line.split(b':', maxsplit=1)
            if key.lower() != b'host':
                continue
            address = value.strip().decode('ascii')
            if ':' in address:
                host, port = address.split(':', maxsplit=1)
                port = int(port)
            else:
                host = address

        if host is None:
            raise HttpProtocolError('Unable to find Host header in HTTP headers:')
        log.debug('Got HTTP host %r and port %d.', host, port)

        if self.__rules.redirect_to_socks(host):
            log.debug('Redirecting HTTP host %r@%d to SOCKS.', host, port)
            up_reader, up_writer = await self.__connect_socks_server(host, port)
        else:
            log.debug('Processing HTTP host %r@%d as is.', host, port)
            up_reader, up_writer = await wait_for(open_connection(host=host, port=port), CONNECT_TIMEOUT)

        await self.__pump_traffic(up_reader, up_writer, down_reader, down_writer, first_chunk, request, b''.join(headers))

    @staticmethod
    async def __get_server_name_indication(tls_payload: bytes) -> str:
        tls = TLS(tls_payload)
        if len(tls.records) != 1:
            raise TlsProtocolError('Invalid amount of TLS records:')
        handshake = TLSHandshake(tls.records[0].data)
        client_hello: TLSClientHello = handshake.data

        for ext_type, ext_data in client_hello.extensions:
            if ext_type == 0:  # SNI
                break
        else:
            raise TlsProtocolError('SNI is not found:')
        ext_len = len(ext_data) - 2

        common_hdr_fmt = '!HB'
        common_hdr_size = calcsize(common_hdr_fmt)
        common_hdr_len, host_type = unpack(common_hdr_fmt, ext_data[0:common_hdr_size])
        if common_hdr_len != ext_len:
            raise TlsProtocolError(f'Invalid common header length, got {common_hdr_len}, expected {ext_len}:')
        if host_type != 0:  # host_name
            raise TlsProtocolError(f'Unsupported name type {host_type}:')

        offset = common_hdr_size
        host_hdr_fmt = '!H'
        host_hdr_size = calcsize(host_hdr_fmt)
        (host_hdr_len,) = unpack(host_hdr_fmt, ext_data[offset:offset + host_hdr_size])
        if host_hdr_len != common_hdr_len - common_hdr_size:
            raise TlsProtocolError(f'Invalid name header length, got {host_hdr_len}, expected {common_hdr_len - common_hdr_size}:')
        offset += host_hdr_size

        host = ext_data[offset:offset + host_hdr_len]
        return host.decode('ascii')

    async def __process_https(self, dst_address: DstAddress, first_chunk: bytes, down_reader: StreamReader, down_writer: StreamWriter):
        request = await wait_for(down_reader.read(n=65535), IO_TIMEOUT)

        async def fallback():
            up_reader, up_writer = await wait_for(open_connection(**dst_address.as_dict()), CONNECT_TIMEOUT)
            await self.__pump_traffic(up_reader, up_writer, down_reader, down_writer, first_chunk, request)

        try:
            host = await self.__get_server_name_indication(first_chunk + request)
        except TlsProtocolError as error:
            log.debug('TLS error %r occurred connecting to %s, falling back to direct pumping traffic.', str(error), dst_address)
            await fallback()
            return
        except Exception:
            log.exception('Unexpected error occurred in TLS request to %s, falling back to pumping traffic.', dst_address)
            await fallback()
            return

        log.debug('Got HTTPS host %r.', host)

        if self.__rules.redirect_to_socks(host):
            log.debug('Redirecting HTTPS host %r@%d to SOCKS server.', host, dst_address.port)
            up_reader, up_writer = await self.__connect_socks_server(host, dst_address.port)
        else:
            log.debug('Processing HTTPS host %r as is (connecting to %s:%d).', host, host, dst_address.port)
            up_reader, up_writer = await wait_for(open_connection(host=host, port=dst_address.port), CONNECT_TIMEOUT)

        await self.__pump_traffic(up_reader, up_writer, down_reader, down_writer, first_chunk, request)

    async def __process_unknown(self, dst_address: DstAddress, first_chunk: bytes, down_reader: StreamReader, down_writer: StreamWriter):
        log.debug('Processing unknown TCP-based protocol to %s.', dst_address)
        up_reader, up_writer = await wait_for(open_connection(**dst_address.as_dict()), CONNECT_TIMEOUT)
        await self.__pump_traffic(up_reader, up_writer, down_reader, down_writer, first_chunk)


def main():
    default_listen_on = '169.254.254.254:3128'
    default_socks_server = '127.0.0.1:9050'
    default_rules_path = '/etc/torxy.rules'

    parser = ArgumentParser(prog='torxy', description='Rules-based transparent HTTP/HTTPS proxy for the TOR server.')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode.')
    parser.add_argument('-D', '--log-to-stderr', action='store_true', help='Write logs to the standard error stream.')
    parser.add_argument('-l', '--listen-on', default=default_listen_on, help=f'Listen on the address ({default_listen_on!r} by default).')
    parser.add_argument('-s', '--socks-server', default=default_socks_server, help=f'SOCKS server address ({default_socks_server} by default).')
    parser.add_argument('-r', '--rules-path', default=default_rules_path, type=Path, help=f'Path to rules config ({default_rules_path} by default).')
    args = parser.parse_args()

    logging.raiseExceptions = False
    logging.captureWarnings(True)
    if args.log_to_stderr:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(f'%(asctime)s: %(levelname)s - %(message)s'))
    else:
        handler = JournalHandler(SYSLOG_IDENTIFIER='torxy')
    logging.getLogger().addHandler(handler)
    logging.root.setLevel(logging.DEBUG if args.debug else logging.INFO)

    rules = RedirectRules(args.rules_path)
    socks_server = SocksServer.from_address(args.socks_server)
    server = TorxyServer(args.listen_on, rules, socks_server)

    loop = get_event_loop()
    loop.add_signal_handler(SIGHUP, rules.reload)
    loop.add_signal_handler(SIGINT, lambda: _exit(0))
    loop.add_signal_handler(SIGTERM, lambda: _exit(0))

    async def notify_start():
        log.debug('Start serving requests on %r.', args.listen_on)
        if getenv('NOTIFY_SOCKET'):
            notify('READY=1')

    loop.run_until_complete(server.start())
    ensure_future(notify_start())
    loop.run_forever()


if __name__ == '__main__':
    main()
