import logging
import re

from typing import Dict, Any
from aiohttp import web
from asyncio import Transport

from .. import ntlm
from .state import ClientState
from .messages import (
    HTTP_HANDSHAKE_REQUEST,
    HTTP_HANDSHAKE_RESPONSE,
    HTTP_TUNNEL_PACKET,
    HTTP_TUNNEL_RESPONSE,
    HTTP_TUNNEL_AUTH_PACKET,
    HTTP_TUNNEL_AUTH_RESPONSE,
    HTTP_CHANNEL_PACKET,
)

logger = logging.getLogger(__package__)

class WebSocketResponse(web.WebSocketResponse):
    async def send_object(self, obj, compress=None):
        logger.debug('Sending %s', obj)
        await self.send_bytes(bytes(obj), compress=compress)

    async def receive_object(self, cls):
        obj = cls.parse(await self.receive_bytes())
        logger.debug('Received %s', obj)
        return obj

class RemoteDesktopGateway:
    ACME_REGEX = re.compile(
        r'^/\.well-known/acme-challenge/([-_a-zA-Z0-9]+)$'
    )

    def __init__(self):
        self._clients: Dict[Transport, ClientState] = {}

    def require_auth_header(self, headers):
        auth = headers.get('Authorization')
        if not auth:
            raise web.HTTPBadRequest(
                text = 'Authorization header missing'
            )
        return auth

    async def handler(self, request):
        method = request.method
        path = request.path

        # support ACME stateless mode
        if method == 'GET':
            match = ACME_REGEX.match(path)
            if match is not None:
                return web.Response(
                    text = '.'.join((match.group(1), 'bla'))
                )

        # only very specific paths are allowed
        if path != '/remoteDesktopGateway/':
            return web.HTTPNotFound()

        clienthash = hash(request.transport)
        state = self._clients.get(clienthash, None)

        # client unknown
        if state is None:
            if method != 'RDG_OUT_DATA':
                return web.HTTPNotFound()

            self._clients[clienthash] = state = ClientState()
            state.CLIENT_CONNECTED()

        # check connection id
        headers = request.headers
        conid = headers.get('RDG-Connection-Id')

        if not conid:
            return web.HTTPBadRequest(
                text = 'RDG-Connection-Id header missing'
            )

        # first request of this connection
        if state.CLIENT_CONNECTED:
            state.conid = conid
            state.WAIT_NTLM_NEGOTIATE()

            return web.HTTPUnauthorized(
                headers = {
                    'WWW-Authenticate': 'NTLM'
                }
            )

        # check connection id
        if state.conid != conid:
            return web.HTTPBadRequest(
                text='RDG-Connection-Id has changed'
            )

        # parse NTLM Negotiate message
        if state.WAIT_NTLM_NEGOTIATE:
            auth = self.require_auth_header(headers)
            msg_negotiate = ntlm.parse_negotiate(auth)

            # send NTLM Challenge
            state.msg_challenge = ntlm.build_challenge(msg_negotiate)
            state.WAIT_NTLM_AUTHENTICATE()

            return web.HTTPUnauthorized(
                headers = {
                    'WWW-Authenticate': str(state.msg_challenge)
                }
            )

        # parse NTLM Authenticate
        if state.WAIT_NTLM_AUTHENTICATE:
            auth = self.require_auth_header(headers)
            msg_authenticate = ntlm.parse_authenticate(auth)

            # authenticate
            if not ntlm.check_authenticate(msg_authenticate, state.msg_challenge):
                return web.HTTPUnauthorized(
                    text = 'Access denied'
                )

            # open websocket
            ws = WebSocketResponse()
            await ws.prepare(request)

            # handshake
            handshake = await ws.receive_object(HTTP_HANDSHAKE_REQUEST)

            if (handshake.verMajor,handshake.verMinor) != (1,0):
                logger.info('Unsupported client version. Closing connection.')
                await ws.close()
                return ws

            await ws.send_object(HTTP_HANDSHAKE_RESPONSE(0,1,0))

            # tunnel create
            tunnel_create = await ws.receive_object(HTTP_TUNNEL_PACKET)
            await ws.send_object(HTTP_TUNNEL_RESPONSE(0,0,1,0))

            # tunnel auth
            tunnel_auth = await ws.receive_object(HTTP_TUNNEL_AUTH_PACKET)
            await ws.send_object(HTTP_TUNNEL_AUTH_RESPONSE(0,0,0))

            # channel create
            channel_create = await ws.receive_object(HTTP_CHANNEL_PACKET)
            print(channel_create)

            return ws

        return web.HTTPConflict()
