import os
import socket

from ntlm_auth.compute_response import ComputeResponse
from ntlm_auth.constants import ( # type: ignore
    NegotiateFlags as NF,
)

from .messages import (
    NegotiateMessage,
    ChallengeMessage,
    AuthenticateMessage,
    NTLMv2Response,
)

NTLM_UNICODE_ENCODING = 'utf_16_le'

def encode_unicode(inp: str) -> bytes:
    return inp.encode(NTLM_UNICODE_ENCODING)

def decode_unicode(inp: bytes) -> str:
    return inp.decode(NTLM_UNICODE_ENCODING)


# get fqdn to use as workstation name
fqdn = encode_unicode(socket.getfqdn())


def parse_negotiate(header: str) -> NegotiateMessage:
    return NegotiateMessage.parse(header)

def build_challenge(msg: NegotiateMessage) -> ChallengeMessage:
    if not msg.NegotiateFlags & NF.NTLMSSP_NEGOTIATE_UNICODE:
        raise 'NTLM Negotiate without NTLMSSP_NEGOTIATE_UNICODE not supported'

    if not msg.NegotiateFlags & NF.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        raise 'NTLM Negotiate without NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not supported'

    return ChallengeMessage(
        fqdn,
        NF.NTLMSSP_NEGOTIATE_UNICODE |                  # only support unicode
        NF.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | # only support NTLMv2 security
        NF.NTLMSSP_REQUEST_TARGET |                     # must be set
        NF.NTLMSSP_TARGET_TYPE_SERVER,                  # set for none-domain server
        os.urandom(8)
    )

def parse_authenticate(header: str) -> AuthenticateMessage:
    return AuthenticateMessage.parse(header)

def check_authenticate(
        msg_authenticate: AuthenticateMessage,
        msg_challenge: ChallengeMessage
    ) -> bool:

    if len(msg_authenticate.NtChallengeResponse) <= 24:
        raise 'Only NTLMv2 authentication supported'

    nt_challenge_response = NTLMv2Response.parse(
        msg_authenticate.NtChallengeResponse)

    nt_response,session_key = ComputeResponse._get_NTLMv2_response(
        decode_unicode(msg_authenticate.UserName),
        'test',
        decode_unicode(msg_authenticate.DomainName),
        msg_challenge.ServerChallenge,
        nt_challenge_response.ChallengeFromClient,
        nt_challenge_response.TimeStamp,
        nt_challenge_response.TargetInfo
    )

    return msg_authenticate.NtChallengeResponse == nt_response
