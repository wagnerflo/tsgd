import base64
import typing

from ntlm_auth.constants import ( # type: ignore
    NTLM_SIGNATURE,
    MessageTypes,
)
from ntlm_auth.messages import ( # type: ignore
    TargetInfo,
)

from ..util import Struct

HEADER_PREFIX = 'NTLM '

def decode_header(header: str) -> bytes:
    if not header.startswith(HEADER_PREFIX):
        raise 'Invalid Authorization header'

    return base64.b64decode(header[len(HEADER_PREFIX):])

def encode_header(data: bytes) -> str:
    return HEADER_PREFIX + base64.b64encode(data).decode('ascii')

negotiate_header = Struct(
    '<',  # little-endian
    '8s', # Signature
    'L',  # MessageType
    'I',  # NegotiateFlags
    'H',  # DomainNameLen
    'H',  # DomainNameMaxLen
    'I',  # DomainNameBufferOffset
    'H',  # WorkstationLen
    'H',  # WorkstationMaxLen
    'I',  # WorkstationBufferOffset
    '8s', # Version
)

class NegotiateMessage(typing.NamedTuple):
    NegotiateFlags: int
    DomainName: bytes
    WorkstationName: bytes

    @classmethod
    def parse(cls, header):
        bytes = decode_header(header)

        ( signature,
          message_type,
          negotiate_flags,
          domain_name_len,
          domain_name_max_len,
          domain_name_offset,
          workstation_len,
          workstation_max_len,
          workstation_offset,
          version ) = negotiate_header.unpack_from(bytes)

        if (signature != NTLM_SIGNATURE or
            message_type != MessageTypes.NTLM_NEGOTIATE):
            raise 'Not a NTLM Negotiate message'

        expected_message_len = (
            negotiate_header.size +
            domain_name_len + workstation_len
        )

        if len(bytes) != expected_message_len:
            raise 'NTLM Negotiate invalid payload length'

        return cls(
            negotiate_flags,
            bytes[domain_name_offset:domain_name_offset+domain_name_len],
            bytes[workstation_offset:workstation_offset+workstation_len],
        )

challenge_header = Struct(
    '<',  # little-endian
    '8s', # Signature
    'L',  # MessageType
    'H',  # TargetNameLen
    'H',  # TargetNameMaxLen
    'I',  # TargetNameBufferOffset
    'I',  # NegotiateFlags
    '8s', # ServerChallenge
    '8s', # Reserved
    'H',  # TargetInfoLen
    'H',  # TargetInfoMaxLen
    'I',  # TargetInfoBufferOffset
    '8s', # Version
)

class ChallengeMessage(typing.NamedTuple):
    TargetName: bytes
    NegotiateFlags: int
    ServerChallenge: bytes
    TargetInfo: bytes = b''

    def __str__(self):
        bytes = (
            challenge_header.pack(
                NTLM_SIGNATURE,
                MessageTypes.NTLM_CHALLENGE,
                len(self.TargetName),
                len(self.TargetName),
                challenge_header.size,
                self.NegotiateFlags,
                self.ServerChallenge,
                b'\x00' * 8,
                len(self.TargetInfo),
                len(self.TargetInfo),
                challenge_header.size + len(self.TargetName),
                b'\x00' * 8,
            ) +
            self.TargetName +
            self.TargetInfo
        )

        return encode_header(bytes)

authenticate_header = Struct(
    '<',  # little-endian
    '8s', # Signature
    'L',  # MessageType
    'H',  # LmChallengeResponseLen
    'H',  # LmChallengeResponseMaxLen
    'I',  # LmChallengeResponseBufferOffset
    'H',  # NtChallengeResponseLen
    'H',  # NtChallengeResponseMaxLen
    'I',  # NtChallengeResponseBufferOffset
    'H',  # DomainNameLen
    'H',  # DomainNameMaxLen
    'I',  # DomainNameBufferOffset
    'H',  # UserNameLen
    'H',  # UserNameMaxLen
    'I',  # UserNameBufferOffset
    'H',  # WorkstationLen
    'H',  # WorkstationMaxLen
    'I',  # WorkstationBufferOffset
    'H',  # EncryptedRandomSessionKeyLen
    'H',  # EncryptedRandomSessionKeyMaxLen
    'I',  # EncryptedRandomSessionKeyBufferOffset
    'I',  # NegotiateFlags
    '8s', # Version
    '4I', # MIC
)

class AuthenticateMessage(typing.NamedTuple):
    NegotiateFlags: int
    LmChallengeResponse: bytes
    NtChallengeResponse: bytes
    DomainName: bytes
    UserName: bytes
    Workstation: bytes
    EncryptedRandomSessionKey: bytes

    @classmethod
    def parse(cls, header):
        bytes = decode_header(header)

        ( signature,
          message_type,
          lm_response_len,
          lm_response_max_len,
          lm_response_offset,
          nt_response_len,
          nt_response_max_len,
          nt_response_offset,
          domain_name_len,
          domain_name_max_len,
          domain_name_offset,
          user_name_len,
          user_name_max_len,
          user_name_offset,
          workstation_len,
          workstation_max_len,
          workstation_offset,
          session_key_len,
          session_key_max_len,
          session_key_offset,
          negotiate_flags,
          version,
          mic1, mic2, mic3, mic4 ) = authenticate_header.unpack_from(bytes)

        if (signature != NTLM_SIGNATURE or
            message_type != MessageTypes.NTLM_AUTHENTICATE):
            raise 'Not a NTLM Authenticate message'

        expected_message_len = (
            authenticate_header.size +
            lm_response_len + nt_response_len + domain_name_len +
            user_name_len + workstation_len + session_key_len
        )

        if len(bytes) != expected_message_len:
            raise 'NTLM Authenticate invalid payload length'

        return cls(
            negotiate_flags, *(
                bytes[offset:offset+length] for offset,length in (
                    ( lm_response_offset, lm_response_len ),
                    ( nt_response_offset, nt_response_len ),
                    ( domain_name_offset, domain_name_len ),
                    ( user_name_offset,   user_name_len   ),
                    ( workstation_offset, workstation_len ),
                    ( session_key_offset, session_key_len ),
                )
            )
        )

ntlmv2response_header = Struct(
    '<',   # little-endian
    '16s', # Response
    'B',   # RespType
    'B',   # HiRespType
    'H',   # Reserved1
    'I',   # Reserved2
    '8s',  # TimeStamp
    '8s',  # ChallengeFromClient
    'I',   # Reserved3
)

class NTLMv2Response(typing.NamedTuple):
    ChallengeFromClient: bytes
    TimeStamp: bytes
    TargetInfo: bytes

    @classmethod
    def parse(cls, bytes):
        ( response,
          resp_type,
          hi_resp_type,
          reserved1,
          reserved2,
          timestamp,
          challenge_from_client,
          reserved ) = ntlmv2response_header.unpack_from(bytes)

        if resp_type != 0x01 or hi_resp_type != 0x01:
            raise 'Not a valid NTLMv2Response'

        target_info = TargetInfo()
        target_info.unpack(bytes[ntlmv2response_header.size:])

        return cls(
            challenge_from_client,
            timestamp,
            target_info
        )
