from __future__ import annotations
from typing import NamedTupleMeta,Tuple,Any

from ..util import Struct
from .constants import ( # type: ignore
    PKT_TYPE,
    HTTP_TUNNEL_RESPONSE_FIELD,
    HTTP_TUNNEL_AUTH_RESPONSE_FIELD,
)

http_packet_header = Struct(
    '<',  # little-endian
    'H',  # packetType
    'H',  # reserved
    'I',  # packetLength
)

def decode_unicode(data) -> str:
    s = bytes(data).decode('utf_16_le')
    if s[-1] != '\x00':
        raise 'Unicode decode error'
    return s[:-1]

class HTTP_UNICODE_STRING(str):
    struct_length = Struct('<H')

    @classmethod
    def parse(cls, data: bytes) -> HTTP_UNICODE_STRING:
        length, = cls.struct_length.unpack_from(data)
        print( bytes(data[cls.struct_length.size:cls.struct_length.size+length]) )


class HTTP_PACKET_Meta(type):
    def __new__(mcls, typename, bases, ns):
        if bases:
            bases = bases + (
                NamedTupleMeta.__new__(mcls, '_base_' + typename, (), ns),
            )
        return type.__new__(mcls, typename, bases, ns)


    def __init__(cls, name, bases, attrs, **kwargs):
        Meta = attrs.get('Meta', None)
        if Meta is not None:
            Meta.body_struct = Struct('<', *Meta.body_types)
            Meta.packet_size = http_packet_header.size + Meta.body_struct.size
        return super().__init__(name, bases, attrs)

class HTTP_PACKET(metaclass=HTTP_PACKET_Meta):
    @classmethod
    def parse(cls, data: bytes) -> HTTP_PACKET:
        *fields,rest = cls.unpack(data)
        return cls(*fields)

    @classmethod
    def unpack(cls, data: bytes) -> Tuple[Any]:
        ( packetType,
          reserved,
          packetLength ) = http_packet_header.unpack_from(data)

        if packetType != cls.Meta.packet_type:
            raise 'Expected {} but got {}'.format(
                cls.Meta.packet_type.name, PacketTypes(packetType).name
            )

        if len(data) != packetLength:
            raise 'Invalid packet length'

        fields = cls.Meta.body_struct.unpack_from(
            data, offset=http_packet_header.size
        )
        rest = memoryview(data)[cls.Meta.packet_size:]

        return fields + (rest,)

    def __bytes__(self):
        return self.pack(*self)

    def pack_header(self, restlen):
        return http_packet_header.pack(
            self.Meta.packet_type,
            0,
            self.Meta.packet_size + restlen
        )

    def pack(self, *body, rest: bytes = b''):
        return (
            self.pack_header(len(rest)) +
            self.Meta.body_struct.pack(*body) +
            rest
        )


class HTTP_HANDSHAKE_REQUEST(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.HANDSHAKE_REQUEST
        body_types = (
            'B', # verMajor
            'B', # verMinor
            'H', # clientVersion
            'H', # extendedAuth
        )

    verMajor: int
    verMinor: int
    clientVersion: int = 0
    extendedAuth: int = 0

class HTTP_HANDSHAKE_RESPONSE(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.HANDSHAKE_RESPONSE
        body_types = (
            'I', # errorCode
            'B', # verMajor
            'B', # verMinor
            'H', # serverVersion
            'H', # extendedAuth
        )

    errorCode: int
    verMajor: int
    verMinor: int
    serverVersion: int = 0
    extendedAuth: int = 0

class HTTP_TUNNEL_PACKET(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.TUNNEL_CREATE
        body_types = (
            'I', # capsFlags
            'H', # fieldsPresent
            'H', # reserved
        )

    capsFlags: int
    fieldsPresent: int
    reserved: int

class HTTP_TUNNEL_RESPONSE(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.TUNNEL_RESPONSE
        body_types = (
            'H', # serverVersion
            'I', # statusCode
            'H', # fieldsPresent
            'H', # reserved
            'I', # tunnelId
            'I', # capsFlags
        )

    def __bytes__(self):
        return self.pack(
            self.serverVersion,
            self.statusCode,
            HTTP_TUNNEL_RESPONSE_FIELD.TUNNEL_ID |
            HTTP_TUNNEL_RESPONSE_FIELD.CAPS,
            0,
            self.tunnelId,
            self.capsFlags,
        )

    serverVersion: int
    statusCode: int
    tunnelId: int
    capsFlags: int

class HTTP_TUNNEL_AUTH_PACKET(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.TUNNEL_AUTH
        body_types = (
            'H', # fieldsPresent
            'H', # cbClientName
        )

    @classmethod
    def parse(cls, data: bytes) -> HTTP_PACKET:
        ( fieldsPresent,
          cbClientName,
          rest ) = cls.unpack(data)

        if len(rest) != cbClientName:
            raise 'Invalid clientName length'

        return cls(fieldsPresent, decode_unicode(rest))

    fieldsPresent: int
    clientName: str

class HTTP_TUNNEL_AUTH_RESPONSE(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.TUNNEL_AUTH_RESPONSE
        body_types = (
            'I', # errorCode
            'H', # fieldsPresent
            'H', # reserved
            'I', # redirFlags
            'I', # idleTimeout
        )

    def __bytes__(self):
        return self.pack(
            self.errorCode,
            HTTP_TUNNEL_AUTH_RESPONSE_FIELD.REDIR_FLAGS |
            HTTP_TUNNEL_AUTH_RESPONSE_FIELD.IDLE_TIMEOUT,
            0,
            self.redirFlags,
            self.idleTimeout,
        )

    errorCode: int
    redirFlags: int
    idleTimeout: int

class HTTP_CHANNEL_PACKET(HTTP_PACKET):
    class Meta:
        packet_type = PKT_TYPE.CHANNEL_CREATE
        body_types = (
            'B', # numResources
            'B', # numAltResources
            'H', # port
            'H', # protocol
        )

    @classmethod
    def parse(cls, data: bytes) -> HTTP_PACKET:
        ( numResources,
          numAltResources,
          port,
          protocol,
          rest ) = cls.unpack(data)

        if protocol != 3:
            raise 'Invalid protocol'

        HTTP_UNICODE_STRING.parse(rest)

        return cls(port)

    port: int
