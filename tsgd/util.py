import struct
import typing

class Struct(struct.Struct):
    def __init__(self, *parts):
        super().__init__(''.join(parts))
