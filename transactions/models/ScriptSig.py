from binascii import hexlify
from io import BytesIO
from .ParsingUtils import bytes_to_int
from django.db import models


class ScriptSig(models.Model):
    hex = models.CharField()
    asm = models.CharField()
    type = models.CharField()

    def __repr__(self):
        return "{}: {} \n {}: {} \n {}: {}".format(self.hex, self.asm, self.type)

    def to_dict(self):
        return dict(
            hex=self.hex,
            asm=self.asm,
            type=self.type
        )

    @classmethod
    def parse(cls, binary):
        script_hex = hexlify(binary).decode('ascii')
        stream = BytesIO(binary)

        script = ''
        if binary[0] == 0:
            script = '0'
            stream = BytesIO(binary[1:])
        else:
            stream = BytesIO(binary)

        length = bytes_to_int(stream.read(1))
        while length == 71 or length == 72:
            signature = hexlify(stream.read(length)).decode('ascii')
            if signature.endswith('01'):
                signature = signature[:-2] + '[ALL]'
            script += ' ' + signature
            length = bytes_to_int(stream.read(1))

        if length > 75:
            length = bytes_to_int(stream.read(1))
        redeem_script = hexlify(stream.read(length)).decode('ascii')
        script += ' ' + redeem_script

        return cls(script_hex, script.strip(), 'scriptsig')
