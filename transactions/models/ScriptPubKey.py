from binascii import hexlify
from io import BytesIO
from .Globals import *
from .ParsingUtils import bytes_to_int
from django.db import models


class ScriptPubKey(models.Model):
    hex = models.CharField()
    asm = models.CharField()
    type = models.CharField()

    def __repr__(self):
        return "{{ \n hex: {}\n asm: {}\n type: {}\n }}".format(
            self.hex, self.asm, self.type
        )

    def to_dict(self):
        return dict(
            hex=self.hex,
            asm=self.asm,
            type=self.type
        )

    @classmethod
    def parse(cls, binary):
        script_pubkey_hex = hexlify(binary).decode('ascii')
        stream = BytesIO(binary)
        elements = []
        byte = stream.read(1)
        while byte != b'':
            num = bytes_to_int(byte)
            if 0 < num <= 75:
                elements.append(hexlify(stream.read(num)).decode('ascii'))
            else:
                elements.append(OP_CODES[num])
            byte = stream.read(1)

        script = ''
        for element in elements:
            script += element + ' '

        script_type = cls.findScriptType(script.strip())
        return cls(script_pubkey_hex, script.strip(), script_type)

    @staticmethod
    def findScriptType(script):
        if ScriptPubKey.isPayToPubKey(script):
            return 'pubkey'
        elif ScriptPubKey.isPayToPubKeyHash(script):
            return 'pubkeyhash'
        elif ScriptPubKey.isPayToScriptHash(script):
            return 'scripthash'
        else:
            return RuntimeError('Unknown Script Type')

    @staticmethod
    def isPayToPubKey(script):
        elements = script.split(' ')
        if elements is None or len(elements) != 1:
            return False
        if elements[0] != 'OP_CHECKSIG':
            return False
        return True

    @staticmethod
    def isPayToPubKeyHash(script):
        elements = script.split(' ')
        if elements is None or len(elements) != 5:
            return False
        if elements[0] != 'OP_DUP' or elements[1] != 'OP_HASH160':
            return False
        if elements[2] is None or len(elements[2]) != LEGACY_ADDRESS_SIZE*2:
            return False
        if elements[3] != 'OP_EQUALVERIFY' or elements[4] != 'OP_CHECKSIG':
            return False
        return True

    @staticmethod
    def isPayToScriptHash(script):
        elements = script.split(' ')
        if elements is None or len(elements) != 3:
            return False
        if elements[0] != 'OP_HASH160':
            return False
        if elements[1] is None or len(elements[1]) != LEGACY_ADDRESS_SIZE*2:
            return False
        if elements[2] != 'OP_EQUAL':
            return False
        return True
