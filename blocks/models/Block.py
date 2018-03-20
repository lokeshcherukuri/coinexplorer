from binascii import hexlify
from transactions.models.ParsingUtils import bytes_to_int
from transactions.models.Transaction import Transaction
from django.db import models


class Block(models.Model):
    version = models.CharField()
    previousblockhash = models.CharField()
    merkleroot = models.CharField()
    timestamp = models.CharField()
    bits = models.CharField()
    nonce = models.CharField()
    txs = []

    def to_dict(self):
        return dict(
            version=self.version,
            previousblockhash=self.previousblockhash,
            merkleroot=self.merkleroot,
            timestamp=self.timestamp,
            bits=self.bits,
            nonce=self.nonce,
            txs=self.txs
        );

    @classmethod
    def parse(cls, stream):
        version = bytes_to_int(stream.read(4))
        previousblockhash = hexlify(stream.read(32)[::-1]).decode('ascii')
        merkleroot = hexlify(stream.read(32)[::-1]).decode('ascii')
        timestamp = bytes_to_int(stream.read(4))
        bits = bytes_to_int(stream.read(4))
        nonce = bytes_to_int(stream.read(4))

        tx_count = bytes_to_int(stream.read(1))
        txs = []
        for i in range(0, tx_count):
            tx = Transaction.parse(stream)
            txs.append(tx)

        return cls(version, previousblockhash, merkleroot, timestamp, bits, nonce, txs)
