from binascii import hexlify
from .ParsingUtils import bytes_to_int, variable_length_from_bytes
from .ScriptSig import ScriptSig
from django.db import models


class TransactionInput(models.Model):
    coinbase = models.CharField()
    txid = models.CharField()
    vout = models.IntegerField()
    scriptSig = models.OneToOneField(ScriptSig)
    sequence = models.CharField()

    def __init__(self, coinbase, sequence, txid=None, prev_tx_output_index=None, script_sig=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if coinbase is not None:
            self.coinbase = coinbase
        else:
            self.txid = txid
            self.vout = prev_tx_output_index
            self.scriptSig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return "{{ \n txid: {},\n vout: {}, \n script: {}, \n sequence: {}\n }}".format(
            self.txid, self.vout, self.scriptSig, self.sequence
        )

    def to_dict(self):
        tx_input = None
        if hasattr(self, 'coinbase'):
            tx_input = dict(
                coinbase=self.coinbase,
                sequence=self.sequence
            )
        else:
            tx_input = dict(
                txid=self.txid,
                vout=self.vout,
                scriptSig=self.scriptSig,
                sequence=self.sequence
            )
        if hasattr(self, 'witness'):
            tx_input['witness'] = self.witness
        return tx_input

    @classmethod
    def parse(cls, stream):
        txid = hexlify(stream.read(32)[::-1]).decode('ascii')
        vout = bytes_to_int(stream.read(4))
        script_length = variable_length_from_bytes(stream)

        if int(txid, 16) == 0:
            coinbase = hexlify(stream.read(script_length)).decode('ascii')
            sequence = bytes_to_int(stream.read(4))
            return cls(coinbase, sequence)
        else:
            script_sig = ScriptSig.parse(stream.read(script_length))
            sequence = bytes_to_int(stream.read(4))
            return cls(None, sequence, txid, vout, script_sig)
