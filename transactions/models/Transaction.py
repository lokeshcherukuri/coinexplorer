from binascii import hexlify
from .ParsingUtils import bytes_to_int, read_stream, double_sha256
from .TransactionInput import TransactionInput
from .TransactionOutput import TransactionOutput
from django.db import models


class Transaction(models.Model):
    txid = models.CharField()
    hash = models.CharField()
    version = models.CharField()
    vin = []
    vout = []
    locktime = models.CharField()

    def __repr__(self):
        inputs_json = ''
        for tx_input in self.vin:
            inputs_json += tx_input.__repr__()

        outputs_json = ''
        for tx_output in self.vout:
            outputs_json += tx_output.__repr__()

        return '{{ \n txid:{}, \n hash:{} \n version:{}, \n vin:[{}], \n vout:[{}], \n locktime:{} \n }}'.format(
            self.txid, self.hash, self.version, inputs_json, outputs_json, self.locktime
        )

    def to_dict(self):
        return dict(
            txid=self.txid,
            hash=self.hash,
            version=self.version,
            vin=self.vin,
            vout=self.vout,
            locktime=self.locktime
        )

    @classmethod
    def parse(cls, stream):
        version_bytes = stream.read(4)
        non_witness_bytes = version_bytes
        version = bytes_to_int(version_bytes)

        is_segwit = None
        segwit_maker_test = bytes_to_int(stream.read(1))
        if segwit_maker_test == 0:
            segwit_flag_test = bytes_to_int(stream.read(1))
            if segwit_flag_test == 1:
                is_segwit = True
            else:
                return RuntimeError('Error: Segwit Maker is set but not Segwit Flag')

        if is_segwit:
            inputs_size = bytes_to_int(stream.read(1))
        else:
            inputs_size = segwit_maker_test

        non_witness_bytes += inputs_size.to_bytes(length=1, byteorder='big')
        inputs_start_position = stream.tell()
        vin = cls.parseInputs(stream, inputs_size)

        outputs_size = bytes_to_int(stream.read(1))
        vout = cls.parseOutputs(stream, outputs_size)

        outputs_end_position = stream.tell()
        non_witness_bytes += read_stream(stream, inputs_start_position, outputs_end_position, outputs_end_position)

        if is_segwit:
            for tx_input in vin:
                witness = cls.parseWitness(stream)
                tx_input.witness = witness

        locktime_bytes = stream.read(4)
        locktime = bytes_to_int(locktime_bytes)
        non_witness_bytes = non_witness_bytes + locktime_bytes

        txid_double_hash = double_sha256(non_witness_bytes)
        txid = hexlify(txid_double_hash[::-1]).decode('ascii')

        tx_double_hash = double_sha256(stream.getvalue())
        tx_hash = hexlify(tx_double_hash[::-1]).decode('ascii')

        return cls(txid, tx_hash, version, vin, vout, locktime)

    @staticmethod
    def parseWitness(stream):
        witness_count = bytes_to_int(stream.read(1))
        witnesses = []
        for i in range(witness_count):
            witness_size = bytes_to_int(stream.read(1))
            witness = hexlify(stream.read(witness_size)).decode('ascii')
            witnesses.append(witness)
        return witnesses

    @staticmethod
    def parseInputs(stream, inputs_size):
        vin = []
        for i in range(0, inputs_size):
            tx_input = TransactionInput.parse(stream)
            vin.append(tx_input)
        return vin

    @staticmethod
    def parseOutputs(stream, outputs_size):
        vout = []
        for i in range(0, outputs_size):
            tx_output = TransactionOutput.parse(stream)
            vout.append(tx_output)
        return vout
