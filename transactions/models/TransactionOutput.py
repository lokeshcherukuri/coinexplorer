from .ParsingUtils import bytes_to_int
from .ScriptPubKey import ScriptPubKey
from django.db import models


class TransactionOutput(models.Model):
    value = models.FloatField()
    scriptPubKey = models.OneToOneField(ScriptPubKey)

    def __repr__(self):
        return "{{ \n value: {}\n scriptPubKey: {}\n }}".format(
            self.value, self.scriptPubKey
        )

    def to_dict(self):
        return dict(
            value=self.value,
            scriptPubKey=self.scriptPubKey
        )

    @classmethod
    def parse(cls, stream):
        value = bytes_to_int(stream.read(8))
        script_pub_key_length = bytes_to_int(stream.read(1))
        script_pub_key = ScriptPubKey.parse(stream.read(script_pub_key_length))
        return cls(value, script_pub_key)
