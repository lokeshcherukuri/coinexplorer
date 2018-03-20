from hashlib import sha256


def bytes_to_int(bytes_array, byteorder='little'):
    return int.from_bytes(bytes_array, byteorder=byteorder)


def read_stream(stream, from_pos, to_pos, set_pos):
    stream.seek(from_pos)
    data = stream.read(to_pos-from_pos)
    stream.seek(set_pos)
    return data


def double_sha256(byte_arr):
    return sha256(sha256(byte_arr).digest()).digest()


def variable_length_from_bytes(stream):
    prefix = stream.read(1)
    value = b''
    if prefix[0] == 253:
        value += stream.read(2)
    elif prefix[0] == 254:
        value += stream.read(2)
    elif prefix[0] == 255:
        value += stream.read(4)
    else:
        return bytes_to_int(prefix)

    return bytes_to_int(value)



