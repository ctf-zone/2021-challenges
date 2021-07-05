import hmac
import hashlib
from binascii import unhexlify

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

client_random = unhexlify(
    "27F0365E759F3EC3E815C53DADAB222D5B005B5B22022185F603D9F12E7F5F3C"
)
server_random = unhexlify(
    "09C103DCAB35D6CEBACF24C6215C6404EF2967ABF62D7D670C537A9F68210597"
)

enc = [
    (
        "B4D8E17A186184D5981F27E981434440",
        "A3636D947F7B328FFCB4597C0BDBF822645EB54D8DCAB4DE2EFFF7DA0DCEAEF2",
    ),
    (
        "26671098FD2E592345776F72F81E5333",
        "3DEF3BD4282049C3E51D7020C2676B8E5C014E58899F7DE55679132A93B7B87CA6249FF1F84923CEFA483D40C6EB493B",
    ),
]


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


with open("possible.txt", "r") as f:
    lines = f.read().strip().split("\n")

possible = list(map(int, lines))

for pms in possible:
    key = hmac.new(
        int_to_bytes(pms), server_random + client_random, hashlib.sha256
    ).digest()

    for iv, data in enc:
        cipher = AES.new(key, AES.MODE_CBC, unhexlify(iv))
        try:
            print(cipher.decrypt(unhexlify(data)))
            pt = unpad(cipher.decrypt(unhexlify(data)), AES.block_size)
            print(pt)
        except ValueError:
            continue
