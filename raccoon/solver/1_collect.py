import asyncio
import random
import binascii
from concurrent.futures import ProcessPoolExecutor, wait
from multiprocessing import cpu_count, Manager
from typing import Tuple
from params import A, B, g, p

HOST = "127.0.0.1"
PORT = 8444

RANDOM_SIZE = 32


def msg_random(data: bytes) -> bytes:
    return b"random " + binascii.hexlify(data) + b"\n"


def msg_pubkey(pubkey: int) -> bytes:
    return b"pub " + binascii.hexlify(int_to_bytes(pubkey)) + b"\n"


def parse_server_random(msg: bytes) -> bytes:
    s = msg.decode()
    return binascii.unhexlify(s.strip().split(" ")[1])


def parse_dh_params(msg: bytes) -> Tuple[int, int, int]:
    s = msg.decode()
    params = s.split(" ")
    p = int(params[1], 16)
    g = int(params[3], 16)
    pub = int(params[5], 16)
    return p, g, pub


def parse_time(msg: bytes) -> int:
    s = msg.decode()
    params = s.strip().split(" ")
    return int(params[1], 16)


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


async def get_time(reader, writer, A: int, first: bool) -> int:

    client_random = random.randbytes(RANDOM_SIZE)
    writer.write(msg_random(client_random))

    if first:
        parse_server_random(await reader.readline())
        parse_dh_params(await reader.readline())

    writer.write(msg_pubkey(A))

    t = parse_time(await reader.readline())

    return t


async def run(queue, done):
    reader, writer = await asyncio.open_connection(HOST, PORT)

    i = 0
    while not done.is_set():
        r = random.randint(1, p - 1)
        A1 = (A * pow(g, r, p)) % p
        t = await get_time(reader, writer, A1, i == 0)
        i += 1

        if t >= 20000:
            continue

        print(t)

        v = pow(B, r, p)
        queue.put(v)

    writer.close()


def start(i, queue, done):
    print(f"Starting {i}")
    asyncio.run(run(queue, done))


def collect(queue, done):
    print("Starting collector")
    n = 0
    with open("values.txt", "a") as f:
        while n < 200:
            v = queue.get()
            f.write(str(v) + "\n")
            f.flush()
            n += 1
    done.set()


def main():
    futures = []
    num_cores = cpu_count()
    proc_count = num_cores
    pool = ProcessPoolExecutor(proc_count)
    manager = Manager()
    queue = manager.Queue()
    done = manager.Event()

    with pool as executor:
        futures.append(executor.submit(collect, queue, done))

        for i in range(proc_count - 1):
            futures.append(executor.submit(start, i, queue, done))

    wait(futures)


if __name__ == "__main__":
    main()
