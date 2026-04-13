import random
import struct

MAGIC_8  = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]
MAGIC_16 = [0x0000, 0x0001, 0x007f, 0x0080, 0x00ff,
            0x7fff, 0x8000, 0xfffe, 0xffff]
MAGIC_32 = [0x00000000, 0x00000001, 0x0000007f, 0x00000080,
            0x000000ff, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]


class BitFlipper:
    name = "bit_flip"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data
        data = bytearray(data)
        idx = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        data[idx] ^= (1 << bit)
        return bytes(data)


class ByteRandomizer:
    name = "byte_rand"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data
        data = bytearray(data)
        idx = random.randint(0, len(data) - 1)
        data[idx] = random.randint(0, 255)
        return bytes(data)


class ByteInserter:
    name = "byte_insert"

    def mutate(self, data: bytes) -> bytes:
        data = bytearray(data)
        idx = random.randint(0, len(data))
        count = random.choice([1, 2, 4, 8, 16, 32, 64, 128, 256])
        insertion = bytes([random.randint(0, 255) for _ in range(count)])
        return bytes(data[:idx] + bytearray(insertion) + data[idx:])


class ByteDeleter:
    name = "byte_delete"

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data
        idx = random.randint(0, len(data) - 1)
        count = random.randint(1, max(1, len(data) // 4))
        return data[:idx] + data[idx + count:]


class MagicValueInjector:
    name = "magic_val"

    def mutate(self, data: bytes) -> bytes:
        if not data:
            return data
        data = bytearray(data)
        idx = random.randint(0, len(data) - 1)
        width = random.choice([1, 2, 4])

        if width == 1:
            val = random.choice(MAGIC_8)
            data[idx] = val

        elif width == 2 and idx + 2 <= len(data):
            val = random.choice(MAGIC_16)
            endian = random.choice(['little', 'big'])
            data[idx:idx+2] = struct.pack(f"{'<' if endian == 'little' else '>'}H", val)

        elif width == 4 and idx + 4 <= len(data):
            val = random.choice(MAGIC_32)
            endian = random.choice(['little', 'big'])
            data[idx:idx+4] = struct.pack(f"{'<' if endian == 'little' else '>'}I", val)

        return bytes(data)


class ChunkRepeater:
    name = "chunk_repeat"

    def mutate(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data
        idx   = random.randint(0, len(data) - 1)
        size  = random.randint(1, max(1, len(data) - idx))
        chunk = data[idx:idx + size]
        times = random.choice([2, 4, 8, 16, 32, 64])
        return data[:idx] + chunk * times


class FormatStringInjector:
    name = "fmt_inject"

    PAYLOADS = [
        b"%x",  b"%s",  b"%n",  b"%p",
        b"%x." * 10,
        b"%08x." * 20,
        b"AAAA" + b"%x." * 30,
        b"%s" * 50,
        b"%n" * 20,
        b"%.100000d",         
        b"%1$n",            
        b"%10$x" * 20,      
    ]

    def mutate(self, data: bytes) -> bytes:
        payload = random.choice(self.PAYLOADS)
        if random.random() < 0.4 or not data:
            return payload
        idx = random.randint(0, len(data))
        return data[:idx] + payload + data[idx:]


class Havoc:
    name = "havoc"

    BASE_MUTATORS = [
        BitFlipper(), ByteRandomizer(), ByteInserter(),
        ByteDeleter(), MagicValueInjector(), ChunkRepeater()
    ]

    def mutate(self, data: bytes) -> bytes:
        count = random.randint(2, 8)
        for _ in range(count):
            m = random.choice(self.BASE_MUTATORS)
            data = m.mutate(data)
        return data


ALL_MUTATORS = [
    BitFlipper(),
    ByteRandomizer(),
    ByteInserter(),
    ByteDeleter(),
    MagicValueInjector(),
    ChunkRepeater(),
    FormatStringInjector(),
    Havoc(),
]

def get_mutator(name: str):
    for m in ALL_MUTATORS:
        if m.name == name:
            return m
    raise ValueError(f"Unknown mutator: {name}")