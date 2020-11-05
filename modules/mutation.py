import random
from pwn import *

def mutate_bit_flip(mutation_percentage, data):
    count = int((len(data) * 8) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        bit = random.randint(0, len(data) * 8 - 1)
        idx_bit = bit % 8
        idx_byte = bit / 8
        data[idx_byte] ^= 1 << idx_bit

    return data

def mutate_byte_random(mutation_percentage, data):
    count = int(len(data) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        data[random.randint(0, len(data) - 1)] = random.randint(0, 255)
        return data

def mutate_byte_flip(mutation_percentage, data):
    count = int(len(data) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        data[random.randint(0, len(data) - 1)] ^= 0xff
    return data

def mutate_byte_insert(mutation_percentage, data):
    count = int(len(data) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        data.insert(random.randint(0, len(data) - 1), random.randint(0, 255))
    return data

def mutate_byte_delete(mutation_percentage, data):
    count = int(len(data) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        data.pop(random.randint(0, len(data) - 1))
    return data

def mutate_byte_operation(mutation_percentage, data):
    operators = ['+', '-', '*', '/']
    numbers = [256, 0xff, 0x7f, 0xffff, 0xffffffff, 0x80000000, 0x40000000, 0x7fffffff, 0x7fffffffffffffff]

    count = int(len(data) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        op = random.choice(operators)
        crazy_integer = random.choice(numbers)
        i = random.randint(0, len(data) - 1)
        data[i] = eval(str(data[i]) + op + str(crazy_integer)) & 0xff
    return data

def mutate_duplicate(mutation_percentage, data):
    return data*2

def mutate_buffer_overflow(mutation_percentage, data):
    return data + "A"*2000

def mutate_magic(mutation_percentage, data):
    numbers = [
        (1, p8(0xff)),
        (1, p8(0x7f)),
        (1, p8(0)),
        (2, p16(0xffff)),
        (2, p16(0)),     
        (4, p32(0xffffffff)),
        (4, p32(0)),
        (4, p32(0x80000000)),
        (4, p32(0x40000000)),
        (4, p32(0x7fffffff)),
        (8, p64(0x7fffffffffffffff))
    ]

    count = int(len(data) * mutation_percentage)
    if count == 0:
        count = 1
    for _ in range(count):
        n_size, n = random.choice(numbers)
        sz = len(data) - n_size
        if sz < 0:
            continue
        idx = random.randint(0, sz)
        data[idx:idx + n_size] = bytearray(n)

    return data