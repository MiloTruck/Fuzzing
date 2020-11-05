from pwn import *
import random
import sys
import subprocess, os
from modules.utilities import *
from modules.mutation import *

class DumbFuzzer:
    def __init__(self, executable):
        self.executable = executable
        self.mutation_percentage = 0.01

        # Create crashes directory if doesn't exist
        self.crashes_dir = os.getcwd() + '/' + executable + '_crashes/'
        self.data_dir = os.getcwd() + '/data/'
        if not os.path.exists(self.crashes_dir):
            os.mkdir(self.crashes_dir)

    def mutate(self, data):
        return random.choice([
            mutate_bit_flip,
            mutate_byte_random,
            mutate_byte_flip,
            mutate_byte_insert,
            mutate_byte_delete,
            mutate_byte_operation,
            mutate_duplicate,
            mutate_buffer_overflow,
            mutate_magic
        ])(self.mutation_percentage, data[::])

    def run(self):
        process = subprocess.Popen(
            ["gdb", "--batch", "-x", "data/detect.gdb", self.executable],
            stdout = subprocess.PIPE,
            stderr = None
        ) 
        output, _ = process.communicate()

        if "Program received signal" in output:
            return output.split("randomseparatorlol")[1]
        return None

    def fuzz(self):
        corpus = [
            load_file('input.sample', self.data_dir)
        ]

        i = 0
        while True:
            i += 1

            sys.stdout.write(".")
            sys.stdout.flush()  

            sample = self.mutate(random.choice(corpus))
            save_file('test.sample', sample, self.data_dir)
            corpus.append(sample)

            output = self.run()
            if output is not None:
                print "Crash " + str(i)
                save_file('input.%i' % i, sample, self.crashes_dir)
                save_file('log.%i' % i, output, self.crashes_dir)

"""
Example usage:

fuzzer = DumbFuzzer('bufferoverflow') # 'bufferoverflow' is the executable name
fuzzer.fuzz()

"""