def load_file(fname, path = ''):
    with open(path + fname, "rb") as f:
        return bytearray(f.read())

def save_file(fname, data, path = ''):
    with open(path + fname, "wb") as f:
        f.write(str(data))