#!/bin/env python3

from contextlib import contextmanager
import os
import os.path
import string

block_size = 4096
digest_size = 256 // 8  # sha256
hashes_per_block = 4096 // (256 // 8)

VALID_CHARS = frozenset(string.ascii_lowercase + '_-' + string.digits)

@contextmanager
def testfile(id):
    assert all(c in VALID_CHARS for c in id)
    # Ensure testfiles directory exists
    os.makedirs('testfiles', exist_ok=True)
    fn = 'testfiles/{}'.format(id)
    if os.path.exists(fn): os.unlink(fn)
    f = open(fn, 'wb')
    print("writing {}...".format(fn))
    yield f
    f.close()

with testfile('empty') as f:
    f.write(b'')

with testfile('onebyte') as f:
    f.write(b'A')

with testfile('oneblock') as f:
    f.write(b'A' * block_size)

with testfile('oneblockplusonebyte') as f:
    f.write(b'A' * block_size + b'B')

for i in [-1, 0, 1]:
    for j in [-1, 0, 1]:
        with testfile('hashblock_{}_{}'.format(i, j)) as f:
            f.write(b'A' * (block_size * (hashes_per_block + i) + j))

with testfile('longfile') as f:
    size = hashes_per_block * hashes_per_block * block_size * 3 + 99
    data = b''
    while len(data) < size:
        print("size = {} / {}".format(len(data), size))
        data += ''.join('{:08x}'.format(len(data) + i) for i in range(0, 1024 * 1024 * 5, 8)).encode('ascii')
    data = data[:size]
    f.write(data)