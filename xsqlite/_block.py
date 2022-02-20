''' _block.py - module that deals with blocks of data within bitstream objects

Copyright (c) 2022 Netherlands Forensic Institute - MIT License
'''

from bitstring import BitStream as _BS
from collections import namedtuple as _nt
from functools import partial as _partial

# A block describes a small region in a bitstream.
_block = _nt('block', 'offset size data')


def _blockdata(btstr, offset, size):
    ''' Returns a slice of the given bitstream (byte sized) '''

    return _BS()+btstr[offset * 8:(offset+size)*8]


def block(btstr, offset, size):
    ''' Returns a block object based on the given offset and size.

    Blocks are byte-sized; both offset and size is defined in bytes, not bits.

    A block contains the following fields:

        - offset: the offset of the block within the bitstream
        - size: the size of the block
        - data: a function that returns a bitstream with the data when called.
    '''
    # check block sanity
    if size > 33554432:
        raise ValueError('blocksize limited to 32MB, use blocklist instead')

    endpos = offset + size

    if btstr.length < endpos * 8:
        raise ValueError('block ends outside bitstream')

    return _block(offset, size, _partial(_blockdata, btstr, offset, size))


def splitblock(blck, cut):
    ''' Splits a block in two blocks based on the given cut offset.

    Returns a tuple of two blocks. The byte at the cut-offset will be the first
    byte of the next block. '''

    # obtain the bitstream from the partial data function
    btstr = blck.data.args[0]

    r1 = block(btstr, blck.offset, cut)
    r2 = block(btstr, blck.offset + cut, blck.size - cut)
    return (r1, r2)


def blocklist_data(blocklist, blocksize=4096):
    ''' Generates a sequence of bitstreams from a list of blocks.

    Blocks in the blocklist may be of varying size. This function hands
    out bitstreams in units of the given blocksize (default 4096 bytes).

    The last block in this sequence may contain less than than blocksize bytes
    if no more blocks with enough data are available.
    '''

    blocksize = blocksize * 8

    cache = _BS()

    for blck in blocklist:
        # read a blck
        blockdata = blck.data()
        toread = blocksize - cache.len
        # fill cache until enough bytes available
        cache += blockdata[0:toread]
        # store remainder
        remainder = blockdata[toread:]

        # if we have enough in cache: yield
        if cache.len == blocksize:
            yield cache

            # empty the remainder when it's more than blocksize
            while remainder.len > blocksize:
                yield remainder[0:blocksize]
                remainder = remainder[blocksize:]

            # place the remainder in cache if it is less than blocksize
            cache = remainder

    # empty the cache
    yield cache


def allblocklistdata(blocklist):
    ''' Returns all data from blocks in blocklist in a single bitstream. '''

    # handle 32MB max at a time
    datagen = blocklist_data(blocklist, blocksize=33554432)
    alldata = _BS()
    for data in datagen:
        alldata += data
    return alldata
