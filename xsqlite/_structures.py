''' _structures - basic structures in the SQLite3 file format

Copyright (c) 2022 Netherlands Forensic Institute - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html
'''

from collections import namedtuple as _nt
from bitstring import BitStream as _BS

from ._block import block as _block


###################
# database header #
###################

_dbheader = _nt('database_header', 'headerstring pagesize writeversion '
                'readversion reservedspace maxpayloadfraction '
                'minpayloadfraction leafpayloadfraction filechangecounter '
                'dbsize firstfreelisttrunkpage totalfreelistpages '
                'schemacookie schemaformat defaultpagecachesize '
                'largestrootbtreepage textencoding userversion '
                'vacuummode reserved validfor version '
                'usablepagesize externalsize inheadersizevalid')


def dbheader(btstr, offset=0):
    ''' Parses the database header at given offset in bitstream.

    A database_header contains the following fields:

        - headerstring: The header string 'SQLite format 3[0x00]'
        - pagesize: The database page size in bytes. Size 1 means 65536
        - writeversion: file format write version. 1 for legacy; 2 for WAL.
        - readversion: file format read version. 1 for legacy; 2 for WAL.
        - reservedspace: Bytes of unused "reserved" space at the end of
           each page. Usually 0.
        - maxpayloadfraction: maximum embedded payload fraction
        - minpayloadfraction: minimum embedded payload fraction
        - leafpayloadfraction: Leaf payload fraction
        - filechangecounter: File change counter. Note: the change counter
           might not be incremented on each transaction in WAL mode.
        - dbsize: Size of the database file in pages, a.k.a. the "in-header
          database size"
        - firstfreelisttrunkpage: Page number of the first freelist trunk page.
        - totalfreelistpages: Total number of freelist pages.
        - schemacookie: The schema cookie.
        - schemaformat: The schema format number.
        - defaultpagecachesize: Default page cache size.
        - largestrootbtreepage: The page number of the largest root b-tree page
           when in auto- or incremental vacuum mode, zero otherwise.
        - textencoding: The database text encoding.
        - userversion: The "user version" as read and set by the user_version
           pragma. Not used by SQLite internally.
        - vacuummode: True (non-zero) for incremental-vacuum mode.  False
           (zero) otherwise.
        - reserved: 24 bytes reserved for expansion. Must be zero.
        - validfor: The version-valid-for number (?)
        - version: SQLITE_VERSION_NUMBER field (?)
        - usablepagesize: calculated usable page size
        - externalsize: calculated size of database in pages based on bitstream
           size (may be wrong if only sub bitstream was passed into function).
        - inheadersizevalid: indicates if in-header database size is valid
    '''

    # the encoding of the database

    # Note: while only the encodings 1 through 3 are allowed per the
    # documentation on the sqlite3 website. We have found several
    # databases with encoding 0. After some searching through the
    # sqlite3 amalgamation source we found the following:
    #
    # 109621       if( encoding==0 ) encoding = SQLITE_UTF8;
    #
    # Thus, an encoding of 0 is also allowed and indicates UTF8

    _encoding = {0: 'utf-8',
                 1: 'utf-8',
                 2: 'utf-16le',
                 3: 'utf-16be'}

    # remember current position and read the bytes
    storepos = btstr.bytepos
    btstr.bytepos = offset
    headerstring = btstr.read('bytes:16').decode('utf-8')
    pagesize = btstr.read('uintbe:16')
    # pagesize 1 is a special value indicating pagesize 65536
    if pagesize == 1:
        pagesize = 65536
    writeversion, readversion = btstr.readlist('uint:8, uint:8')
    reservedspace = btstr.read('uint:8')
    maxpayloadfraction = btstr.read('uint:8')
    minpayloadfraction = btstr.read('uint:8')
    leafpayloadfraction = btstr.read('uint:8')
    filechangecounter = btstr.read('uintbe:32')
    dbsize = btstr.read('uintbe:32')
    firstfreelisttrunkpage = btstr.read('uintbe:32')
    totalfreelistpages = btstr.read('uintbe:32')
    schemacookie = btstr.read('uintbe:32')
    schemaformat = btstr.read('uintbe:32')
    defaultpagecachesize = btstr.read('uintbe:32')
    largestrootbtreepage = btstr.read('uintbe:32')
    textencoding = _encoding[btstr.read('uintbe:32')]
    userversion = btstr.read('uintbe:32')
    vacuummode = bool(btstr.read('uintbe:32'))
    reserved = btstr.read('uintbe:192')
    validfor = btstr.read('uintbe:32')
    version = btstr.read('uintbe:32')
    # after reading, reset pointer
    btstr.bytepos = storepos

    # define calculated properties
    usablepagesize = pagesize - reservedspace
    # NOTE: externalsize may be wrong if only a sub bitstream was passed
    externalsize = int(btstr.length / 8 / pagesize)

    # The 'in header database size' is only valid if it is nonzero
    # and if the filechange counter matches the validfor number.
    inheadersizevalid = True
    if dbsize == 0 or filechangecounter != validfor:
        inheadersizevalid = False

    # validation
    if headerstring != 'SQLite format 3\x00':
        raise ValueError('header string should be SQLite format 3\x00')
    if pagesize not in [1] + [512 * i for i in range(1, 65)]:
        raise ValueError('pagesize must be a power of two between 512 '
                         'and 32768 inclusive or the value 1 to represent '
                         'page size of 65536')
    if writeversion not in [1, 2]:
        raise ValueError('write version should be 1 or 2')
    if readversion not in [1, 2]:
        raise ValueError('read version should be 1 or 2')
    if maxpayloadfraction != 64:
        raise ValueError('Max embedded payload fraction != 64')
    if minpayloadfraction != 32:
        raise ValueError('Min embedded payload fraction != 32')
    if leafpayloadfraction != 32:
        raise ValueError('Leaf payload fraction must != 32')
    # NOTE: the schema format is only allowed to be 1 through 4,
    # but similar to the encoding field, the actual sqlite3
    # source is a bit more relaxed with it's constraint. In the
    # amalgamation we find:
    #
    # 109651   /*
    # 109652   ** file_format==1    Version 3.0.0.
    # 109653   ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
    # 109654   ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
    # 109655   ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
    # 109656   */
    # 109657   pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
    # 109658   if( pDb->pSchema->file_format==0 ){
    # 109659     pDb->pSchema->file_format = 1;
    # 109660   }
    #
    # Thus, we allow schemaformat 0 as well.
    #
    # Also note that the schemaformat is not used in any way in the rest of
    # xsqlite's parsing and interpretation.
    if schemaformat not in [0, 1, 2, 3, 4]:
        raise ValueError('Supported schema formats are 1,2,3,4')
    if reserved != 0:
        raise ValueError('Space used for expansion should be zero.')
    if externalsize % 1 != 0:
        raise ValueError('db size should be multiple of page size.')

    return _dbheader(headerstring, pagesize, writeversion,
                     readversion, reservedspace, maxpayloadfraction,
                     minpayloadfraction, leafpayloadfraction,
                     filechangecounter, dbsize, firstfreelisttrunkpage,
                     totalfreelistpages, schemacookie, schemaformat,
                     defaultpagecachesize, largestrootbtreepage,
                     textencoding, userversion, vacuummode, reserved,
                     validfor, version, usablepagesize,
                     externalsize, inheadersizevalid)


##############
# pageheader #
##############

_pageheader = _nt('btree_pageheader',
                  'pagetype first_freeblock_offset cellcount '
                  'cell_content_offset fragmented_freebyte_count '
                  'rightmost_pointer size')


def _pagetype(number):
    ''' Returns pagetype name for given pagetype number.

    There are four b-tree pagetypes defined:

        - table_interior : A table b-tree interior page
        - table_leaf     : A table b-tree leaf page
        - index_interior : An index b-tree interior page
        - index_leaf     : An index b-tree leaf page
    '''

    typemap = {
        2: 'index_interior',
        5: 'table_interior',
        10: 'index_leaf',
        13: 'table_leaf'
        }

    if number in typemap:
        return typemap[number]
    else:
        raise ValueError('invalid b-tree page type {:d}'.format(number))


def pageheader(btstr, offset, usablepagesize):
    ''' Interprets bytes at offset as btree pageheader.

    A btree_pageheader object contains the following fields:

        - pagetype: the type of b-tree page as defined in _pagetype
        - first_freeblock_offset: relative offset of the first freeblock.
        - cellcount: number of cells on this page.
        - cell_content_offset: relative offset of cell content area.
        - fragmented_freebyte_count: total number of fragmented free bytes.
        - rightmost_pointer: the right-most pointer for interior pages.
        - size: the size of the btree_pageheader
    '''

    # move to header offset
    storepos = btstr.bytepos
    btstr.bytepos = offset

    # parse first 8 bytes
    hsize = 8
    header = btstr.readlist('uint:8, uintbe:16, uintbe:16, uintbe:16, uint:8')
    pgtype, first_freeblock, cellcount, cellarea, freebytes = header
    # in some fields (including this one), value 0 means 65536
    if cellarea == 0:
        cellarea = 65536
    # replace parsed values with interpreted values
    pgtype = _pagetype(pgtype)

    # interior pages have a rightmost pointer
    rmp = None
    if pgtype in ['index_interior', 'table_interior']:
        rmp = btstr.read('uintbe:32')
        hsize += 4

    # restore offset
    btstr.bytepos = storepos

    if first_freeblock > usablepagesize:
        raise ValueError('first freeblock offset outside usable page area.')
    if cellarea > usablepagesize:
        raise ValueError('cell content area offset outside usable page area.')
    if freebytes > (usablepagesize - cellarea):
        raise ValueError('free byte count exceeds cell content area size.')

    return _pageheader(pgtype, first_freeblock, cellcount,
                       cellarea, freebytes, rmp, hsize)


##############
# btree page #
##############

_btreepage = _nt('btree_page', 'pagetype header cellpointer_area '
                               'cells rowidmap freeblocks unallocated '
                               'reserved size')


def btree_page(btstr, offset, pagesize, usablepagesize, isheaderpage=False):
    ''' Parses the page at the given offset as btree page.

    A btree_page object has the following fields:

        - pagetype: one of the four pagetypes defined in pagetype function
        - header: the btree_pageheader object for the current page
        - cellpointer_area: the cellpointer_area object for the current page
        - cells: a list of cell objects (see cell.py)
        - rowidmap: {rowid:cellnumber} for table_leaf pages, None otherwise
        - freeblocks: a list of freeblock objects for this page
        - unallocated: the unallocated object for this page
        - reserved: the reserved area for this page or None if not defined
        - size: the page size (passed in as variable)
    '''

    # some parsing functionality work on bytes array instead of bitstream
    bytes_ = btstr.bytes

    # parse the pageheader
    hoffset = offset
    if isheaderpage is True:
        hoffset += 100
    pgheader = pageheader(btstr, hoffset, usablepagesize)

    # parse the cell pointer area (directly after the pageheader)
    cpa = cellpointer_area(btstr, hoffset + pgheader.size, pgheader.cellcount)

    # parse the cells
    cells = [cell(btstr, bytes_, offset + cp, pgheader.pagetype,
                  usablepagesize) for cp in cpa.cellpointers]

    # add rowid to cell number map for this page if it is table leaf
    rowidmap = None
    if pgheader.pagetype == 'table_leaf':
        rowidmap = {cells[i].rowid: i for i in range(len(cells))}

    # unallocated space runs from end of last cellpointer to cell content area
    cpa_offset = hoffset + pgheader.size
    cpa_size = pgheader.cellcount * 2
    # calculate size and offset of unallocated area
    usize = pgheader.cell_content_offset - (cpa_offset + cpa_size)
    uoffset = cpa_offset + cpa_size
    unalloc = _block(btstr, uoffset, usize)

    # collect the freeblocks on this page
    fblocks = []
    fboffset = pgheader.first_freeblock_offset
    while fboffset != 0:
        fblock = freeblock(btstr, offset + fboffset)
        fboffset = fblock.next_freeblock
        fblocks.append(fblock)

    # reserved area runs from end of cell content area to end of page
    res = None
    if pagesize > usablepagesize:
        res = _block(btstr, offset + usablepagesize,
                     pagesize - usablepagesize)

    return _btreepage(pgheader.pagetype, pgheader, cpa, cells, rowidmap,
                      fblocks, unalloc, res, pagesize)


####################
# cellpointer area #
####################

_cellpointerarea = _nt('cellpointer_area',
                       'cellpointers size')


def cellpointer_area(btstr, offset, cellcount):
    ''' Interprets bytes at offset as cell pointer area with cellcount cells.

    A cellpointer_area object contains the following fields:

        - cellpointers: a list of cell pointers
        - size: size of the cell pointer area
    '''

    # store current position
    oldpos = btstr.bytepos
    btstr.bytepos = offset
    # parse proper amount of cell pointers
    cpointers = btstr.readlist(cellcount * 'uintbe:16,')
    # cellpointer value 0 means 65536
    cpointers = [65536 if p == 0 else p for p in cpointers]
    # restore position in btstr
    btstr.bytepos = oldpos
    # cell pointer is two bytes wide
    cpa_size = cellcount * 2
    return _cellpointerarea(cpointers, cpa_size)


########
# cell #
########


def cell(btstr, bytes_, offset, pagetype, usablepagesize):
    ''' Parses a single cell at the given offset depending on pagetype. '''

    # cell structure varies for different page types
    if pagetype == 'table_leaf':
        return _tableleaf_cell(btstr, bytes_, offset, usablepagesize)
    elif pagetype == 'index_leaf':
        return _indexleaf_cell(btstr, bytes_, offset, usablepagesize)
    elif pagetype == 'index_interior':
        return _indexinterior_cell(btstr, bytes_, offset, usablepagesize)
    elif pagetype == 'table_interior':
        return _tableinterior_cell(btstr, bytes_, offset)
    else:
        raise ValueError('unknown pagetype when trying to parse cells')


def _inline_payload_size(celltype, payloadsize, usablepagesize):
    ''' Calculates the inline size for the given payloadsize. '''

    if celltype not in ['table', 'index']:
        raise ValueError("celltype should be 'table' or 'index'")

    # Table B-Tree Leaf Cell:
    # If the payload size P is less than or equal to U-35 then the entire
    # payload is stored on the b-tree leaf page. Let M be ((U-12)*32/255)-23.
    # If P is greater than U-35 then the number of byte stored on the b-tree
    # leaf page is the smaller of M+((P-M)%(U-4)) and U-35. Note that number of
    # bytes stored on the leaf page is never less than M.
    #
    # Index B-Tree Leaf Or Interior Cell:
    # Let X be ((U-12)*64/255)-23). If the payload size P is less than or equal
    # to X then the entire payload is stored on the b-tree page. Let M be
    # ((U-12)*32/255)-23. If P is greater than X then the number of byte stored
    # on the b-tree page is the smaller of M+((P-M)%(U-4)) and X. Note that
    # number of bytes stored on the index page is never less than M.

    P = payloadsize
    U = usablepagesize

    # code rounds down (used to have math.ceil here) by casting to u16.
    # c-test: (unsigned short int) 3.9652 --> result = 3
    # --> this is same as int() in Python
    M = int(((U - 12) * 32 / 255) - 23)   # (minLocal and minLeaf)

    if celltype is 'table':
        X = U - 35                           # (maxLeaf)
    elif celltype is 'index':
        # see note on rounding above
        X = int(((U - 12) * 64 / 255) - 23)  # (maxLocal)

    if P <= X:
        return P
    else:
        istore = M + ((P - M) % (U - 4))
        if istore <= X:
            return istore
        else:
            # NOTE: in btree.c size is set to minLocal in this case,
            # which is essentially M, whereas the documentation on
            # the fileformat says X here. Used M instead, docs seem wrong!
            return M


_table_leaf_cell = _nt('table_leaf_cell',
                       'payloadsize rowid first_overflow_page inline_payload '
                       'size')


def _tableleaf_cell(btstr, bytes_, offset, usablepagesize):
    ''' Returns a table_leaf_cell object for the bytes at the given offset.

    A table_leaf_cell contains the following fields:

        - payloadsize: the size of all payload, including overflow
        - rowid: rowid of the cell
        - first_overflow_page: page number of first overflow page (or None)
        - inline_payload: the inline part of the payload
        - offset: offset of the cell within the bitstream
        - size: size of the cell within the bitstream
    '''

    # table B-Tree leaf cell starts with payloadsize and rowid
    payloadsize, payloadsize_width = varint(bytes_, offset)
    rowid, rowid_width = varint(bytes_, offset + payloadsize_width)

    # determine dimensions and location of inline payload
    ipsize = _inline_payload_size('table', payloadsize, usablepagesize)
    payloadstart = payloadsize_width + rowid_width

    # set inline payload block
    payload = _block(btstr, offset + payloadstart, ipsize)

    # determine size of the cell structure so far
    cellsize = payloadsize_width + rowid_width + ipsize

    # if the payload overflows, we need to read first overflow page pointer
    fop = None
    if payloadsize > ipsize:
        # read 4 byte integer for first overflow page (fop)
        storepos = btstr.bytepos
        btstr.bytepos = offset + cellsize
        fop = btstr.read('uintbe:32')
        btstr.bytepos = storepos
        cellsize += 4

    return _table_leaf_cell(payloadsize, rowid, fop, payload, cellsize)


_table_interior_cell = _nt('table_interior_cell',
                           'left_child_pointer key size')


def _tableinterior_cell(btstr, bytes_, offset):
    ''' Returns a table_interior_cell object for the bytes at the given offset.

    A table_interior_cell contains the following fields:

        - left_child_pointer: left child pointer (pagenumber)
        - key: integer key
        - size: size of the cell
    '''

    # read left child pointer
    storepos = btstr.bytepos
    btstr.bytepos = offset
    lcp = btstr.read('uintbe:32')
    btstr.bytepos = storepos
    # read the varint key
    key, key_width = varint(bytes_, offset + 4)
    cellsize = 4 + key_width
    return _table_interior_cell(lcp, key, cellsize)


_index_leaf_cell = _nt('index_leaf_cell',
                       'payloadsize first_overflow_page inline_payload '
                       'size')


def _indexleaf_cell(btstr, bytes_, offset, usablepagesize):
    ''' Returns an index_leaf_cell object for the bytes at the given offset.

    An index_leaf_cell contains the following fields:

        - payloadsize: the total payloadsize, including overflow
        - first_overflow_page: page number of first overflow page (or None)
        - inline_payload: the inline part of the payload
        - size: size of the cell within the bitstream
    '''

    # index B-Tree leaf cell starts with payloadsize
    payloadsize, payloadsize_width = varint(bytes_, offset)

    # determine dimensions and location of inline payload
    ipsize = _inline_payload_size('index', payloadsize, usablepagesize)
    payloadstart = payloadsize_width

    # define inline payload block
    payload = _block(btstr, offset + payloadstart, ipsize)

    # determine size of the cell structure so far
    cellsize = payloadsize_width + ipsize

    # if the payload overflows, we need to read first overflow page pointer
    slack, overflowpages, fop = (None, ) * 3
    if payloadsize > ipsize:
        # read 4 byte integer for first overflow page (fop)
        storepos = btstr.bytepos
        btstr.bytepos = offset + cellsize
        fop = btstr.read('uintbe:32')
        btstr.bytepos = storepos
        cellsize += 4

    return _index_leaf_cell(payloadsize, fop, payload, cellsize)


_index_interior_cell = _nt('index_interior_cell',
                           'left_child_pointer payloadsize '
                           'first_overflow_page inline_payload '
                           'size')


def _indexinterior_cell(btstr, bytes_, offset, usablepagesize):
    ''' Returns an index_interior_cell object for bytes at given offset.

    An index_interior_cell contains the following fields:

        - left_child_pointer: left child pointer (pagenumber)
        - payloadsize: the total payloadsize, including overflow
        - first_overflow_page: page number of first overflow page (or None)
        - inline_payload: the inline part of the payload
        - size: size of the cell within the bitstream
    '''

    # read left child pointer
    storepos = btstr.bytepos
    btstr.bytepos = offset
    lcp = btstr.read('uintbe:32')
    btstr.bytepos = storepos

    # index B-Tree interior cell has payloadsize at offset 4
    payloadsize, payloadsize_width = varint(bytes_, offset + 4)

    # determine dimensions and location of inline payload
    ipsize = _inline_payload_size('index', payloadsize, usablepagesize)
    payloadstart = payloadsize_width + 4

    # define inline payload block
    payload = [_block(btstr, offset + payloadstart, ipsize)]

    # determine size of the cell so far
    cellsize = payloadsize_width + ipsize + 4

    # if the payload overflows, we need to read first overflow page pointer
    slack, overflowpages, fop = (None, ) * 3
    if payloadsize > ipsize:
        # read 4 byte integer for first overflow page (fop)
        storepos = btstr.bytepos
        btstr.bytepos = offset + cellsize
        fop = btstr.read('uintbe:32')
        btstr.bytepos = storepos
        cellsize += 4

    return _index_interior_cell(lcp, payloadsize, fop, payload, cellsize)


##########
# varint #
##########


def varint(bytes_, offset, maxwidth=9):
    ''' Read a single varint form the given bytes_ at given offset

    The maxwidth argument is added to prevent reading very large varints, which
    is only realistic for the rowid of tables with many rows or for columns that
    contain very large TEXT or BLOB values. A value of 5 seems a reasonable max
    when parsing recordheader serialtypes.

    However, when maxwidth is not 9, the decoding of varints dictates that
    the upperbit of the last byte must be 0. Otherwise the varint decoder
    would proceed and try to read another byte. So in this case we raise a
    ValueError

    Returnvalue is the varint value and it's width in bytes
    '''

    # read and decode the varint
    value = 0
    for idx in range(0, maxwidth):
        # read a byte
        val = bytes_[offset+idx]
        upperbit = val >> 7
        if idx == 8:
            # all bits of the 9th byte are included
            value = value << 8
            value += val
        else:
            # only the lower 7 bits of the byte are included
            value = value << 7
            value += val & 0x7f
        if upperbit == 0:
            # stop when the upperbit is zero
            break
        elif idx == (maxwidth - 1) and idx != 8:
            # The upperbit dictates that we should read another
            # byte, but this would exceed the given maxwidth.
            # Thus, this would lead to an incorrectly parsed varint
            raise ValueError("given maxwidth prevents proper parsing of varint")
        if idx > 8:
            break

    # return varint and width
    return value, idx+1


def varints(bytes_, offset, bytecount, limit=None, maxwidth=9):
    ''' Interprets bytecount bytes at given offset as varints.

    Returns a list of varint values. When limit is set, decoding varints
    is aborted after 'limit' varints have been found. Raises an exception if
    the last varint that has been read exceeds the bytecount boundary.  The maxwidth
    argument is passed onto the varint function to limit the width of each individual
    varint to this maximum, which is usefull when parsing recordheader serialtypes
    '''

    if bytecount <= 0:
        return []

    pos = offset
    endpos = offset + bytecount

    # check if amount of bytes is available
    if endpos > len(bytes_):
        raise ValueError('not enough bytes available')


    results = []
    while True:
        if len(results) == limit:
            # stop if we have read enough varints
            break

        if pos == endpos:
            # stop if we have read the desired amount of bytes
            break

        if pos > endpos:
            # the last varint has moved us beyond desired amount of bytes
            raise ValueError("last varint required reading extra bytes")

        # read the varint and append to the list
        value, width = varint(bytes_, pos, maxwidth)
        results.append((value, width))
        pos += width

    return results


def tovarint(number):
    ''' Creates a bitstream object with the given number as varint. '''

    if number >= 2**64:
        raise ValueError('max varint is 2**64-1')

    val = 0
    count = 0
    upper = 0

    if number >= 2**56:
        # need all 9 bytes, lower is full
        val = number & 0xff
        number >>= 8
        count = 1
        upper = 0x80
    elif number == 0:
        val = 0
        count = 1

    while count < 9 and number > 0:
        val += (number & 0x7f | upper) << count * 8
        number >>= 7
        count += 1
        upper = 0x80

    return _BS(uintbe=val, length=count*8)


#################
# record format #
#################

_recordformat = _nt('recordformat', 'header body')


def recordformat(btstr, offset):
    ''' Returns a recordformat object by parsing data in given bitstream

    A recordformat object consists of the following fields:

        - header: a recordheader object
        - body: a list of column data fields as one of 5 storage classes

    The payload is a list of blocks in the given bitstream that together
    describe the location of the payload.

    TEXT and BLOB values are currently fully expanded in the returned object.
    This can be a problem when stored TEXT or BLOB values are very large.
    '''

    bytes_ = btstr.bytes

    recheader = recordheader(bytes_, offset)
    bodyoffset = recheader.headersize + offset
    body = recordbody(btstr, bodyoffset, recheader)
    return _recordformat(recheader, body)


#################
# record header #
#################

_recordheader = _nt('recordheader', 'headersize serialtypes')


def recordheader(bytes_, offset):
    ''' Parses the bytes at given offset as recordheader.

    A recordheader object consists of the following fields:
        - headersize: the size of the header in the given bitstream
        - serialtypes: a list of serialtype numbers
    '''

    # parse and unpack headersize varint (value, varint_width)
    hsize, skip = varint(bytes_, offset)

    # default max number of columns is 2000 and each column may take
    # up to 5 bytes in record header (varint of 5 bytes is enough for
    # max size of individual columns)
    if hsize > 2000 * 5:
        raise ValueError('columns exceed default maximum.')

    # read varints in remaining header
    types_offset = offset+skip
    types_bytecount = hsize-skip

    serialtypes = varints(bytes_, types_offset, types_bytecount)
    # this function returns tuples, consisting of (varint_value, varint_width) pairs
    serialtypes = [i[0] for i in serialtypes]

    if len(serialtypes) <= 0:
        raise ValueError('empty list of serialtypes.')

    return _recordheader(hsize, serialtypes)


##############
# serialtype #
##############

_serialtype = _nt('serialtype', 'size storageclass parser')

# SQLite uses these 5 storage classes
_null = _nt('null', 'size value')
_integer = _nt('integer', 'size value')
_real = _nt('real', 'size value')
_text = _nt('text', 'size value')
_blob = _nt('blob', 'size value')

# The fixed-width types and the corresponding parser instruction
_fixedtypes = {0: _serialtype(0, _null, None),
               1: _serialtype(1, _integer, 'intbe:8'),
               2: _serialtype(2, _integer, 'intbe:16'),
               3: _serialtype(3, _integer, 'intbe:24'),
               4: _serialtype(4, _integer, 'intbe:32'),
               5: _serialtype(6, _integer, 'intbe:48'),
               6: _serialtype(8, _integer, 'intbe:64'),
               7: _serialtype(8, _real, 'floatbe:64'),
               8: _serialtype(0, _integer, None),
               9: _serialtype(0, _integer, None)}


def serialtype(stype):
    ''' returns a serialtype object based on the given typecode

    These properties are fully determined by the serialtype and are needed
    to determine the column value either by parsing bytes in the body or by
    using one of the fixed values (None, 0 or 1).

    Returnvalue: tuple of (size, storageclass, parsecommand)

    - size is the amount of bytes occupied in the body by the column
    - storageclass is one of the 5 storage classes
    - parsecommand is a string containing an instruction for the parser. '''

    if stype in [10, 11]:
        raise ValueError('reserved serialtype 10 or 11 encountered')
    elif type(stype) != int:
        raise ValueError('serialtype should be integer')
    elif stype < 0:
        raise ValueError('negative serialtype encountered')
    elif stype >= 12 and stype % 2 == 0:
        # BLOB of length (N-12) / 2
        size = int((stype - 12) / 2)
        return _serialtype(size, _blob, 'bytes:%d' % (size,))
    elif stype >= 13 and stype % 2 == 1:
        # STRING of length (N-13) / 2
        size = int((stype - 13) / 2)
        return _serialtype(size, _text, 'bytes:%d' % (size,))
    else:
        return _fixedtypes[stype]


###############
# record body #
###############


def recordbody(btstr, offset, recheader):
    ''' Parses the recordbody at given offset based on given recordheader.

    Returns a list of storage class objects for the various objects. Some
    serial types are not stored in the body, but are determined by the header.
    These have size 0. The following serial types are defined:

        - null: used for NULL column values
        - integer: used for INTEGER column values
        - real: used for REAL column values
        - text: used for TEXT column values
        - blob: used for BLOB column values

    Note that TEXT columns are not yet decoded, since it depends on the
    database text encoding, which this function is unaware of. Also, we want to
    use this function for recovery of partial records, which might not properly
    decode. So the bytes are returned as-is.
    '''

    # make list of sizes, storageclases and a parser command from serialtypes
    stypes = [serialtype(t) for t in recheader.serialtypes]
    sizes = [s[0] for s in stypes]
    sclasses = [s[1] for s in stypes]
    plist = [s[2] for s in stypes]
    pcommand = ','.join([p for p in plist if p is not None])

    # read data from bitstream and restore position
    storepos = btstr.pos
    btstr.pos = offset * 8
    parsedcolumns = btstr.readlist(pcommand)
    btstr.pos = storepos

    # add the non-space-consuming column values in the appropriate slots
    columns = []
    for i in range(len(recheader.serialtypes)):
        tc = recheader.serialtypes[i]
        sclass = sclasses[i]
        size = sizes[i]
        if tc == 0:
            val = None
        elif tc == 8:
            val = 0
        elif tc == 9:
            val = 1
        else:
            val = parsedcolumns.pop(0)
        columns.append(sclass(size, val))
    return columns


#############
# freeblock #
#############

_freeblock = _nt('freeblock', 'next_freeblock offset size block')


def freeblock(btstr, offset):
    ''' Interprets bytes at offset as freeblock.

    A freeblock contains the following fields:

        - next_freeblock : pointer to next freeblock in chain
        - offset: the offset of the freeblock
        - size: the freeblock size, including the header
        - block: a block object containing the freeblock data
    '''

    # store current position
    oldpos = btstr.bytepos
    # move to start of freeblock
    btstr.bytepos = offset
    # read next freeblock pointer and freeblocksize
    next_fb, size = btstr.readlist('uintbe:16, uintbe:16')
    # restore pos
    btstr.bytepos = oldpos
    # define a block for the data area
    fbdata = _block(btstr, offset + 4, size - 4)
    return _freeblock(next_fb, offset, size, fbdata)


################
# overflowpage #
################

_overflowpage = _nt('overflowpage', 'next_overflow_page payload '
                                    'reserved offset')


def overflowpage(btstr, offset, pagesize, usablepagesize):
    ''' Parses a page as overflowpage, returning an overflowpage object.

    An overflowpage contains the following fields:

        - next_overflow_page: pagenumber of next overflowpage or 0 (eoc)
        - payload: a block object containing the payload data function
        - reserved: the reserved area as block object or None
        - offset: the offset of the overflowpage

    Note that the last overflow page in a chain may not completely contain
    payload data. In other words, there may be slack in the chained overflow
    pages. This has to be determined by the caller, because for this
    cell-specific information is needed (the payloadsize).

    (Note that conceptually overflow is part of the cell)
    '''

    # read the next overflowpage pagenumber and restore btstr position
    storepos = btstr.bytepos
    btstr.bytepos = offset
    next_overflow_page = btstr.read('uintbe:32')
    btstr.bytepos = storepos

    # payload and reserved area
    payload = _block(btstr, offset + 4, usablepagesize - 4)
    # reserved area
    res = None
    if pagesize > usablepagesize:
        res = _block(btstr, offset + usablepagesize,
                         pagesize - usablepagesize)

    return _overflowpage(next_overflow_page, payload, res, offset)


#######################
# freelist trunk page #
#######################


_freelisttrunkpage = _nt('freelisttrunkpage',
                         'nextfreelisttrunkpage leafpointercount '
                         'freelistleafpointers unallocated reserved')


def freelisttrunkpage(btstr, offset, pagesize, usablepagesize):
    ''' Parses the page at the given offset as freelist trunk page.

    A freelist trunkpage contains the following fields:

        - nextfreelisttrunkpage: page number of the next freelist trunk page
        - leafpointercount: amount of pointers to freelist leaf pages.
        - freelistleafpointers: list of pointers to freelist leaf pages.
        - unallocated: unallocated space within the freelist trunk page.
        - reserved: the reserved space within the freelist trunk page.
    '''

    # leafpointers are 4 bytes wide
    lpsize = 4

    # read the fields
    storepos = btstr.bytepos
    btstr.bytepos = offset

    nextfreelisttrunkpage = btstr.read('uintbe:32')
    leafpointercount = btstr.read('uintbe:32')

    # NOTE: not sure if it should it be >= or >
    if leafpointercount * lpsize + 2 * lpsize >= usablepagesize:
        raise ValueError('page cannot hold that many leafpointers')

    flpointers = btstr.readlist('uintbe:32, ' * leafpointercount)

    # calculate and check current position in page
    fpstart = 8 + offset
    fpend = fpstart + leafpointercount * lpsize
    if btstr.bytepos != fpend:
        raise ValueError('bytepos inconsistency')

    # reset pointer
    btstr.bytepos = storepos

    # define unallocated and reserved blocks
    unallocated = _block(btstr, fpend, offset + usablepagesize - fpend)
    reserved = _block(btstr, offset + usablepagesize,
                          pagesize - usablepagesize)

    return _freelisttrunkpage(nextfreelisttrunkpage, leafpointercount,
                              flpointers, unallocated, reserved)


######################
# freelist leaf page #
######################

_freelistleafpage = _nt('freelistleafpage', 'unallocated reserved')


def freelistleafpage(btstr, offset, pagesize, usablepagesize):
    ''' Returns a freelistleafpage object.

    A freelist leafpage contains the following fields:

        - unallocated: unallocated space within the freelist trunk page.
        - reserved: the reserved space within the freelist trunk page.

    When a page ends up on the freelist, it either becomes a freelisttrunk page
    or a freelistleafpage. In the first case, parts of the page are
    overwritten. In the second case, the entire page is left as is, and it is
    merely made unreachable from the original position (either since the
    overflow pointers to the page are no longer valid, or because the page is
    removed from some btree.
    '''

    # define unallocated and reserved blocks
    unallocated = _block(btstr, offset, usablepagesize)
    reserved = _block(btstr, offset + usablepagesize,
                          pagesize - usablepagesize)

    return _freelistleafpage(unallocated, reserved)


################
# generic page #
################

_genericpage = _nt('genericpage', 'unallocated')


def genericpage(btstr, offset, pagesize):
    ''' Returns a genericpage object.

    An genericpage that can be used for pages that originate from various
    sources, such as superseded pages for which a more recent version exists
    in a WAL file, or from pages carved from memory dumps, for example. It
    treats the entire page a single unallocated area
    '''

    # define unallocated and reserved blocks
    unallocated = _block(btstr, offset, pagesize)

    return _genericpage(unallocated)


##################
# WAL structures #
##################

_walheader = _nt('wal_header', 'magic file_format_version pagesize checkpoint_sequence_number '
                               'salt1 salt2 checksum1 checksum2 checksum_endianness')


def _walchecksum(integers, s0=0, s1=0):
    ''' computes the crc for the given sequence of integers '''

    for i in range(0, len(integers), 2):
        s0 += integers[i] + s1
        # limit to lower 32 bits
        s0 = s0 & 0xffffffff
        s1 += integers[i+1] + s0
        # limit to lower 32 bits
        s1 = s1 & 0xffffffff
    return s0, s1


def walheader(btstr, offset=0):
    ''' Parses the WAL header at given offset in bitstream.

    A walheader contains the following fields:

        - magic: magic number Magic number. 0x377f0682 or 0x377f0683
        - file_format_version: File format version. Currently 3007000
        - pagesize: Database page size. Example: 1024
        - checkpoint_sequence: Checkpoint sequence number
        - salt1: random integer incremented with each checkpoint
        - salt2: a different random number for each checkpoint
        - checksum1: First part of a checksum on the first 24 bytes of header
        - checksum2: Second part of the checksum on the first 24 bytes of header
        - endianness: the endianness used in checksum computation
    '''

    # remember current position and read the bytes
    storepos = btstr.bytepos
    btstr.bytepos = offset
    magic = btstr.read('uintbe:32')

    # the endianness is only used in the checksum computation, the
    # values in the header are still
    if magic == 0x377f0683:
        endianness = 'big'
    elif magic == 0x377f0682:
        endianness = 'little'
    else:
        raise ValueError('unknown magic value encountered in WAL file')

    # compute the checksums
    btstr.bytepos = offset
    if endianness == 'little':
        integers = btstr.readlist(['uintle:32'] * 6)
    if endianness == 'big':
        integers = btstr.readlist(['uintbe:32'] * 6)

    calc_checksum1, calc_checksum2 = _walchecksum(integers)

    # move back to the position directy after the magic
    btstr.bytepos = offset + 4
    file_format_version = btstr.read('uintbe:32')

    if file_format_version != 3007000:
        raise ValueError('unexpected file format version in WAL file')

    pagesize = btstr.read('uintbe:32')

    if pagesize not in [2**i for i in range(9,17)]:
        raise ValueError('pagesize is not a power of two between 512 and 65536 inclusive')

    checkpoint_sequence_number = btstr.read('uintbe:32')
    salt1 = btstr.read('uintbe:32')
    salt2 = btstr.read('uintbe:32')
    checksum1 = btstr.read('uintbe:32')
    checksum2 = btstr.read('uintbe:32')

    # validation
    if calc_checksum1 != checksum1:
        raise ValueError('checksum1 in WAL header is incorrect')
    if calc_checksum2 != checksum2:
        raise ValueError('checksum2 in WAL header is incorrect')

    # after reading, reset pointer
    btstr.bytepos = storepos

    return _walheader(magic, file_format_version, pagesize,
                      checkpoint_sequence_number, salt1,
                      salt2, checksum1, checksum2, endianness)


_wal_frame_header = _nt('wal_frame_header', 'pagenumber commit_page_count salt1 salt2 '
                                            'checksum1 checksum2')


def walframeheader(btstr, offset=0):
    ''' Parses the WAL frame header at given offset in bitstream.

    A walheader contains the following fields:

        - pagenumber: Page number
        - commit_page_count: For commit records, the size of the database file in pages after the
                             commit. For all other records, zero.
        - salt1: Salt-1 copied from the WAL header
        - salt2: Salt-2 copied from the WAL header
        - checksum1: Cumulative checksum up through and including this page
        - checksum2: Second half of the cumulative checksum
    '''

    # remember current position and read the bytes
    storepos = btstr.bytepos
    btstr.bytepos = offset

    pagenumber = btstr.read('uintbe:32')
    commit_page_count = btstr.read('uintbe:32')
    salt1 = btstr.read('uintbe:32')
    salt2 = btstr.read('uintbe:32')
    checksum1 = btstr.read('uintbe:32')
    checksum2 = btstr.read('uintbe:32')

    # after reading, reset pointer
    btstr.bytepos = storepos

    return _wal_frame_header(pagenumber, commit_page_count, salt1, salt2, checksum1, checksum2)
