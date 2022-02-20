''' database.py - functionality related to sqlite3 database files

Copyright (c) 2022 Netherlands Forensic Institute - MIT License

The implementation of the structures and the logic is based on the description
of the database format as given on: https://www.sqlite.org/fileformat.html

NOTE: indices, views and triggers are not implemented. WITHOUT ROWID tables are
also not implemented. WAL support is implemented, but JOURNAL support is not. '''

from collections import namedtuple as _nt
from collections import OrderedDict as _OD
from functools import partial as _partial
from bitstring import ConstBitStream as _CB
import os.path as _path
from os import stat as _stat
from enum import Enum as _Enum

from . import _exceptions
from . import _structures
from . import _block
from . import _sql
from . import _decode


class Database():
    ''' class representing a SQLite3 database, optionally including wal or journal file '''


    def __init__(s, infile, wal=None, journal=None):
        ''' open the given file as Database object, optionally including wal or journal file

        infile, wal and journal can be filepath (string) or an already opened file-like objects

        If wal or journal are not given, we try to detect if a WAL or journal file exists
        in the same directory as the main database file.
        '''

        if wal is not None and journal is not None:
            raise _exceptions.InvalidArgumentException("only one of wal or journal can be given")

        if isinstance(infile, str):
            # parse the file as constant bitstream
            s.filename = _path.abspath(_path.expanduser(infile))
            s.bitstream = _CB(filename=s.filename)
        else:
            # read the bytes from the file as constant bitstream
            s.filename = None
            s.bitstream = _CB(bytes=infile.read())

        if wal is not None:
            if isinstance(wal, str):
                # parse the file as constant bitstream
                walfilename = _path.abspath(_path.expanduser(wal))
                if _stat(walfilename).st_size != 0:
                    walbitstream = _CB(filename=walfilename)
                    s.walfile = WalFile(walfilename, walbitstream)
            else:
                # read the bytes from the file as constant bitstream
                walfilename = None
                walbitstream = _CB(bytes=wal.read())
                s.walfile = WalFile(walfilename, walbitstream)
        else:
            # check if a WAL file exists in the same directory as the main db file
            if s.filename is not None:
                dirname = _path.dirname(s.filename)
                basename = _path.basename(s.filename)
                walpath = _path.join(dirname, basename+'-wal')
                if _path.exists(walpath):
                    walfilename = walpath
                    if _stat(walfilename).st_size != 0:
                        walbitstream = _CB(filename=walfilename)
                        s.walfile = WalFile(walfilename, walbitstream)

        if journal is not None:
            if isinstance(journal, str):
                # parse the file as constant bitstream
                s.journalfilename = _path.abspath(_path.expanduser(journal))
                s.journalbitstream = _CB(filename=s.journalfilename)
            else:
                # read the bytes from the file as constant bitstream
                s.journalfilename = None
                s.journalbitstream = _CB(bytes=journal.read())
        else:
            # check if a journal file exists in the same directory as the main db file
            if s.filename is not None:
                dirname = _path.dirname(s.filename)
                basename = _path.basename(s.filename)
                journalpath = _path.join(dirname, basename+'-journal')
                if _path.exists(journalpath):
                    s.journalfilename = journalpath
                    s.journalbitstream = _CB(filename=s.journalfilename)


        if hasattr(s, 'walfile') and hasattr(s, 'journalbitstream'):
            raise ValueError('database appears to have a WAL and a journal file!')

        # parse the header at offset 0
        s.header = _structures.dbheader(s.bitstream, offset=0)

        if hasattr(s, 'walfile'):
            if s.header.pagesize != s.walfile.pagesize:
                raise _exceptions.AssumptionBrokenException("wal and main db disagree on pagesize")

        # check if the header indicates wal mode or not
        if s.header.writeversion == 2 and s.header.readversion == 2:
            s.walmode = True
        elif s.header.writeversion != s.header.readversion:
            raise _exceptions.AssumptionBrokenException("writeversion and readversion differ")
        else:
            s.walmode = False

        # check if total freelistpages match header
        total_freelist_pages = len(list(s.freelist_pages()))
        if s.header.totalfreelistpages != total_freelist_pages:
            if hasattr(s, 'walfile'):
                # in this case, it might be the case that the
                # header has not yet been updated since there is
                # still a checkpoint operation to be done.
                pass
            else:
                raise ValueError('total nr of freelistpages incorrect')

        # parse sqlite_master table (stored in btree starting in page 1)
        s.sqlite_master = SQLiteMaster(s.rowidrecords(1), s.header.textencoding)

        # create table objects for each of the defined tables
        s.tables = _OD()
        for tbl_name, sqlite_master_rec in s.sqlite_master.tables.items():
            if sqlite_master_rec.virtual is True:
                # skip VIRTUAL TABLEs
                continue
            tbl = Table(sqlite_master_rec, s.header.textencoding)
            s.tables[tbl_name] = tbl

        # add a list of tablenames for convenience
        s.tablenames = [n for n in s.tables.keys()]


    def get_pageoffset(s, pagenumber):
        ''' function that returns the offset of the page with given pagenumber
        '''

        if pagenumber < 1:
            raise _exceptions.InvalidArgumentException('pagenumbers start at 1 in SQLite fileformat')

        # if the page is an active page in the WAL file, return the WAL frame contents offset
        if s.page_is_in_wal(pagenumber):
            walframe = s.walfile.get_page_frame(pagenumber)
            return walframe.contents_block.offset

        if s.header.inheadersizevalid and pagenumber > s.header.dbsize:
            raise _exceptions.InvalidArgumentException('pagenumber points beyond EOF')

        if not s.header.inheadersizevalid and pagenumber > s.header.externalsize:
            raise _exceptions.InvalidArgumentException('pagenumber points beyond EOF')

        return (pagenumber - 1) * s.header.pagesize


    def get_page_data(s, pagenumber):
        ''' function that returns the page as block object '''

        # first check if we should get the page from the main database or from the WAL
        if hasattr(s, 'walfile'):
            walframe = s.walfile.get_page_frame(pagenumber)
            if walframe is not None:
                return walframe.contents_block

        return _block.block(s.bitstream, s.get_pageoffset(pagenumber), s.header.pagesize)


    def page_is_in_wal(s, pagenumber):
        ''' return True if page is in WAL file, False otherwise '''

        if hasattr(s, 'walfile'):
            walframe = s.walfile.get_page_frame(pagenumber)
            if walframe is not None:
                return True
        return False


    def get_btreepage(s, pagenumber):
        ''' Parse given page as btree page and return a parsed page

        A page object is a simple object combining a pagenumber, pageoffset and a
        parsed page. This function is a wrapper for _structures.btree_page.
        '''

        pageblock = s.get_page_data(pagenumber)
        pagesize = pageblock.size
        btstr = pageblock.data()
        pageoffset = s.get_pageoffset(pagenumber)

        # start with the page with the given pagenumber
        isheaderpage = False
        if pagenumber == 1:
            isheaderpage = True

        # use offset 0 here, since btstr contains only the single page to be parsed
        page = _structures.btree_page(btstr, 0, s.header.pagesize, s.header.usablepagesize, isheaderpage)
        from_wal = s.page_is_in_wal(pagenumber)
        return Page(btstr, page, pagenumber, pageoffset, from_wal)


    def get_page_by_rowid(s, rootpagenumber, rowid):
        ''' Returns the page that should contain the record with the given rowid.

        The term 'should' is chosen deliberately: When a record is removed it is no longer
        accessible on the corresponding page, but when navigating the tree you still end up on the
        same page. Also, when you start the search on a page that is in the wrong subtree, you will
        end up with the wrong page altogether, so you should call this with the root page of the
        table that you are interested in. Finally, if the rowid is larger than the highest stored
        rowid, you will receive the last page in the btree, regardless of whether or not the rowid
        is actually stored there.

        Uses the btreepage function to return a page object, see documentation there for details on
        the returnvalue.  '''

        rootpage = s.get_btreepage(rootpagenumber)

        if rootpage.page.pagetype not in ['table_leaf', 'table_interior']:
            raise _exceptions.InvalidArgumentException('need the pagenumber of a table page')

        if rootpage.page.pagetype == 'table_leaf':
            return rootpage

        if rootpage.page.pagetype == 'table_interior':
            if rowid > rootpage.page.cells[-1].key:
                # go right: rmp points to subtree were keys are > cells[-1].key
                return s.get_page_by_rowid(rootpage.page.header.rightmost_pointer, rowid)
            else:
                # go left :leftpointer points to pages were all keys are <= key
                # from documentation: pointers to the left of a X refer to b-tree
                # pages on which all keys are less than or equal to X.
                for cell in rootpage.page.cells:
                    lp = cell.left_child_pointer
                    if rowid <= cell.key:
                        return s.get_page_by_rowid(lp, rowid)


    def treewalker(s, rootpagenumber):
        ''' Generates a sequence of btree pages for a given btree-page object. The
        generated sequence represents the subtree under the given page. Both
        the interior and the leaf table pages are returned so that this can be used
        for both index and table trees (index pages contain data, especially for
        WITHOUT_ROWID tables). Normally one should call this with the rootpage of a
        table or index, but you can also start at a lower level in the tree.

        Pages from subtrees are yielded in the same order as they are stored in the
        b-tree, so natural ordering by the table's key (mostly rowid) is honoured.
        The interior pages are yielded prior to descending into the subtree defined
        by the corresponding interior page.

        Uses the get_btreepage function to yield a page object, see documentation
        there for details on the returnvalue.
        '''

        # start with the rootpage
        btpage = s.get_btreepage(rootpagenumber)

        yield btpage

        if btpage.page.pagetype in ['table_leaf', 'index_leaf']:
            # leaf pages have no subtree
            pass

        elif btpage.page.pagetype in ['table_interior', 'index_interior']:
            # interior pages have subtrees, descent into them
            for cell in btpage.page.cells:
                subpagenum = cell.left_child_pointer
                for subpage in s.treewalker(subpagenum):
                    yield subpage

            # don't forget the rightmost pointer
            rmp = btpage.page.header.rightmost_pointer
            for subpage in s.treewalker(rmp):
                yield subpage


    def cellwalker(s, rootpagenumber):
        ''' Generates logical cells for a (sub)tree starting at rootpagenumber

        A logical cell is a thin wrapper around the cell as returned by
        _structures.cell(), which includes the pagenumber, cellnumber and a
        function to retrieve the cell payload.
        '''

        tree = s.treewalker(rootpagenumber)

        for pg in tree:
            if pg.page.pagetype == 'table_leaf':
                for idx, c in enumerate(pg.page.cells):
                    pload = Payload(s, c)
                    yield Cell(c, pload, idx, pg.pagenumber, pg.pageoffset, pg.pagesource)


    def get_cell_by_rowid(s, rootpagenumber, rowid):
        ''' Returns the logical cell with the given rowid by searching the b-tree.

        A logical cell is a thin wrapper around the cell as returned by
        _structures.cell(), which includes the pagenumber, cellnumber and a
        function to retrieve the cell payload.

        See comments in page_by_rowid function for details on where to start the
        search. If the record is not in the subtree that you start searching in, or
        if the record has been deleted, None is returned.
        '''
        pg = s.get_page_by_rowid(rootpagenumber, rowid)

        if rowid in pg.page.rowidmap:
            cellnumber = pg.page.rowidmap[rowid]
            cell = pg.page.cells[cellnumber]
            pload = Payload(s, cell)
            return Cell(cell, pload, cellnumber, pg.pagenumber, pg.pageoffset, pg.pagesource)
        return None


    def _freelist_pages(s, freelist_trunkpage_number):
        ''' yields all freelist pages starting at the given trunkpage '''

        # when the next freelist trunkpage number is 0, we are done
        if freelist_trunkpage_number == 0:
            return

        # parse and yield the freelist trunkpage
        rootpg = s.get_page_data(freelist_trunkpage_number)
        pageoffset = s.get_pageoffset(freelist_trunkpage_number)
        pagesize = rootpg.size
        btstr = rootpg.data()
        rootfltpage = _structures.freelisttrunkpage(btstr, 0, pagesize, s.header.usablepagesize)
        from_wal = s.page_is_in_wal(freelist_trunkpage_number)
        yield Page(btstr, rootfltpage, freelist_trunkpage_number, pageoffset, from_wal)

        # yield all pages pointed to by the leaf pointers in the trunkpage
        for pgnum in rootfltpage.freelistleafpointers:
            pg = s.get_page_data(pgnum)
            pg_offset = s.get_pageoffset(pgnum)
            btstr = pg.data()
            leafpage = _structures.freelistleafpage(btstr, 0, pagesize, s.header.usablepagesize)
            from_wal = s.page_is_in_wal(pgnum)
            yield Page(btstr, leafpage, pgnum, pg_offset, from_wal)

        # continue with the next freelist trunk page
        for pg in s._freelist_pages(rootfltpage.nextfreelisttrunkpage):
            yield pg


    def freelist_pages(s):
        ''' Generates a sequence of all freelist pages within the SQLite file. '''

        for pg in s._freelist_pages(s.header.firstfreelisttrunkpage):
            yield pg


    def superseded_pages(s):
        ''' Generates a sequence of all pages that have been superseded by a WAL page

        The superseded pages originate from the main database file, for
        superseded or outdated pages from the WAL itself use the WalFile API
        functions '''

        if not hasattr(s, 'walfile'):
            # No WAL file, no superseded pages
            return

        # pages from the database file that are superseded by a page from a WAL frame
        for pagenumber in s.walfile._checkpoint_frames.keys():
            # first check if there is an associated page in the database, since
            # the WAL can have additional pages that are not yet in database file.
            # In this case, there is no superseded page for this WAL page in the
            # main database, so we can skip over these
            if s.header.inheadersizevalid and pagenumber > s.header.dbsize:
                continue
            if not s.header.inheadersizevalid and pagenumber > s.header.externalsize:
                continue

            # determine the pageoffset within the main database file
            pageoffset = (pagenumber - 1) * s.header.pagesize

            # get the page_data from the main database file, not via get_page_data API
            btstr = _block.block(s.bitstream, pageoffset, s.header.pagesize).data()
            # unpack as a generic page
            page = _structures.genericpage(btstr, 0, s.header.pagesize)
            from_wal = False
            yield Page(btstr, page, pagenumber, pageoffset, from_wal)


    def rowidrecords(s, rootpagenumber):
        ''' Generates rowid-records for the table-btree starting at the given page.

        Rootpagenumber has to be the number of a table-btree page. There is no
        sanity check wether this is actually the rootpage of the tree, it just
        starts handing out records from that point in the tree (intended
        behaviour).
        '''

        # parse the rootpage to check pagetype
        rootpage = s.get_btreepage(rootpagenumber)

        if rootpage.page.pagetype not in ['table_leaf', 'table_interior']:
            raise ValueError('rowidrecords should be called on table b-tree page')

        # walk the tree
        tree = s.treewalker(rootpagenumber)

        # for table B-tree pages, records are only stored in the table leaf pages
        for page in tree:
            if page.page.pagetype == 'table_leaf':
                # yield records on this page in rowid order, not in
                # cell-location order
                rowids_on_page = [r for r in page.page.rowidmap.keys()]
                rowids_on_page.sort()
                for rowid in rowids_on_page:
                    cellnum = page.page.rowidmap[rowid]
                    parsed_cell = page.page.cells[cellnum]
                    # make logical cell out of raw cell
                    pload = Payload(s, parsed_cell)
                    cell = Cell(parsed_cell, pload, cellnum, page.pagenumber, page.pageoffset, page.pagesource)
                    yield RowidRecord(cell)


    def rowidrecord_by_rowid(rootpagenumber, rowid):
        ''' Returns rowidrecord with given rowid by searching b-tree under rootpage

        See comments in page_by_rowid function for details on where to start the
        search. If the record is not in the subtree that you start searching in, or
        if the record has been deleted, None is returned.

        Returns a rowidrecord object, see rowidrecord function for details on
        format

        Arguments:
        rootpagenumber : page to start searching on
        rowid          : the rowid you are looking for
        '''

        cell = s.get_cell_by_rowid(rootpagenumber, rowid)
        if cell is None:
            return None

        return RowidRecord(cell)


    def recordheaders(s, cls):
        ''' Generates sequence of recordheaders from a sequence of logical cells.

        The sequence of logical cells can be generated using the _logical.cells()
        function.

        A logical recordheader is a thin wrapper around the recordheader as returned by
        _structures.recordheader(), which includes the pagenumber and cellnumber in
        which the recordheader exists

        Arguments:
        cls            : a sequence of cells
        '''

        for c in cls:
            data = _block.allblocklistdata(c.payload.blocklist)
            bytes_ = data.bytes
            yield RecordHeader(_structures.recordheader(bytes_, 0), c.cellnumber, c.pagenumber)


class SQLiteMaster():
    ''' class representing the sqlite_master table in a database '''


    def __init__(s, master_records, textencoding):
        ''' Interprets the sqlite_master table and returns sqlite_master object.

        The sqlite_master table stores the complete database schema.
        The rootpage of the sqlite_master table is page 1.
        '''

        # store tables, indices, views and triggers in ordered dictionaries
        s.tables = _OD()
        s.indices = _OD()
        s.views = _OD()
        s.triggers = _OD()

        for rec in master_records:
            record = SQLiteMasterRecord(rec, textencoding)

            if record.tbl_type == 'table':
                s.tables[record.name] = record
            elif record.tbl_type == 'index':
                s.indices[record.name] = record
            elif record.tbl_type == 'view':
                s.views[record.name] = record
            elif record.tbl_type == 'trigger':
                s.triggers[record.name] = record
            else:
                raise ValueError('unknown table type in sqlite_master table')


class SQLiteMasterRecord():
    ''' class representing a single record in the sqlite_master table '''

    def __init__(s, rowidrecord, textencoding):
        ''' initialize SQLiteMasterRecord from given rowidrecord '''

        # the type afinities of the sqlite master table
        affinities = ['TEXT', 'TEXT', 'TEXT', 'INTEGER', 'TEXT']

        s.rowid = rowidrecord.rowid

        # decode the record using the textencoding and type affinities
        decoder = _decode.BodyDecoder(textencoding, affinities)
        body, errors = decoder.decode(rowidrecord.body)

        s.tbl_type = body[0]
        # name of the view, index, trigger or table
        s.name = body[1]
        # name of the table to which view, index, trigger or tabledef applies
        s.tbl_name = body[2]
        s.rootpage = body[3]
        s.sql = body[4]

        if s.tbl_type == 'table':
            tbldef = _sql.parse_create_table_statement(s.sql)

            # this function returns None for VIRTUAL tables. VIRTUAL tables may
            # also have an a entry in sqlite master, but they do not represent
            # any in-file structures the parse_create_table_statement function
            # returns None in such cases, so move on to the next entry if this
            # is the case
            s.virtual = False

            if tbldef is None:
                s.columns = None
                s.temporary = None
                s.tblconstraints = None
                s.withoutrowid = None
                s.ipk_column = None
                if "VIRTUAL TABLE" in s.sql:
                    s.virtual = True
                return

            # compare tblname in sql with name field (ignoring quotes in the
            # parsed sql table name)
            tbldefname = tbldef.tblname.lstrip('"\'[`').rstrip('"\']`')
            if tbldefname != s.name:
                raise ValueError('master table definition inconsistency.')

            s.dbname = tbldef.dbname
            s.columns = tbldef.columns
            s.temporary = tbldef.temp
            s.tblconstraints = tbldef.tblconstraints
            s.withoutrowid = tbldef.withoutrowid
            s.ipk_column = tbldef.ipk_column


class Column():
    ''' class that represent a column in a Table '''

    def __init__(s, sql_parsed_columndef):
        ''' initialize a Column object from the given parsed column definition '''

        s.name = sql_parsed_columndef.name
        s.typename = sql_parsed_columndef.coltype
        s.affinity = sql_parsed_columndef.affinity
        s.notnull = sql_parsed_columndef.notnull
        s.unique = sql_parsed_columndef.unique
        s.default = sql_parsed_columndef.default
        s.primary = sql_parsed_columndef.primary
        s.pkey_sort = sql_parsed_columndef.pkey_sort
        s.pkey_autoincrement = sql_parsed_columndef.pkey_autoincrement
        s.constraints = sql_parsed_columndef.constraints


class Table():
    ''' class that represents a the structure of a table an SQLite3 database

    The returned object has two decoder properties. These can be used to decode
    a single raw record. In order to decode a sequence of raw records from the
    table 'tbl' you can do something like::

        tblrecs = (tbl.user_decoder(r) for r in db.rowidrecords(tbl.rootpage))
    '''

    def __init__(s, sqlite_master_record, textencoding):
        ''' initialize the table object from the given SQLiteMasterRecord '''

        s.name = sqlite_master_record.name
        s.rootpage = sqlite_master_record.rootpage

        # reduce column definition to a subset of fields
        s.columns = [Column(c) for c in sqlite_master_record.columns]

        s.ipk_col = sqlite_master_record.ipk_column
        s.withoutrowid = sqlite_master_record.withoutrowid

        # prepare body decoder
        colnames = [c.name for c in s.columns]
        affinities = [c.affinity for c in s.columns]
        s.decoder = _decode.BodyDecoder(textencoding, affinities)

        # prepare record viewer
        s.viewer = _decode.RecordViewer(colnames, s.decoder, s.ipk_col)


class Payload():
    ''' class representing the payload for a single record, including optional overflow '''

    # a namedtuple to represent the overflow
    _overflow = _nt('overflow', 'blocklist slack overflowpages')


    def __init__(s, db, cell):
        ''' create payload object for given cell, including optional overflow

        Note that the cell argument can be a raw cell as returned by the
        _structures.cell() function, but it can also be the cell_wrapper
        defined in the Database class '''

        if isinstance(cell, Cell):
            # we need the raw cell for this function
            cell = cell.parsed_cell

        s.payloadsize = cell.payloadsize

        # construct a list of block objects
        s.blocklist = [cell.inline_payload]
        oflow = s._get_overflow(db, cell)
        s.overflowpages = []
        s.overflowslack = None
        if oflow is not None:
            # extend the list with the overflow blocks
            s.blocklist.extend(oflow.blocklist)
            s.overflowpages = oflow.overflowpages
            s.overflowslack = oflow.slack


    def _get_overflow(s, db, cell):
        ''' returns an overflow object for a cell or None if no overflow exists

        Note that the cell argument can be a raw cell as returned by the
        _structures.cell() function, but it can also be the wrapper defined
        in this class

        Returns an overflow object, which consists of the following fields:
            - blocklist: a list of blocks containing the payload bytes
            - slack: a single block contains slack, or None
            - overflowpages: a list of pagenumbers from which overflow was fetched
        '''
        if isinstance(cell, Cell):
            # we need the raw cell for this function
            cell = cell.parsed_cell

        if cell.payloadsize > cell.inline_payload.size:
            if cell.first_overflow_page is None:
                raise ValueError('cell has overflow, but no first_overflow_page')
            toread = cell.payloadsize - cell.inline_payload.size
            return s._collect_overflow(db, toread, cell.first_overflow_page)
        return None


    def _collect_overflow(s, db, toread, pagenumber):
        ''' Creates overflow object by parsing overflowpages starting at pagenumber

        The toread parameter is used to check if overflow chain ends at the same
        moment at which enough bytes are read. In addition, it is used to
        separate payload from slack if the payload doesn't end at the last byte
        of the last overflow page. Note that I've not yet seen slack in
        test databases, so maybe payload calculations are such that no payload
        slack exists. This remains to be investigated.

        Returns an overflow object, see overflow function for details
        '''

        pload = []
        overflowpages = []
        slack = None
        nextpage = pagenumber

        while nextpage != 0:
            overflowpages.append(nextpage)
            if toread <= 0:
                raise ValueError('nextpage available but no more bytes to read')

            # get the next overflowpage
            next_pg = db.get_page_data(nextpage)
            pagesize = next_pg.size
            btstr = next_pg.data()

            # start at offset 0, since we have created a sub bitstream
            opage = _structures.overflowpage(btstr, 0, pagesize, db.header.usablepagesize)
            nextpage = opage.next_overflow_page
            if toread >= opage.payload.size:
                pload.append(opage.payload)
                toread -= opage.payload.size
            else:
                remainder, slack = _block.splitblock(opage.payload, toread)
                pload.append(remainder)
                toread = 0

        return Payload._overflow(pload, slack, overflowpages)


class PageSource(_Enum):
    ''' use to identify the source of the page (i.e. WAL or main db) '''

    DatabaseFile = 0
    WALFile = 1


class Page():
    ''' wrapper for parsed pages with some extra meta-data '''


    def __init__(s, bitstream, parsed_page, pagenum=None, offset=None, from_wal=False):
        ''' initialize Page object, optionally setting pagenumber and offset to given values '''

        s.pagenumber = pagenum
        s.pageoffset = offset
        s.bitstream = bitstream
        s.page = parsed_page
        if from_wal is True:
            s.pagesource = PageSource.WALFile
        else:
            s.pagesource = PageSource.DatabaseFile


class Cell():
    ''' wrapper for parsed cell with some extra meta-data '''

    def __init__(s, parsed_cell, payload, cellnumber, pagenumber=None, pageoffset=None, pagesource=None):
        ''' initialize Cell object, optionally setting pagenumber '''

        s.pagenumber = pagenumber
        s.pageoffset = pageoffset
        s.pagesource = pagesource
        s.cellnumber = cellnumber
        s.parsed_cell = parsed_cell
        s.payload = payload


class RecordHeader():
    ''' wrapper for parsed recordheader with some extra meta-data '''

    def __init__(s, parsed_recordheader, cellnumber, pagenumber=None):
        ''' initialize RecordHeader, optionally setting pagenumber '''

        s.parsed_recordheader = parsed_recordheader
        s.cellnumber = cellnumber
        s.pagenumber = pagenumber


class RowidRecord():
    ''' wrapper around recordformat with some extra metadata

    A rowid-record is defined here as a detailed version of what is returned by
    the _structures.recordformat() function, including information about the page
    and cell that the record is stored in. This information is only available
    if a logical cell is passed into this function. If a raw cell is given,
    pagenumber and cellnumber will be None.

    A rowid-record has the following fields:

        - pagenumber: pagenumber that contains the cell, or None
        - pagesource: source of the recordpage (main db, WAL)
        - pageoffset: offset of the page that contains the cell, or None
        - cellnumber: cellnumber that contains the record, or None
        - rowid: the rowid of the record
        - header: the recordformat header object
        - body: the recordformat body object
        - inlinesize: size of the inline recordheader and body (inline payload)
        - payloadsize: size of the cell payload, including overflow
        - has_overflow: whether or not the cell has payload overflow

        When the table has a INTEGER PRIMARY KEY, this is what is stored in the
        rowid and the record itself contains a NULL value for that column.
    '''

    def __init__(s, cell):
        ''' initialize RowidRecord from given cell'''

        if isinstance(cell, Cell):
            # we have a logical cell, extract required info
            s.pagenumber = cell.pagenumber
            s.pageoffset = cell.pageoffset
            s.pagesource = cell.pagesource
            s.cellnumber = cell.cellnumber
            s.rowid = cell.parsed_cell.rowid
            s.inlinesize = cell.parsed_cell.inline_payload.size
            s.payloadsize = cell.parsed_cell.payloadsize
            s.payloadoffset = cell.parsed_cell.inline_payload.offset
            pload = cell.payload
        else:
            s.pagenumber = None
            s.pageoffset = None
            s.pagesource = None
            s.cellnumber = None
            s.rowid = cell.rowid
            s.inlinesize = cell.inline_payload.size
            s.payloadsize = cell.payloadsize
            s.payloadoffset = cell.payload.offset
            pload = Payload(s, cell)

        if len(pload.overflowpages) == 0:
            s.has_overflow = False
        else:
            s.has_overflow = True

        # construct a new bitstring for the payload
        btstr = _block.allblocklistdata(pload.blocklist)
        # check if length matches defined payloadsize (btstr is in bits)
        if int(len(btstr)/8) != s.payloadsize:
            raise RuntimeError('created payload bitstring not correct size')

        # parse as recordformat struct
        recdata = _structures.recordformat(btstr, 0)
        s.header = recdata.header
        s.body = recdata.body

        # sanity check on payload size and total size of header + body
        sizes = [_structures.serialtype(t).size for t in recdata.header.serialtypes]
        definedsize = sum(sizes) + recdata.header.headersize
        availablesize = len(btstr)
        if definedsize != s.payloadsize:
            raise RuntimeError('mismatch between size in recordheader and payloadsize.')


class WalFile():
    ''' class representing the WAL file associated with a database

    From sqlite documentation:

    A WAL file consists of a header followed by zero or more "frames". Each
    frame records the revised content of a single page from the database file.
    All changes to the database are recorded by writing frames into the WAL.
    Transactions commit when a frame is written that contains a commit marker.
    A single WAL can and usually does record multiple transactions.
    Periodically, the content of the WAL is transferred back into the database
    file in an operation called a "checkpoint".

    A single WAL file can be reused multiple times. In other words, the WAL can
    fill up with frames and then be checkpointed and then new frames can
    overwrite the old ones. A WAL always grows from beginning toward the end.
    Checksums and counters attached to each frame are used to determine which
    frames within the WAL are valid and which are leftovers from prior
    checkpoints.  '''

    def __init__(s, filename, bitstream):
        ''' initialize a WAL file object from the given bitstream '''

        s.filename = filename
        s.bitstream = bitstream

        # wal file size
        s.filesize = s.bitstream.length // 8

        # parse the walheader
        walheader = _structures.walheader(s.bitstream, 0)
        # and extract the properties to WalFile properties
        s.pagesize = walheader.pagesize
        s.checkpoint_sequence_number = walheader.checkpoint_sequence_number
        s.salt1 = walheader.salt1
        s.salt2 = walheader.salt2
        s.checksum1 = walheader.checksum1
        s.checksum2 = walheader.checksum2
        s.checksum_endianness = walheader.checksum_endianness

        # amount of bytes available for frames is filesize minus header
        frame_bytecount = s.filesize - 32
        # each frame is pagesize + frameheader size
        s.frame_size = s.pagesize + 24
        # total number of frames is thus:
        s.frame_count = frame_bytecount // s.frame_size
        if frame_bytecount % s.frame_size != 0:

            # We have seen examples of WAL files where an additional
            # frame header exists at the end of the WAL file, with
            # some data that is not a full pagesize. This can happen
            # for various reasons, for example when the framesize has been
            # modified during the lifetime of the database, or if the
            # file has been truncated to a multiple of the filesystem
            # blocksize.

            # The existence of such slack should not hinder the processing
            # of the WAL file, thus instead of failing here, we include this
            # remaining data as slack.

            slacksize = s.filesize - 32 - (s.frame_count * s.frame_size)
            if slacksize > s.frame_size:
                raise ValueError("a mistake was made in slack calculation")

            slackoffset = 32 + (s.frame_count * s.frame_size)
            s.slack = _block.block(bitstream, slackoffset, slacksize)

        # from the sqlite amalgamation source file we learn (line numbers added):

        # 51188 ** A frame is considered valid if and only if the following conditions are¬
        # 51189 ** true:¬
        # 51190 **¬
        # 51191 **    (1) The salt-1 and salt-2 values in the frame-header match¬
        # 51192 **        salt values in the wal-header¬
        # 51193 **¬
        # 51194 **    (2) The checksum values in the final 8 bytes of the frame-header¬
        # 51195 **        exactly match the checksum computed consecutively on the¬
        # 51196 **        WAL header and the first 8 bytes and the content of all frames¬
        # 51197 **        up to and including the current frame.¬

        # so first determine the sequence of frames with valid checksums (2) by computing the
        # checksum of each frame using the previous checksum as input. Stores the last page with a
        # valid checksum in the last_valid_checksum_frame property.
        s._determine_last_valid_checksum()

        # next determine which of the frames have the same checksum as defined in the
        # wal header. Stores 4 properties: first_current_frame, last_current_frame,
        # first_outdated_frame and last_outdated_frame.
        s._check_frame_salt_values()

        # determine the last valid frame that is also a commit frame
        s._determine_mxFrame()

        # So now we have two sets of frames: those that are valid and that are still to be copied
        # into the database, which are all the frames prior to and including the mxFrame. And we
        # have the outdated frames, which are all frames beyond the mxFrame.

        # However, even within the valid frames, we can have outdated versions of the same page
        # (i.e. when multiple changes have been done sequentially). When multiple frames exist that
        # pertain to the same database page, the latest (i.e. sequentially closest to the mxFrame)
        # version is copied into the database by the checkpointer. This next function mimics the
        # checkpointer by building two dictionaries: One with a mapping of pagenumber to framenumber
        # for the latest (i.e. up to date) frame and one with a mapping of pagenumber to a list
        # of outdated/superseded framenumbers
        s._determine_checkpoint_frames()

        # We now have two dictionaries with the most recent and the outdated frames. These are used
        # as the basis for three functions to the WalFile API:
        #
        # - get_page_frame    : returns the most recent page frame for the given pageframe
        # - superseded_frames : generates frames below mxFrame that are superseded by a newer frame
        # - allocated_frames  : generates the most recent page frames


    def _determine_last_valid_checksum(s):
        ''' returns the last frame number with a correct checksum

        The checksum stored in the previous frame is used as input for the checksum
        computation of the next frame. So this function checks which part of the
        wal file frames have a valid checksum. This is used in determination of the
        so called mxFrame.
        '''

        c1 = s.checksum1
        c2 = s.checksum2

        s.last_valid_checksum_frame = None

        for i in range(1, s.frame_count + 1):
            frame = s.get_frame(i)
            new_c1, new_c2 = frame.compute_checksum(s.checksum_endianness, c1, c2)
            if new_c1 != frame.checksum1 or new_c2 != frame.checksum2:
                return
            else:
                s.last_valid_checksum_frame = i
            c1 = new_c1
            c2 = new_c2


    def _check_frame_salt_values(s):
        ''' determine which frames have the current salt values, and which frames are leftover

        Invalidated frames are frames that have been invalidated by a checkpoint operation
        by updating the salt1 and salt2 values in the WAL header. All pages for which the
        salt values match the header salt values are valid and if their checksum is also correct,
        they are part of the database state and the last version of each page should be written
        back into the database in the next checkpoint operation '''

        # from this page: https://sqlite.org/fileformat2.html#walformat we learn

        # "After a complete checkpoint, if no other connections are in transactions that use the WAL,
        # then subsequent write transactions can overwrite the WAL file from the beginning. This is
        # called "resetting the WAL". At the start of the first new write transaction, the WAL
        # header salt-1 value is incremented and the salt-2 value is randomized. These changes to
        # the salts invalidate old frames in the WAL that have already been checkpointed but not yet
        # overwritten, and prevent them from being checkpointed again."

        # This suggests that valid frames only exist at the start of the WAL file and that we can
        # still have some ranges of older frames at the end of the file that correspond to earlier
        # database state. On one of our test databases this gives the following image:
        #
        # >>> g = db.walfile.allframes()
        # >>> [(f.salt1, f.salt2) for f in g]
        # ...
        # [(3313696399, 2889901289),
        #  (3313696399, 2889901289),
        #  ...
        #  (3313696399, 2889901289),    <-- end of current state
        #  (3313696398, 1826548311),
        #  ...
        #  (3313696398, 1826548311),    <-- end of previous state
        #  (3313696397, 334084473),
        #  (3313696397, 334084473),     <-- end of earlier state
        #  (3313696390, 511391743),
        #  (3313696375, 671756787),
        #  (3313696214, 1129315483),
        #  (3313696214, 1129315483)]    <-- end of earliest state
        #
        # Here we see that at some point there were more frames in the WAL file than
        # is currently the case, and we can see ranges of frames from those earlier periods
        # towards the end of the file.

        current_frames = []
        outdated_frames = []
        for frame in s.allframes():
            if frame.salt1 == s.salt1 and frame.salt2 == s.salt2:
                current_frames.append(frame.framenumber)
            elif frame.salt1 != s.salt1 and frame.salt2 != s.salt2:
                outdated_frames.append(frame.framenumber)
            else:
                raise ValueError("one of the two salt values matches, the other does not!")

        if len(current_frames) > 0:
            s.first_current_frame = min(current_frames)
            s.last_current_frame = max(current_frames)
            # it is our assumption that we only have current frames at the start
            # of the file and outdated frames at the end. Verify this here
            if current_frames != list(range(1, max(current_frames)+1)):
                raise _exceptions.AssumptionBrokenException("strangeness in current frame list")
        else:
            s.first_current_frame = None
            s.last_current_frame = None

        if len(outdated_frames) > 0:
            s.first_outdated_frame = min(outdated_frames)
            s.last_outdated_frame = max(outdated_frames)
            if s.last_current_frame is not None:
                if s.first_outdated_frame != s.last_current_frame + 1:
                    raise _exceptions.AssumptionBrokenException("unexpected first invalid frame")
            if s.last_outdated_frame != s.frame_count:
                raise _exceptions.AssumptionBrokenException("unexpected last invalid frame")
            if outdated_frames != list(range(min(outdated_frames), max(outdated_frames)+1)):
                raise _exceptions.AssumptionBrokenException("gaps in invalid frame list")


    def _determine_mxFrame(s):
        ''' determine the last valid frame that is also a commit frame '''

        # At the start of the source wal.c within the amalgamation file, we see:

        #    To read a page from the database (call it page number P), a reader first
        #    checks the WAL to see if it contains page P. If so, then the last valid
        #    instance of page P that is followed by a commit frame or is a commit frame
        #    itself becomes the value read. If the WAL contains no copies of page P
        #    that are valid and which are a commit frame or are followed by a commit
        #    frame, then page P is read from the database file.

        # This indicates that the last page frame for a given pagenumber represents
        # the most recent version of the page, as long as it is a commit frame, or if
        # it is followed by a commit frame.

        # Concerning the shm file, we can also read:

        #     Recovery works by doing a single pass over the WAL, from beginning to
        #     end.  The checksums are verified on each frame of the WAL as it is read.
        #     The scan stops at the end of the file or at the first invalid checksum.
        #     The mxFrame field is set to the index of the last valid commit frame in
        #     WAL. Since WAL frame numbers are indexed starting with 1, mxFrame is also
        #     the number of valid frames in the WAL. A "commit frame" is a frame that
        #     has a non-zero value in bytes 4 through 7 of the frame header. Since the
        #     recovery procedure has no way of knowing how many frames of the WAL might
        #     have previously been copied back into the database, it initializes the
        #     nBackfill value to zero.

        # So, we need to determine the last valid commit frame, which is stored in the
        # shm file as mxFrame, but can also be determined by finding the last frame with
        # the current salt values and a valid checksum that is also a commit frame.

        # first determine which is larger: the last valid checksum frame or the last
        # current frame. This serves as the absolute upper level for the mxFrame
        last_valid_frame = s.last_valid_checksum_frame
        if s.last_current_frame < last_valid_frame:
            last_valid_frame = s.last_current_frame

        s.mxFrame = None
        # iterate over the frames with correct salt and checksum
        for fnum in range(1, last_valid_frame + 1):
            frame = s.get_frame(fnum)
            # check if this is also a commit frame
            if frame.commit_page_count != 0:
                # this is a commit frame, update mxFrame value
                s.mxFrame = fnum


    def _determine_checkpoint_frames(s):
        ''' determines the latest frame for each pagenumber, similar to a checkpoint operation

        This function creates a dictionary mapping the pagenumber to the frameindex
        for the last (most recent) version of each page frame, and a dictionary mapping
        each pagenumber to a sequence of outdated, but valid page frames.
        '''

        # From the amalgamation a note on the waliterator struct:
        #
        #     this structure is used to implement an iterator that loops through
        #     all frames in the wal in database page order. where two or more frames
        #     correspond to the same database page, the iterator visits only the
        #     frame most recently written to the wal (in other words, the frame with
        #     the largest index)
        #
        # Further down, in the walCheckpoint function we see the following:
        #
        #     /* Iterate through the contents of the WAL, copying data to the db file */
        #     while( rc==SQLITE_OK && 0==walIteratorNext(pIter, &iDbpage, &iFrame) ){
        #       i64 iOffset;
        #       assert( walFramePgno(pWal, iFrame)==iDbpage );
        #       if( iFrame<=nBackfill || iFrame>mxSafeFrame || iDbpage>mxPage ){
        #         continue;
        #       }
        #       iOffset = walFrameOffset(iFrame, szPage) + WAL_FRAME_HDRSIZE;
        #       /* testcase( IS_BIG_INT(iOffset) ); // requires a 4GiB WAL file */
        #       rc = sqlite3OsRead(pWal->pWalFd, zBuf, szPage, iOffset);
        #       if( rc!=SQLITE_OK ) break;
        #       iOffset = (iDbpage-1)*(i64)szPage;
        #       testcase( IS_BIG_INT(iOffset) );
        #       rc = sqlite3OsWrite(pWal->pDbFd, zBuf, szPage, iOffset);
        #       if( rc!=SQLITE_OK ) break;
        #     }
        #
        # Here we see a call to the walItereratorNext function, which is documented
        # as follows:
        #
        #     Find the smallest page number out of all pages held in the WAL that
        #     has not been returned by any prior invocation of this method on the
        #     same WalIterator object.   Write into *piFrame the frame index where
        #     that page was last written into the WAL.  Write into *piPage the page
        #     number.
        #
        # From this we can infer that for each valid frame, only the latest version
        # for a particular page number is actually to be copied back into the main database
        # file. From this, in turn, we can classify all but the last wal frame for a
        # particular page as outdated/unallocated.
        #
        # Another snippet from this page: https://sqlite.org/wal.html
        #
        # The checkpointer makes an effort to do as many sequential page writes
        # to the database as it can (the pages are transferred from WAL to database in
        # ascending order) '''

        s._checkpoint_frames = {}
        s._superseded_frames = {}

        for i in range(1, s.mxFrame + 1):
            frame = s.get_frame(i)
            pgnum = frame.pagenumber
            if pgnum in s._checkpoint_frames:
                # the old version is superseded
                old_framenumber = s._checkpoint_frames[pgnum]
                if pgnum in s._superseded_frames:
                    s._superseded_frames[pgnum].append(old_framenumber)
                else:
                    s._superseded_frames[pgnum] = [old_framenumber]
            # add the current page to the checkpoint frames
            s._checkpoint_frames[pgnum] = i


    def _frame_offset(s, framenumber):
        ''' return offset for given framenumber. Frames are numbered starting at 1 '''

        if framenumber > (s.frame_count):
            raise _exceptions.InvalidArgumentException("framenumber exceeds frame count")

        if framenumber < 1:
            raise _exceptions.InvalidArgumentException("framenumber starts at 1")

        return 32 + s.frame_size * (framenumber - 1)


    def get_frame(s, framenumber):
        ''' return frame with given frame number '''

        offset = s._frame_offset(framenumber)

        return WalFrame(s.bitstream, framenumber, offset, s.pagesize)


    def allframes(s, only_valid=False):
        ''' generate all frames within the WAL file '''

        for i in range(1, s.frame_count + 1):
            yield s.get_frame(i)


    def allocated_frames(s):
        ''' yields the allocated frames that have not been superseded

        These frames all exist below mxFrame and are the most recent version for their pagenumber
        '''

        for pnum, framenum in s._checkpoint_frames.items():
            yield s.get_frame(framenum)


    def superseded_frames(s):
        ''' yields the superseded frames from below mxFrame '''

        for pnum, framenums in s._superseded_frames.items():
            for framenum in framenums:
                yield s.get_frame(framenum)


    def get_page_frame(s, pagenum):
        ''' return the frame for the given pagenumber, or None if it doesn't exist '''

        if pagenum in s._checkpoint_frames:
            return s.get_frame(s._checkpoint_frames[pagenum])
        else:
            return None


    def outdated_frames(s):
        ''' generate all frames above mxFrame

        These are the frames that are not part of the current database stated
        for various reasons (i.e. different salt1/salt2, incorrect CRC, not
        followed by commit record) '''

        for i in range(s.mxFrame + 1, s.frame_count + 1):
            yield s.get_frame(i)


    def superseded_pages(s):
        ''' generate a sequence of pages from WAL file that have been superseded by a newer page

        All generated pages originate from the frames in the WAL file prior to the mxFrame '''

        # pages from the WAL file that have been superseded by a page from a later WAL frame
        for frame in s.superseded_frames():
            # determine the offset of the page in the WAL file
            pageoffset = frame.contents_block.offset
            # get the page data from the wal frame
            btstr = frame.contents_block.data()
            # unpack as a generic page
            page = _structures.genericpage(btstr, 0, s.pagesize)
            from_wal = True
            yield Page(btstr, page, frame.pagenumber, pageoffset, from_wal)


    def outdated_pages(s):
        ''' generate a sequence of pages from WAL file that are beyond mxFrame

        These pages have been checkpointed during an earlier checkpoint operation and
        are no longer part of the database state '''

        # pages from the WAL file that have been superseded by a page from a later WAL frame
        for frame in s.outdated_frames():
            # determine the offset of the page in the WAL file
            pageoffset = frame.contents_block.offset
            # get the page data from the wal frame
            btstr = frame.contents_block.data()
            # unpack as a generic page
            page = _structures.genericpage(btstr, 0, s.pagesize)
            from_wal = True
            yield Page(btstr, page, frame.pagenumber, pageoffset, from_wal)


class WalFrame():
    ''' class representing a single frame in a WAL file '''

    def __init__(s, bitstream, framenumber, offset, pagesize):
        ''' initialize a frame from given offset in bitstream using given pagesize '''

        s.framenumber = framenumber
        # store the header and contents as block object so we can feed these
        # to various parsers
        s.header_block = _block.block(bitstream, offset, 24)
        s.contents_block = _block.block(bitstream, offset+24, pagesize)

        # parse the frame header
        frame_header = _structures.walframeheader(s.header_block.data(), 0)
        # and promote properties to be walframe properties
        s.pagenumber = frame_header.pagenumber
        s.commit_page_count = frame_header.commit_page_count
        s.salt1 = frame_header.salt1
        s.salt2 = frame_header.salt2
        s.checksum1 = frame_header.checksum1
        s.checksum2 = frame_header.checksum2


    def compute_checksum(s, endianness, init_checksum1=0, init_checksum2=0):
        ''' computes the checksum for this frame, using the provided initial values '''

        # from the amalgamation sqlite source we get (line numbers added):

        # 51194 **    (2) The checksum values in the final 8 bytes of the frame-header¬
        # 51195 **        exactly match the checksum computed consecutively on the¬
        # 51196 **        WAL header and the first 8 bytes and the content of all frames¬
        # 51197 **        up to and including the current frame.¬

        # so first, combine the data from the first 8 bytes of the header
        # and the full contents
        header_data = s.header_block.data()[0:64]
        contents_data = s.contents_block.data()
        all_data = header_data + contents_data

        # total number of DWORDs to read
        dword_count = all_data.length // 8 // 4

        # read frame contents according to checksum endianess
        if endianness == 'little':
            integers = all_data.readlist(['uintle:32']*dword_count)
        elif endianness == 'big':
            integers = all_data.readlist(['uintbe:32']*dword_count)

        c1,c2 = _structures._walchecksum(integers, init_checksum1, init_checksum2)
        return (c1, c2)
