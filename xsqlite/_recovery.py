''' _recovery.py - recovery of unallocated records

Copyright (c) 2022 Netherlands Forensic Institute - MIT License
'''

from collections import namedtuple as _nt
from collections import OrderedDict as _OD
from collections import Counter as _Counter
import statistics as _statistics
from enum import Enum as _Enum
import bitstring as _bitstring
import re as _re
from itertools import chain as _chain

from . import _structures
from . import _exceptions
from . import _block
from . import _export
from . import _database

# NOTE: rowid might be guessable based on surrounding records, but we should be
# very careful with this, so this is not implemented.

# NOTE: the record recovery currently assumes that the entire record is stored
# in a single containing object (i.e. freeblock, unallocated area in btree
# page, and so on). Recovery of fragmented records (i.e. with cell-overflow) is
# difficult especially when the header overflows as well. This is not yet
# implemented.


################
# recovery API #
################


class RejectReason(_Enum):
    ''' Enum indicating why a varint_candidate was rejected '''

    # higher numbers should be a stricter filter, so we can easily select
    # to include some candidates based on the RejectReason value

    NotRejected = 0                    # None of the filters rejected the candidate

    ReservedSerialType = 5             # candidate contains a reserved serialtype (10, 11)

    SchemaBasedSignature = 10          # The candidate does not match CREATE TABLE statement
    LooseObservedSignature = 20        # The candidate does not match loose observed serialtypes
    StrictObservedSignature = 30       # The candidate does not match strict observed serialtypes


def determine_recovery_parameters(db, tablename, minimal_record_count=30, ignore_last_cols=None):
    ''' Returns properties of allocated records that can aid in filtering false positive headers

    If less than minimum_record_count allocated records exist, the function
    will raise an exception. In this case you can lower this number or,
    preferably, use a reference database to determine the recovery parameters.
    The default is rather arbitrarily set to 30 '''

    # An observation is that the first four bytes of a deleted cell record are
    # overwritten immediately by the freeblock header upon deletion. When a
    # single record is deleted it is likely to end up in unallocated space, in
    # which case the cell header remains intact, or it may end up in a
    # freeblock, in which case 4 bytes of the cell header and the first part of
    # the recordheader are overwritten.  Just how many bytes of the record
    # header are overwritten may vary based on the exact size of the cell
    # header. The cell-header is defined as follows:

    # 1. payloadsize (1-9 bytes varint)    (overwritten)
    # 2. rowid (1-9 bytes varint)          (overwritten if payloadsize uses less than 4 bytes)
    # 3. inline payload
    # 4. overflow page pointer (not present or uintbe:32)

    # The inline payload, in turn, contains the recordheader, which consists of
    # the following:

    # 1. headersize (1-9 bytes varint)     (overwritten if payloadsize + rowid use less than 4 bytes)
    # 2. serialtypes (series of varints)   (1st varint overwritten if payloadsize, rowid + headersize < 4 bytes)
    # 3. recorddata

    # From above we see that it is likely that 1 or 2 bytes of the recordheader
    # are overwritten, if the record is deleted. However, for rowid > 127 we
    # already use 2 bytes for the rowid, in which case the first varint of the
    # serialtypes is *not* overwritten.

    # Other scenario's are conceivable as well, for example when multiple
    # record are deleted, leading to a single freeblock with multiple records.
    # Now, when the freeblock is partially re-used, the freeblock will shrink
    # again. IIRC: the freeblocks are filled from the high-end to the low-end,
    # because this way only the size in the freeblock-header has to be updated,
    # the next_freeblock pointer can remain intact.  This means that in this
    # scenario (multiple deleted records in a freeblock), we also have only the
    # first 1 or 2 bytes of the recordheader overwritten (and of course part of
    # the recordheader or recorddata at the *end* of the record).

    # When the first record in a page is deleted, it ends up on in the
    # unallocated space between the last cell pointer and the (new) first
    # record. In this case, none of the fields in the recordheader are
    # overwritten. Since the cell-pointers and the records grow towards each
    # other, and since records are allocated from the high-address to the low
    # address, we can only encounter these scenario's:

    # consider this initial state:
    # +-----------------+-----------------------------------------+---------------+
    # | cellptr area    |-> unallocated         deleted record  <-| active record |
    # +-----------------+-----------------------------------------+---------------+

    # Now, if a new record is allocated that is smaller than the deleted
    # record, it will only partially overwrite the record, leaving the start of
    # the record intact. If a new record is allocated that is larger than the
    # deleted record, the entire deleted record will be overwritten and we will
    # not find a candidate there. If the deleted record was large, and it is
    # later overwritten by many smaller records we could have the situation
    # where part of the record header of the deleted record remains, whereas
    # another part is overwritten by the new cell pointers. However, since the
    # content area of the record (and probably also a significant portion of
    # the record-header) are overwritten by new records, we can probably not
    # recover the record anyway.

    # So for now, we assume that at most 2 bytes of the recordheader are
    # overwritten, the first being the headersize, and the second being the
    # first serialtype. We can also infer that if any of the varints preceding
    # the first serialtype varint is larger than 1 byte, that the entire
    # sequence of serialtypes remains intact. This happens in the following
    # scenario's:

    # 1. The cell payload > 127 or the rowid > 127
    # 2. Cell payload > 16383
    # 3. Rowid > 16383
    # 4. Any combination of the above

    # To conclude: when scanning for potential recordheaders, we should scan
    # for the total number of columns in the specific table, minus the first,
    # since this can optionally be overwritten for records with a low rowid.
    # Also when a table has been updated using the ALTER TABLE statement to add
    # columns, these are added at the end. Since we can not know for deleted
    # records if they existed prior or after the ALTER TABLE was done, we
    # should scan only for the common columns that exist in all allocated
    # records.

    _recovery_parameters = _nt('recovery_parameters', 'schema_serialtypes strict_observed_serialtypes '
                               'loose_observed_serialtypes observations_per_column '
                               'observed_max_varint_widths text_and_blob_stats added_columns '
                               'pagesize textencoding columns ipk_col common_columns '
                               'possible_headersizes max_varints_in_header '
                               'col0_prepend_list max_nr_of_cols')

    tbl = db.tables[tablename]
    schema_stypes = _schema_based_allowed_serialtypes(db, tablename)

    # obtain the typecodes from the allocated records
    typecodes = _scan_btree_typecodes(db, tbl.rootpage)
    # count occurrence of typecodes for each column
    typecode_counters = _observed_typecodes(typecodes)
    # determine strict and loose signatures
    strict_observed_stypes = _observation_based_allowed_serialtypes(typecode_counters, False)
    loose_observed_stypes = _observation_based_allowed_serialtypes(typecode_counters, True)
    # determine total number of observations per column
    observations_per_column = _observations_per_column(typecode_counters)

    if len(observations_per_column) == 0:
        msg = "given table doesn't contain allocated records, use reference database!"
        raise _exceptions.UserFeedbackException(msg)
    if max(observations_per_column) < minimal_record_count:
        msg = "only {:d} allocated records in database, lower minimal_record_count or use reference database"
        msg = msg.format(max(observations_per_column))
        raise _exceptions.UserFeedbackException(msg)

    # determine the max observed varint size for each column
    observed_max_varint_widths = _observed_max_varint_widths(typecode_counters)
    # get stats on the BLOB and TEXT values in each columns
    text_and_blob_stats = _collect_text_and_blob_size_stats(typecode_counters)
    # determine if one or more columns have been added during lifetime of database
    added_columns = _determine_added_columns(observations_per_column)

    # when scanning for varints, exclude the first column, because this is potentially
    # overwritten, and exclude the added columns, because these are not present in all records
    common_columns = (1, len(tbl.columns) - added_columns - 1)

    # The header size is at least the amount of columns and at most amount of columns
    # times the maximum size of the varint describing that column. To find this
    # number we have to know the SQLITE_MAX_LENGTH parameter. This defaults to
    # 1000000000 bytes. A BLOB of this length is represented as follows:

    # (N-13)/2 = 1000000000
    # N - 13 = 2000000000
    # N = 2000000013

    # A TEXT of this length is represented as follows:

    # (N-12)/2 = 1000000000
    # N - 12 = 2000000000
    # N = 2000000012

    # Thus, for this default maximum the width of a serial type in the record
    # header is at most 5 bytes
    # >>> tovarint(2000000013).len / 8
    # 5.0

    # However, since a record is itself stored as a blob, the same restriction
    # applies to the record as a whole. This means that the entire record may
    # never exceed SQLITE_MAX_LENGTH itself. This indicates that not even a
    # single column can contain this theoretical maximum length, but throughout
    # this code we assume that any column can have a size requiring a 5 byte
    # varint size.

    # the recordheader size includes the recordheader size field itself,
    # so the minimal size is that of the common columns
    min_headersize = len(tbl.columns) - added_columns + 1

    # in principle, all columns could house a TEXT or BLOB, but for computation
    # of the max_headersize, we assume that only those with TEXT or BLOB
    # affinity can use more than 1 bytes for their serialtype varint
    single_byte_cols = len([c for c in tbl.columns if c.affinity == 'INTEGER' or c.affinity == 'REAL'])
    multi_byte_cols = len(tbl.columns) - single_byte_cols

    # for each non numeric column, add the max width of 5 for the varint, which
    # is most likely not very realistic
    max_headersize = single_byte_cols + multi_byte_cols * 5

    # it is even less realistic that we have more than 25 columns, all with a
    # TEXT or BLOB value that require a 5-byte varint to express, so limit the
    # headersize to a 1-byte varint
    if max_headersize > 127:
        max_headersize == 127

    # make sure we only have to create these size varints once
    headersizes = _OD()
    for size in range(min_headersize, max_headersize + 1):
        varint = _structures.tovarint(size)
        headersizes[size] = (varint, varint.bytes)

    # the recordheader can contain 1 varint for each column + headersize
    max_varints_in_header = len(tbl.columns) + 1

    # make a sequence of prepend bytes we can use for the first column
    # so that we only have to do this once per table
    if tbl.ipk_col == 0:
        # if col0 is the INTEGER PRIMARY KEY column, then the only allowed value is 0
        # which significantly speeds up recordheader reconstruction
        prepend_col0 = [_bitstring.BitStream(uint=0, length=8)]
    else:
        # otherwise, we can not be sure and we need to try them all.
        prepend_col0 = [_bitstring.BitStream(uint=i, length=8) for i in range(0, 256) if i != 128]

    max_nr_of_cols = len(tbl.columns)

    return _recovery_parameters(schema_stypes, strict_observed_stypes, loose_observed_stypes,
                                observations_per_column,
                                observed_max_varint_widths, text_and_blob_stats, added_columns,
                                db.header.pagesize, db.header.textencoding, tbl.columns,
                                tbl.ipk_col, common_columns, headersizes,
                                max_varints_in_header, prepend_col0, max_nr_of_cols)


def recover_records(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' generate sequence of recovered records for given table '''

    g = _scan(db, tablename, recov_params)
    for candidate in g:
        res = RecoveredRecord(candidate)
        yield res


def recover_table(db, refdb, tablename, outfile, include_allocated=True, refcount=30, tsv=False):
    ''' attempt recovery for given table and export to given outfile (xlsx)

    If include_allocated is True, the allocated records are exported as well
    '''

    if refdb is None:
        refdb = db

    recov_params = determine_recovery_parameters(refdb, tablename, refcount)

    if tsv is False:
        recover_to_xlsx(db, tablename, recov_params, outfile, include_allocated)
    else:
        recover_to_tsv(db, tablename, recov_params, outfile, include_allocated)


def recover_to_xlsx(db, tablename, recov_params, outfile, include_allocated):
    ''' recover the given table to the given outfile '''

    tbl = db.tables[tablename]

    with _export.XLSXWriter(outfile) as x:

        if include_allocated is True:
            x.add_sheet('allocated')
            x.write_detailed_header('allocated', tbl)
            allocated = db.rowidrecords(tbl.rootpage)
            for r in allocated:
                x.write_row('allocated', tbl.viewer.detailed_view(r))

        x.add_sheet('recovered')
        x.write_detailed_header('recovered', tbl)
        x.add_sheet('recovery_details')
        x.write_forensic_header('recovery_details', tbl)

        for r in recover_records(db, tablename, recov_params):
            x.write_row('recovered', tbl.viewer.detailed_view(r))
            x.write_row('recovery_details', tbl.viewer.forensic_view(r))


def recover_to_tsv(db, tablename, recov_params, outfile, include_allocated):
    ''' recover the given table to tsv using outfile as basename '''

    tbl = db.tables[tablename]

    if include_allocated is True:
        allocated_name = outfile + "_allocated.tsv"
        with _export.TSVWriter(allocated_name) as f:
            f.write_detailed_header(tbl)
            for r in db.rowidrecords(tbl.rootpage):
                f.write_row(tbl.viewer.detailed_view(r))

    recovered_name = outfile + "_recovered.tsv"
    detail_name = outfile + "_recovery_details.tsv"
    with _export.TSVWriter(recovered_name) as f:
        with _export.TSVWriter(detail_name) as g:
            f.write_detailed_header(tbl)
            g.write_forensic_header(tbl)
            for r in recover_records(db, tablename, recov_params):
                f.write_row(tbl.viewer.detailed_view(r))
                g.write_row(tbl.viewer.forensic_view(r))


###################
# wrapper classes #
###################

# This sections contains some wrappers for structures within SQLite that
# contain the necessary properties for recovery of such structures. These
# objects are included in scan_results as the "containing_object"


class Freeblock():
    ''' wrapper for parsed freeblock with some extra meta-data '''

    def __init__(s, parsed_freeblock, pagenumber=None, pageoffset=None, pagesource=None):
        ''' initialize Freeblock object, optionally setting pagenumber and pageoffset '''

        s.next_freeblock = parsed_freeblock.next_freeblock
        s.header_offset = parsed_freeblock.offset
        s.data_offset = s.header_offset + 4
        s.size = parsed_freeblock.size
        s.data_size = s.size - 4
        # this is the data *after* the 4 byte freeblock header
        s.data = parsed_freeblock.block.data()
        s.pageoffset = pageoffset
        s.pagenumber = pagenumber
        s.pagesource = pagesource


class Unallocated():
    ''' wrapper for unallocated area within a btree page, with some extra meta-data '''

    def __init__(s, unallocated, pagenumber=None, pageoffset=None, pagesource=None):
        ''' initialize Unallocated object, optionally setting pagenumber and pageoffset '''

        s.header_offset = None
        s.data_offset = unallocated.offset
        s.size = unallocated.size
        s.data_size = s.size
        s.data = unallocated.data()
        s.pageoffset = pageoffset
        s.pagenumber = pagenumber
        s.pagesource = pagesource


class AllocatedCell():
    ''' wrapper for an allocated cell within a btree page, for testing recovery on allocated cells
    '''

    def __init__(s, cell):
        ''' initialize AllocatedCell object '''

        s.pagenumber = cell.pagenumber
        s.pageoffset = cell.pageoffset
        s.pagesource = cell.pagesource
        s.cellnumber = cell.cellnumber

        # since we are parsing a cell, we know the rowid and cellnumber
        s.rowid = cell.parsed_cell.rowid

        # the size of the cell itself (not taking any overflow into account)
        cell_size = cell.parsed_cell.size
        # the size of the cell minus the inline_payload size
        cell_metadata_size = cell_size - cell.parsed_cell.inline_payload.size
        # the total size of the payload, including overflow (if any)
        s.data_size = cell.parsed_cell.payloadsize
        # the total size consists of all metadata + payload
        s.size = cell_metadata_size + s.data_size

        # the offset of the inline_payload within the cell is taken
        # as data offset, even though the data is fragmented when there is overflow
        s.data_offset = cell.parsed_cell.inline_payload.offset

        # combine the data blocks into a single bitstream (collects overflow as well)
        s.data = _block.allblocklistdata(cell.payload.blocklist)

        # The header holds the payloadsize and the rowid in varints, so it's
        # size needs to be determined. Without overflow, we can determine the
        # header_size by subtracting inline_payload_size from cell size
        header_size = cell_size - cell.parsed_cell.inline_payload.size

        # now, the total size depends on whether or not we have overflow
        if cell.parsed_cell.first_overflow_page is None:
            s.has_overflow = False
        else:
            s.has_overflow = True
            # with overflow, the cell includes a 4 bytes overflow page pointer
            # at the end, so we need to subtract this from the header_size
            header_size -= 4

        # derive header offset from data offset and header size
        s.header_offset = s.data_offset - header_size


class FreelistCell():
    ''' wrapper for an allocated cell within an unallocated freelist btree page
    '''

    def __init__(s, raw_cell, pagenumber=None, pageoffset=None, cellnumber=None, pagesource=None):
        ''' initialize FreelistCell object '''

        s.pagenumber = pagenumber
        s.pageoffset = pageoffset
        s.cellnumber = cellnumber
        s.pagesource = pagesource

        # since we are parsing a cell, we know the rowid
        s.rowid = raw_cell.rowid

        # the size of the cell structure, including header and optional overflow page pointer
        s.size = raw_cell.size
        # the size of the inline payload (we do not include overflow)
        s.data_size = raw_cell.inline_payload.size

        # the offset of the inline payload
        s.data_offset = raw_cell.inline_payload.offset
        # we only include the inline_payload, since we can not be sure
        # that the overflow page is still intact
        s.data = raw_cell.inline_payload.data()

        # The header holds the payloadsize and the rowid in varints, so it's
        # size needs to be determined. Without overflow, we can determine the
        # header_size by subtracting inline_payload_size from cell size
        header_size = s.size - s.data_size

        # check if cell has payload overflow
        if raw_cell.first_overflow_page is None:
            s.has_overflow = False
        else:
            s.has_overflow = True
            # with overflow, the cell includes a 4 bytes overflow page pointer
            # at the end, so we need to subtract this from the header_size
            header_size -= 4

        # determine offset of the cell header
        s.header_offset = s.data_offset - header_size


class UnallocatedCell():
    ''' wrapper for an allocated cell within an unallocated (superseded, outdated) btree page
    '''

    def __init__(s, raw_cell, pagenumber=None, pageoffset=None, cellnumber=None, pagesource=None):
        ''' initialize UnallocatedCell object '''

        s.pagenumber = pagenumber
        s.pageoffset = pageoffset
        s.cellnumber = cellnumber
        s.pagesource = pagesource

        # since we are parsing a cell, we know the rowid
        s.rowid = raw_cell.rowid

        # the size of the cell structure, including header and optional overflow page pointer
        s.size = raw_cell.size
        # the size of the inline payload (we do not include overflow)
        s.data_size = raw_cell.inline_payload.size

        # the offset of the inline payload
        s.data_offset = raw_cell.inline_payload.offset
        # we only include the inline_payload, since we can not be sure
        # that the overflow page is still intact
        s.data = raw_cell.inline_payload.data()

        # The header holds the payloadsize and the rowid in varints, so it's
        # size needs to be determined. Without overflow, we can determine the
        # header_size by subtracting inline_payload_size from cell size
        header_size = s.size - s.data_size

        # check if cell has payload overflow
        if raw_cell.first_overflow_page is None:
            s.has_overflow = False
        else:
            s.has_overflow = True
            # with overflow, the cell includes a 4 bytes overflow page pointer
            # at the end, so we need to subtract this from the header_size
            header_size -= 4

        # determine offset of the cell header
        s.header_offset = s.data_offset - header_size


###########
# walkers #
###########

# This sections contains functions that walk over types of free spaces within
# a database file


def _freeblock_walker(db, rootpagenumber):
    ''' Generates sequence of all freeblocks within the btree starting at rootpagenumber '''

    pages = db.treewalker(rootpagenumber)
    for page in pages:
        for freeblock in page.page.freeblocks:
            yield Freeblock(freeblock, page.pagenumber, page.pageoffset, page.pagesource)


def _unallocated_walker(db, rootpagenumber):
    ''' Generates sequence of the unallocated area's within btree starting at rootpagenumber

    NOTE: this is the unallocated area between the cellpointer area and the first cell
    '''

    pages = db.treewalker(rootpagenumber)
    for page in pages:
        yield Unallocated(page.page.unallocated, page.pagenumber, page.pageoffset, page.pagesource)


def _freespace_walker(db, rootpagenumber):
    ''' yields freeblocks and unallocated space within btree starting at rootpagenumber '''

    for fb in _freeblock_walker(db, rootpagenumber):
        yield fb

    for ua in _unallocated_walker(db, rootpagenumber):
        yield ua


def _allocated_walker(db, rootpagenumber):
    ''' yields AllocatedCell objects for testing purposes '''

    for cell in db.cellwalker(rootpagenumber):
        yield AllocatedCell(cell)


##################
# table analysis #
##################

# This section contains functionality related to scanning tables for the type
# of data that is stored, which gives more accurate record-header scanning
# based on the observed recordheaders than simply relying on column affinity.
# The type of data is stored in the record header, which consists of typecodes
# (which encode the serial_type of the associated column) so we are basically
# scanning record headers to identify the serial_types in each column.


def _schema_based_allowed_serialtypes(db, tablename):
    ''' determine the allowed serialtypes for each column in given table based on the schema

    Here, the numbers 0 through 9 correspond to the fixed serial types as used
    in the record headers. The value -1 is used to indicate BLOB, and the value
    -2 is used to indicate TEXT, similar to signature based SQLite recovery tools.
    '''

    tbl = db.tables[tablename]

    allowed_types = []
    for idx, column in enumerate(tbl.columns):
        if idx == tbl.ipk_col:
            # the INTEGER PRIMARY KEY column has NULL value in it's record-header position
            allowed_types.append({0})
        elif column.affinity == 'TEXT':
            # columns with TEXT affinity are NULL, TEXT or BLOB
            allowed_types.append({0,-1,-2})
        else:
            # all other column affinities can be stored in any of the storage classes
            allowed_types.append({-1,-2,0,1,2,3,4,5,6,7,8,9})
        if column.notnull is True:
            # remove the null type if column has NOT NULL constraint
            allowed_types[idx].remove(0)

    return allowed_types


def _scan_btree_typecodes(db, rootpagenumber):
    ''' yield serial typecodes for allocated records in btree with the given rootpage '''

    recheaders = db.recordheaders(db.cellwalker(rootpagenumber))
    tcodes = (tuple(r.parsed_recordheader.serialtypes) for r in recheaders)
    for tc in tcodes:
        yield tc


def _observed_typecodes(tcodes):
    ''' count occurence of typecodes in each column in the sequence of typecodes

    This function is used to determine for each column how often each typecode
    occurs. This is done by merging all typecodes in a specific column into a
    Counter object, that counts the occurence of each serialtype value per
    column. This allows us to detect invariants throughout all records that can
    be used for the recovery. In addition we can build a signature from this
    that can be used for signature based recovery.

    Consider these typecodes:

        (0, 65, 9, 37, 1, 8)
        (0, 65, 8, 37, 1, 6)
        (0, 65, 8, 37, 1, 6, 6)
        (0, 64, 8, 35, 1, 8, 6, 0)

    One observation that can be made is that the total number of columns may
    vary between records. This is caused by the ALTER TABLE statement by which
    columns can be added. These added columns will have a default value, which
    is used to retreive their value for already stored records. This means that
    the old records are not updated and we can have records of varying length.

    However, since we know that new columns are only added at the end, we can
    still collect them in one list, since the common first columns always have
    the same meaning within the allocated (and removed) records. So, in the
    above example we would get the following result:

        [Counter({0:4}, Counter({65:3, 64:1}), ... , Counter({6:2}), Counter({0,1})]
    '''

    counters = []
    for tcode in tcodes:
        # make sure we have the proper amount of Counters and update as we encounter
        # wider records
        if len(counters) != len(tcode):
            added_columns = len(tcode) - len(counters)
            for i in range(added_columns):
                counters.append(_Counter())
        # and update their values
        for idx, tcode in enumerate(tcode):
            counters[idx].update([tcode])
    return counters


def _observation_based_allowed_serialtypes(typecode_counters, expand_numeric=False):
    ''' convert typecode list to set of allowed serialtypes per column '''

    numeric = {1,2,3,4,5,6,7,8,9}
    null = {0}
    blob = {-1}
    text = {-2}
    # most columns can be any of the available serialtypes
    all_types = numeric.union(null).union(blob).union(text)

    allowed_types = []
    for idx, counter in enumerate(typecode_counters):
        column_allowed = set()
        for typecode, count in counter.items():
            if typecode in numeric:
                if expand_numeric is True:
                    column_allowed.update(numeric)
                else:
                    column_allowed.add(typecode)
            elif typecode in null:
                column_allowed.update(null)
            elif typecode >= 12 and typecode % 2 == 0:
                column_allowed.update(blob)
            elif typecode >= 13 and typecode % 2 == 1:
                column_allowed.update(text)
        allowed_types.append(column_allowed)

    return allowed_types


def _observed_max_varint_widths(typecode_counters):
    ''' determined allowed width of each typecode varint based on the typecode_counters dictionary

    This can be used to determine what sequence of varints can be a potential
    record header for the associated table, based on the width of the
    individual varints in the sequence. We often see that false-positives have
    several large varint values, for example when a sequence of string
    characters are parsed as varints. Limiting the allowed width of each varint
    / typecode will remove such false positives from the sequence of potential
    record headers. This approach is a bit less strict than using full
    signatures based on the allocated data, because we only look at the size of
    each column's varint in the record-header '''

    widths = []

    for colidx, counter in enumerate(typecode_counters):
        # initially, assume that the varint for this column is < 127, consuming 1 byte
        widths.append(1)

        # now, for each occurrence, determine the actual width
        for typecode, count in counter.items():
            curwidth = None
            if typecode < 127:
                # we already assumed minimal width 1
                pass
            elif typecode < 16384:
                if widths[colidx] < 2: widths[colidx] = 2
            elif typecode < 2097152:
                if widths[colidx] < 3: widths[colidx] = 3
            elif typecode < 268435456:
                if widths[colidx] < 4: widths[colidx] = 4
            elif typecode < 34359738368:
                if widths[colidx] < 5: widths[colidx] = 5

    return widths


def _observations_per_column(typecode_counters):
    ''' for each column, store how many observations where made

    This is used to detect if columns have been added to a table using the
    ALTER TABLE statement during the existence of the database. In this case,
    the latter columns will have less observations than the earlier columns.
    This, in turn can be used to target the various number of columns in our
    recordheader detection algorithm '''

    counts = []

    for colidx, counter in enumerate(typecode_counters):
        # now, for each occurrence, determine the actual number of observations
        counts.append(sum([c for c in counter.values()]))
    return counts


def _text_and_blob_size_stats(typecode_counter):
    ''' return statistics on the TEXT and BLOB sizes in the given typecode_counter '''

    _size_stats = _nt('size_stats', 'max min mean median mode mode_frequency stdev most_common total')
    _dynamic_stats = _nt('dynamic_size_stats', 'text_stats blob_stats')

    # first determine the amount of BLOB and TEXT values in this typecode_counter
    total_texts = sum([c for tc, c in typecode_counter.items() if (tc > 13 and tc % 2 != 0)])
    total_blobs = sum([c for tc, c in typecode_counter.items() if (tc > 12 and tc % 2 == 0)])

    text_sizes = []
    blob_sizes = []
    max_text = 0
    min_text = 2**31
    max_blob = 0
    min_blob = 2**31
    text_size_counter = _Counter()
    blob_size_counter = _Counter()
    total_text = 0
    total_blob = 0

    for tc, count in typecode_counter.items():
        if tc >= 13 and tc % 2 != 0:
            size = int((tc - 13) / 2)
            size_list = [size,]*count
            text_sizes.extend(size_list)
            text_size_counter.update(size_list)
            total_text += count
            if size > max_text:
                max_text = size
            if size < min_text:
                min_text = size

        if tc >= 12 and tc % 2 == 0:
            size = int((tc - 12) / 2)
            size_list = [size,]*count
            blob_sizes.extend(size_list)
            blob_size_counter.update(size_list)
            total_blob += count
            if size > max_blob:
                max_blob = size
            if size < min_blob:
                min_blob = size

    text_stats = None
    blob_stats = None
    text_mode_fraction = None
    blob_mode_fraction = None
    if len(text_sizes) > 1 and total_texts != 0:
        try:
            text_mode = _statistics.mode(text_sizes)
            for tc, count in typecode_counter.items():
                size = int((tc - 13) / 2)
                if size == text_mode:
                    text_mode_fraction = count / total_texts
        except _statistics.StatisticsError:
            text_mode = None
            text_mode_fraction = None
        text_stats = _size_stats(max_text, min_text, _statistics.mean(text_sizes),
                                 _statistics.median(text_sizes), text_mode, text_mode_fraction,
                                 _statistics.stdev(text_sizes), text_size_counter.most_common(3),
                                 total_text)
    if len(blob_sizes) > 1:
        try:
            blob_mode = _statistics.mode(blob_sizes)
            for tc, count in typecode_counter.items():
                size = int((tc - 12) / 2)
                if size == blob_mode:
                    blob_mode_fraction = count / total_blobs
        except _statistics.StatisticsError:
            blob_mode = None
            blob_mode_fraction = None

        blob_stats = _size_stats(max_blob, min_blob, _statistics.mean(blob_sizes),
                                 _statistics.median(blob_sizes), blob_mode, blob_mode_fraction,
                                 _statistics.stdev(blob_sizes), blob_size_counter.most_common(3),
                                 total_blob)

    return _dynamic_stats(text_stats, blob_stats)


def _collect_text_and_blob_size_stats(typecode_counters):
    ''' runs text_and_blob_size_stats on each typecode_counter in the list of typecode_counters '''

    stats = []
    for counter in typecode_counters:
        results = _text_and_blob_size_stats(counter)
        if results.text_stats is None and results.blob_stats is None:
            stats.append(None)
        else:
            stats.append(results)
    return stats


def _determine_added_columns(observations_per_column):
    ''' determines if any columns have been added using the ALTER TABLE statement '''

    added_columns = 0
    if len(set(observations_per_column)) != 1:
        # not all columns occur equally often, one or more columns have been added later
        # scan over the total number of columns and count all observations count changes
        curval = observations_per_column[0]
        for s in observations_per_column:
            if s != curval:
                if s >= curval:
                    raise ValueError("we only expect later added columns to have less observations")
                added_columns += 1
    return added_columns


###################
# varint scanning #
###################

# This section contains functionality related to searching for recordheaders by
# scanning for valid sequences of varints that could correspond to a
# recordheader. The main idea is that we try to parse through all free-space in
# the database and look for potential record headers. Initially, we do this by
# scanning for valid sequences of a certain amount of varints. This number of
# varints is determined by the recovery_parameters obtained earlier.

_varint_candidate = _nt('varint_candidate', 'containing_object scantype startcol '
                                            'endcol offset varints stypes')


class ScanType(_Enum):
    ''' Enum indicating which type of scanner produced the varint_candidate '''

    RawData = 0
    NativeBtree = 1
    AlienBtree = 2
    IndexBtree = 3
    FreeList = 4
    SupersededPages = 5
    OutdatedPages = 6
    WalSlack = 7
    Allocated = 9


def _varints_to_generic_stypes(varints):
    ''' convert list of varint (value,width) tuples to list of serialtypes '''

    res = []
    for v, s in varints:
        if v >= 12 and v % 2 == 0:
            res.append(-1)
        elif v >= 13 and v % 2 != 0:
            res.append(-2)
        else:
            res.append(v)
    return res


def _varint_cache(bytes_):
    ''' prepare a varint cache for the given bytes array

    Parsing individual varints at each offset is expensive, so instead we make
    a cache by converting the given bitstream to a sequence of varints,
    starting at the given offset

    Note that this will likely include many false-positives and garbage
    varints, for example when we are parsing an area that does not contain
    actual varints. If, for example, more than 9 bytes all have their upper bit
    set to 1, we end up with a sequence of many large 9 byte varints that have
    no actual meaning in the database format.

    Returns a sequence of varints, and two dictionaries mapping offset to index.
    '''

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    # The first varint might be 'hidden' in this initial scan, for example when
    # the previous byte P (that should not have been part of the varint
    # sequence) has it's upper bit set. In this case, the next byte Q will be
    # interpreted as part of the varint that starts one byte earlier, instead
    # of a single 1-byte varint:

    #  P      Q      R      S      T      U      V      W      X      Y      Z
    # +------+------+------+------+------+------+------+------+------+------+------+
    # | 0x81 | 0x01 | 0x08 | 0x81 | 0x04 | 0x06 | 0x81 | 0x86 | 0x4f | 0x04 | 0x82 |
    # +------+------+------+------+------+------+------+------+------+------+------+

    # So if we start scanning at P, we read varint value 129, whereas if we
    # start scanning at Q, we read value 1. A priori, we can not know where the
    # sequence of varints starts, so the interpretation of the first varint
    # depends on the start offset.

    # To analyse this problem further, the following shows the interpretation
    # of varints when we start scanning at each offset P through Z:

    # P: 129 - 8 - 132 - 6 - 17231 - 4 - error
    # Q:   1 - 8 - 132 - 6 - 17231 - 4 - error
    # R:       8 - 132 - 6 - 17231 - 4 - error
    # S:           132 - 6 - 17231 - 4 - error
    # T:             4 - 6 - 17231 - 4 - error
    # U:                 6 - 17231 - 4 - error
    # V:                     17231 - 4 - error
    # W:                       847 - 4 - error
    # X:                        79 - 4 - error
    # Y:                             4 - error
    # Z:                                 error

    # As we can see, depending on where we start scanning, we may get different
    # values for the first varint in our sequence. Since a byte array can
    # contain multiple varint sequences, and because there is no way of knowing
    # where each sequence starts, we can not a priori determine which offsets
    # should and which should not be in the cache. For example, in the byte
    # array above we can have 2 small varint sequences (offset Q through U and
    # offset W through Y), but if we start scanning at offset P, both offsets
    # are not in the cache:

    # Cache 1:

    # P: 129
    # Q: not in cache
    # R: 8
    # S: 132
    # T: not in cache
    # U: 6
    # V: 17231
    # W: not in cache
    # X: not in cache
    # Y: 4
    # Z: error

    # The actual cache should be:

    # Cache 2:

    # P: not in cache
    # Q: 1
    # R: 8
    # S: 132
    # T: not in cache
    # U: 6
    # V: not in cache
    # W: 847
    # X: not in cache
    # Y: 4
    # Z: error

    # We can solve this problem in two ways:

    # 1) whenever we have parsed a multi-byte varint, parse the individual
    # varints that are 'consumed' by the multi-byte varint and add these to the
    # cache as well. This way, we have an interpreted varint for each offset,
    # which in our example results in:

    #     P: 129
    #     Q: 1
    #     R: 8
    #     S: 132
    #     T: 4
    #     U: 6
    #     V: 17231
    #     W: 847
    #     X: 79
    #     Y: 4
    #     Z: error

    # 2) leave holes in the cache, and only when requesting a varint from the
    # cache for an offset that is not in the cache (since it is consumed by a
    # larger varint starting one or more bytes earlier), re-parse the bytes at
    # that given offset from the original bitstream.  In our example above,
    # starting at offset P this would result in a cache as shown under Cache 1.

    # The downside of 1 is that we have to re-parse some bytes multiple times,
    # which can be expensive when parsing an area that does not contain any
    # actual varints. This is especially true when many of these bytes have a
    # value > 127 (upper bit set). Moreover, the problem with approach 1 is
    # that we no longer have the correct sequence of varints directly after
    # multi-byte varints. For example, if we start at V, we expect the next
    # varint to be 4, however, we have now corrupted this sequence by adding
    # the varint- values for the sub-bytes of the varint starting at V. Thus,
    # we can not use this approach.

    # The downside of 2 is that we can not fetch all varints from cache and we
    # have to re-parse the bytes at request time.

    # Since option 1 corrupts our sequence, and since we are likely to carve
    # through many area's that do not contain any varints, we opt for solution
    # 2. This way we can still cache most of the varints safely, as long as we
    # re-parse whenever we are trying to start at an offset that is inside one
    # of the >1-byte varints in our cache.

    # Note that whenever an offset is in the cache and we request a sequence of
    # n varints from the cache, we get the same results from the cache as when
    # we would parse the bytes at the given offset as a sequence of n varints
    # directly. Thus, each cache hit will yield the correct sequence of varints

    # length of bitstring in bytes
    length = len(bytes_)

    # parsing everything as varints will fail if the last bytes have their
    # upper bit set (see offset Z in example above), so first determine how
    # much we can cache this way by checking the offset of the last byte with
    # it's lower bit unset
    cacheable_length = length
    for i in range(length-1, -1, -1):
        if bytes_[i] & 0x80 != 0:
            cacheable_length -=1
        else:
            break

    # cache the varints in this bytes array
    vcache = _structures.varints(bytes_, 0, cacheable_length)

    # since varints can be multiple bytes, the index in the vcache does not
    # reflect the actual offset within the bytes_ array. Also, we need to be
    # able to search for varint_sequences by offset. For this we add a second
    # structure to the cache, mapping varint offset to it's index in the
    # sequence.
    v_offset=0
    vcache_offsets = {}
    for idx, varint in enumerate(vcache):
        vcache_offsets[v_offset] = idx
        v_offset += varint[1]

    return vcache, vcache_offsets


def _parse_as_varints(bytes_, offset, varint_count):
    ''' parse the bytes at given offset as a sequence of varint_count varints

    Returns the sequence of varints or raises an Exception when data could not be parsed as such
    '''

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    # Theoretically, a single varint can be 9 bytes wide. This means that if we
    # need varint_count varints, the theoretical maximum size of the area to
    # scan for varints is varint_count * 9.  However, this can only be true for
    # TEXT and BLOB fields, all others have a 1 byte varint describing the
    # serial type. The maximum size of a TEXT or BLOB is determined by the
    # compile-time option SQLITE_MAX_LENGTH, which defaults to 1000000000 bytes
    # (~ 950 MB). A BLOB of this length is represented as follows:

    # (N-13)/2 = 1000000000
    # N - 13 = 2000000000
    # N = 2000000013

    # A TEXT of this length is represented as follows:

    # (N-12)/2 = 1000000000
    # N - 12 = 2000000000
    # N = 2000000012

    # Thus, for this default maximum the width of a serial type in the record
    # header is at most 5 bytes
    # >>> tovarint(2000000013).len / 8
    # 5.0

    # So, in order to find varint_count varints in a row, without any prior
    # knowledge about the type of records we are dealing with, we need a
    # minimum of varint_count bytes, and a maximum of varint_count * 5 bytes,
    # assuming all fields hold TEXT or BLOB of maximum size.

    # to summarize, we must find the smallest sequence of bytes that lead to
    # varint_count varints at given offset. Start with smallest bytecount, and
    # gradually increase bytecount until a sequence of the desired amount of
    # varints is returned.

    for width in range(varint_count, varint_count * 5):
        try:
            varints = _structures.varints(bytes_, offset, width, limit=varint_count, maxwidth=5)
            # check if we have the expected amount of varints, if not try again with one more byte
            if len(varints) == varint_count:
                # as soon as we found a valid sequence, return it
                return varints
            else:
                continue
        except:
            pass

    # if we get here, no valid varints sequence was found
    return None


def _get_varints(bytes_, offset, varint_count, vcache, vcache_offsets):
    ''' return varint sequence from given bytes_ array at given offset

    We first check if the given offset has a cached entry in the vcache and
    return the varint sequence from the cache if possible. Otherwise, the bytes
    at given offset are parsed as varints.

    Note that the caller is responsible for making sure the vcache and
    vcache_offsets correspond to the bytes_ array, otherwise this will just
    return garbage. '''

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    length = len(bytes_)

    if offset < 0 or offset >= length:
        raise _exceptions.InvalidArgumentException('offset is not withing bytes array')

    # unallocated area may contain some left over cellpointers followed by an
    # area with only 0x00 bytes, followed by the remnants of older records. In
    # this case, there is always a freeblock or cell header prior to the record
    # to reconstruct. When the recordheader consists of only null-bytes, this
    # is either not a valid recordheader or the record will not yield much
    # information, so we can safely skip all area's that are equal or longer
    # than the minimum recordheader size for this table and that contain only
    # null-bytes. Regions of null-bytes will always be parsed as valid varints
    # and so these will be in the cache. In this case the varint sequence will
    # be [(0,1),(0,1),...,(0,1)] and this will be of no use to us.
    all_zero_parsed = [(0,1)]*varint_count
    all_zero_bytes = b'\x00'*varint_count

    if offset in vcache_offsets:
        # HIT: fetch the sequence from the cache
        v_index = vcache_offsets[offset]
        varints = vcache[v_index:v_index+varint_count]
        if len(varints) != varint_count:
            # there is a varint sequence at this offset, but it is too short
            return None
        if varints == all_zero_parsed:
            return None
        stypes = _varints_to_generic_stypes(varints)
        return varints, stypes

    else:
        # MIS: parse varints at given offset
        # first check if we have a sequence of null bytes
        if bytes_[offset:offset+varint_count] == all_zero_bytes:
            # most sequences of null-bytes are in the varint cache,
            # but when the previous byte has its upper bit set,
            # the current byte offset is not in the cache, so we
            # need to check for this here as well.
            return None
        varints = _parse_as_varints(bytes_, offset, varint_count)
        if varints is not None:
            stypes = _varints_to_generic_stypes(varints)
            return varints, stypes
        else:
            return None


def _varint_scanner(bytes_, varint_count):
    ''' yield sequences of varint_count varints, from given region in bytes_ array

    For recovery of records we need to look for recordheaders, which consists
    of two varints for the rowid and the recordsize, followed by a sequence of
    varints holding the serial typecodes for each field in the record.

    This function can be used to scan the given bytes array for locations where
    we can successfully parse the given number of varints, so that we have a
    set of candidate locations that we can compare against serial type
    signatures.

    Scanning is stopped varint_count bytes prior to the end of the array, since
    we are only interested in varint_count sized sequences. The varint cache
    (vcache) is used to prevent having to reparse sequences if we shift only a
    single byte during the scan.

    We know that, depending on where the deleted record exists (freeblock,
    unallocated area), and depending on the width of the rowid varint and the
    width of the record size varint, at most the first 2 bytes of the
    recordheader can be overwritten by the 4-byte freeblock header (which does
    not use varints but uses two 16 bit values for next_freeblock_offset and
    freeblock_size.

    Thus, it can be a good strategy to search for sequences of varints with
    length n-2 if n is the number of columns in the table (or the minimally
    encountered number of columns when a table has been altered using ALTER
    TABLE statement to add more columns during the lifetime of the database.

    Note that the caller is responsible for making sure the vcache and
    vcache_offsets correspond to the bytes_ array, otherwise this will just
    return garbage. '''

    # NOTE: this function used to accept an offset and a size to limit scanning
    #       of the given bytes_ array to a sub-region. However, this turned out to
    #       be problematic since the vcache could contain varint sequences of the
    #       proper length (varint_count) that end outside the defined region. In this
    #       case, the _get_varints function would return a valid sequence from the
    #       cache whereas it spills over the defined region. So, we now create the
    #       varint_cache within this function to make sure it is based on the same
    #       bytes_ array and does not contain varint_sequences that spill over the
    #       bytes_ array. Also, caching the entire database file does not turn out
    #       to be faster. This note is here mainly to prevent myself from attempting
    #       to "optimize" this later again.

    if not isinstance(bytes_, bytes):
        raise _exceptions.InvalidArgumentException("requires a bytes array as argument")

    # check arguments
    if varint_count < 0:
        raise _exceptions.InvalidArgumentException('varint_count is negative')

    length = len(bytes_)

    # Not an error, but simply a stop condition
    if length < varint_count:
        return

    # if we have only null bytes, no need to scan for varints, stop condition
    if bytes_ == b'\x00'*length:
        return

    # create a varint_cache for this bytes_ array
    vcache, vcache_offsets = _varint_cache(bytes_)

    # the region in which we search for varints is the entire length, but since
    # we want a sequence of varint_count varints, we can stop varint_count bytes
    # prior to that offset, assuming that each varint consumes 1 byte.
    end_pos = length - varint_count

    # scan over offsets in the bytes_ array, and look for sequences of varint_count varints
    for o in range(0, end_pos):
        res = _get_varints(bytes_, o, varint_count, vcache, vcache_offsets)
        if res is None:
            # _get_varints returns None if the sequence has too few varints or contains
            # only null bytes
            continue

        # if we get here, we have a valid sequence, yield offset, varints and serialtypes
        yield o, res[0], res[1]


def _scan_btree_for_varints(db, rootpagenumber, varint_count):
    ''' scan free areas in btree with rootpagenumber for sequences of varint_count varints
    '''

    for free_area in _freespace_walker(db, rootpagenumber):
        for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
            yield free_area, offset, varints, stypes


def _scan_btree_allocated_for_varints(db, rootpagenumber, varint_count):
    ''' scan allocated cells in btree with rootpagenumber for sequences of varint_count varints

    This is mainly used for testing if recovery works on allocated cells
    '''

    for alloc in _allocated_walker(db, rootpagenumber):
        for offset, varints, stypes in _varint_scanner(alloc.data.bytes, varint_count):
            yield alloc, offset, varints, stypes


def _scan_freelist_for_varints(db, varint_count, rootpage_for_testing=None):
    ''' scan through freelist pages for varints '''

    if rootpage_for_testing is not None:
        print("WARNING: running freelist recovery on allocated btree for testing purposes!")
        pages = db.treewalker(rootpage_for_testing)
    else:
        pages = db.freelist_pages()

    for p in pages:
        # Note that in this function we use the page yielded by the generator, which is
        # a freelist page, and we have a parsed page when the freelistpage can be parsed
        # as an old btree page. The pagenumber and pageoffset are properties of the page
        # yielded from the generator (freelistpage), whereas other properties are taken
        # from the parsed btree-page (if applicable)
        pagenumber = p.pagenumber
        pageoffset = p.pageoffset
        pagesource = p.pagesource

        if hasattr(p.page, 'nextfreelisttrunkpage'):
            # this is a freelisttrunk page, consisting of a small header, freelistleafpointers,
            # and an unallocated area. Search the unallocated area for varint sequences
            free_area = Unallocated(p.page.unallocated, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes
            # move on to next page
            continue

        # if we get here, this is a freelist leafpage, get its data as a block object
        pagedata = db.get_page_data(pagenumber)
        try:
            # try to parse as a btree page
            parsed = _structures.btree_page(pagedata.data(), 0, db.header.pagesize, db.header.usablepagesize)
        except:
            # this is not a btree page, treat as a single unallocated area and scan
            # for varint sequences in the entire page
            free_area = Unallocated(pagedata, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes
            # move on to next page
            continue

        # if we get here, we where able to parse a btree page, scan for varints in the
        # various regions (allocated cells, freeblocks, unallocated space)

        # if this is a table_leaf cell, the page contains cells with records
        if parsed.pagetype == 'table_leaf':
            # iterate over the cells in rowid order
            rowids_on_page = [r for r in parsed.rowidmap.keys()]
            rowids_on_page.sort()
            for rowid in rowids_on_page:
                cellno = parsed.rowidmap[rowid]
                cell = parsed.cells[cellno]
                free_area = FreelistCell(cell, pagenumber, pageoffset, cellno, pagesource)
                # scan the freelist cell for varints
                for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                    yield free_area, offset, varints, stypes

        # If we get here, we have either a table_leaf or table_interior page parsed from the
        # freelist. In the first case, we have already processed the allocated cells above.
        # Next, scan the freeblocks for varints
        for freeblock in parsed.freeblocks:
            free_area = Freeblock(freeblock, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes

        # Finally, scan the unallocated area of the parsed btree page
        free_area = Unallocated(parsed.unallocated, pagenumber, pageoffset, pagesource)
        for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
            yield free_area, offset, varints, stypes


def _scan_superseded_pages_for_varints(db, varint_count):
    ''' scan through the superseded pages for varints '''

    pages = _chain(db.superseded_pages(), db.walfile.superseded_pages())

    for p in pages:
        # Note that in this function we use the page yielded by the generator, which is
        # a generic page, and we have a parsed page when the page can be parsed
        # as an old btree page. The pagenumber and pageoffset are properties of the page
        # yielded from the generator, whereas other properties are taken
        # from the parsed btree-page (if applicable)
        pagenumber = p.pagenumber
        pageoffset = p.pageoffset
        pagesource = p.pagesource

        # we can not use the get_page_data function here, but we know that the entire page
        # is an unallocated block, so we can simply use that block for the pagedata
        pagedata = p.page.unallocated

        try:
            # try to parse as a btree page
            parsed = _structures.btree_page(pagedata.data(), 0, db.header.pagesize, db.header.usablepagesize)
        except:
            # this is not a btree page, treat as a single unallocated area and scan
            # for varint sequences in the entire page
            free_area = Unallocated(pagedata, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes
            # move on to next page
            continue

        # if we get here, we were able to parse a btree page, scan for varints in the
        # various regions (allocated cells, freeblocks, unallocated space)

        # if this is a table_leaf cell, the page contains cells with records
        if parsed.pagetype == 'table_leaf':
            # iterate over the cells in rowid order
            rowids_on_page = [r for r in parsed.rowidmap.keys()]
            rowids_on_page.sort()
            for rowid in rowids_on_page:
                cellno = parsed.rowidmap[rowid]
                cell = parsed.cells[cellno]
                free_area = UnallocatedCell(cell, pagenumber, pageoffset, cellno, pagesource)
                # scan the unallocated cell for varints
                for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                    yield free_area, offset, varints, stypes

        # If we get here, we have either a table_leaf or table_interior page.
        # In the first case, we have already processed the allocated cells above.
        # Next, scan the freeblocks for varints
        for freeblock in parsed.freeblocks:
            free_area = Freeblock(freeblock, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes

        # Finally, scan the unallocated area of the parsed btree page
        free_area = Unallocated(parsed.unallocated, pagenumber, pageoffset, pagesource)
        for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
            yield free_area, offset, varints, stypes


def _scan_outdated_pages_for_varints(db, varint_count):
    ''' scan through the outdated pages for varints '''

    for p in db.walfile.outdated_pages():
        # Note that in this function we use the page yielded by the generator, which is
        # a generic page, and we have a parsed page when the page can be parsed
        # as an old btree page. The pagenumber and pageoffset are properties of the page
        # yielded from the generator, whereas other properties are taken
        # from the parsed btree-page (if applicable)
        pagenumber = p.pagenumber
        pageoffset = p.pageoffset
        pagesource = p.pagesource

        # we can not use the get_page_data function here, but we know that the entire page
        # is an unallocated block, so we can simply use that block for the pagedata
        pagedata = p.page.unallocated

        try:
            # try to parse as a btree page
            parsed = _structures.btree_page(pagedata.data(), 0, db.header.pagesize, db.header.usablepagesize)
        except:
            # this is not a btree page, treat as a single unallocated area and scan
            # for varint sequences in the entire page
            free_area = Unallocated(pagedata, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes
            # move on to next page
            continue

        # if we get here, we were able to parse a btree page, scan for varints in the
        # various regions (allocated cells, freeblocks, unallocated space)

        # if this is a table_leaf cell, the page contains cells with records
        if parsed.pagetype == 'table_leaf':
            # iterate over the cells in rowid order
            rowids_on_page = [r for r in parsed.rowidmap.keys()]
            rowids_on_page.sort()
            for rowid in rowids_on_page:
                cellno = parsed.rowidmap[rowid]
                cell = parsed.cells[cellno]
                free_area = UnallocatedCell(cell, pagenumber, pageoffset, cellno, pagesource)
                # scan the unallocated cell for varints
                for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                    yield free_area, offset, varints, stypes

        # If we get here, we have either a table_leaf or table_interior page.
        # In the first case, we have already processed the allocated cells above.
        # Next, scan the freeblocks for varints
        for freeblock in parsed.freeblocks:
            free_area = Freeblock(freeblock, pagenumber, pageoffset, pagesource)
            for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
                yield free_area, offset, varints, stypes

        # Finally, scan the unallocated area of the parsed btree page
        free_area = Unallocated(parsed.unallocated, pagenumber, pageoffset, pagesource)
        for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
            yield free_area, offset, varints, stypes


def _scan_wal_slack_for_varints(db, varint_count):
    ''' scan through the wal slack varints '''

    slackdata = db.walfile.slack
    pageoffset = db.walfile.slack.offset
    pagesource = _database.PageSource.WALFile

    # treat as a single unallocated area and scan for varint sequences
    free_area = Unallocated(slackdata, None, pageoffset, pagesource)
    for offset, varints, stypes in _varint_scanner(free_area.data.bytes, varint_count):
        yield free_area, offset, varints, stypes
        # move on to next page
        continue


def _varint_scan_native_btree(db, tablename, recovery_parameters):
    ''' yields varint candidates from the tables own (native) btree '''

    tbl = db.tables[tablename]
    rootpage = tbl.rootpage

    # since the first varint can be overwritten and any added columns (via ALTER TABLE) are not
    # always present, we only scan for varint sequences corresponding to the columns that are
    # available in all allocated records.
    startcolumn, endcolumn = recovery_parameters.common_columns
    # total number of included columns is equal to endcolumn, if startcolumn is 1
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    # scan unallocated space in the freespace in the btree
    varint_candidates = _scan_btree_for_varints(db, rootpage, included_columns)
    for c in varint_candidates:
        yield _varint_candidate(c[0], ScanType.NativeBtree, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_alien_btrees(db, tablename, recovery_parameters):
    ''' yields varint candidates from btrees from other tables (alien) '''

    # since the first varint can be overwritten and any added columns (via ALTER TABLE) are not
    # always present, we only scan for varint sequences corresponding to the columns that are
    # available in all allocated records.
    startcolumn, endcolumn = recovery_parameters.common_columns
    # total number of included columns is equal to endcolumn, if startcolumn is 1
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    # collect the rootpages of all other tables
    alien_rootpages = [tbl.rootpage for tbl in db.tables.values() if tbl.name != tablename]

    for alienpage in alien_rootpages:
        varint_candidates = _scan_btree_for_varints(db, alienpage, included_columns)
        for c in varint_candidates:
            yield _varint_candidate(c[0], ScanType.AlienBtree, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_index_btrees(db, tablename, recovery_parameters):
    ''' yields varint candidates from index btrees '''

    # NOTE: I've observed at least one db where an index page contained a larger
    #       unallocated area with records from some other table. This illustrates
    #       that pages can be re-used without wiping them first.

    # since the first varint can be overwritten and any added columns (via ALTER TABLE) are not
    # always present, we only scan for varint sequences corresponding to the columns that are
    # available in all allocated records.
    startcolumn, endcolumn = recovery_parameters.common_columns
    # total number of included columns is equal to endcolumn, if startcolumn is 1
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    # collect the rootpages of all other tables
    index_rootpages = [tbl.rootpage for tbl in db.sqlite_master.indices.values()]

    for indexpage in index_rootpages:
        varint_candidates = _scan_btree_for_varints(db, indexpage, included_columns)
        for c in varint_candidates:
            yield _varint_candidate(c[0], ScanType.IndexBtree, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_allocated_btree(db, tablename, recovery_parameters):
    ''' yield varint candidates from the allocated cells in the tables btree for testing purposes
    '''

    tbl = db.tables[tablename]
    rootpage = tbl.rootpage
    startcolumn, endcolumn = recovery_parameters.common_columns
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    varint_candidates = _scan_btree_allocated_for_varints(db, rootpage, included_columns)
    for c in varint_candidates:
        yield _varint_candidate(c[0], ScanType.Allocated, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_freelist_pages(db, tablename, recovery_parameters, debug=False):
    ''' yield varint candidates from the freelist pages

    If debug is True, the recovery will be done on the tables allocated btree,
    instead of on the actual freelist pages. This is only for debugging purposes
    '''

    tbl = db.tables[tablename]
    rootpage = tbl.rootpage
    startcolumn, endcolumn = recovery_parameters.common_columns
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    if debug is True:
        varint_candidates = _scan_freelist_for_varints(db, included_columns, rootpage)
    else:
        varint_candidates = _scan_freelist_for_varints(db, included_columns)
    for c in varint_candidates:
        yield _varint_candidate(c[0], ScanType.FreeList, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_superseded_pages(db, tablename, recovery_parameters):
    ''' yield varint candidates from superseded pages
    '''

    startcolumn, endcolumn = recovery_parameters.common_columns
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    varint_candidates = _scan_superseded_pages_for_varints(db, included_columns)
    for c in varint_candidates:
        yield _varint_candidate(c[0], ScanType.SupersededPages, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_outdated_pages(db, tablename, recovery_parameters):
    ''' yield varint candidates from outdated WAL pages
    '''

    startcolumn, endcolumn = recovery_parameters.common_columns
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    varint_candidates = _scan_outdated_pages_for_varints(db, included_columns)
    for c in varint_candidates:
        yield _varint_candidate(c[0], ScanType.OutdatedPages, startcolumn, endcolumn, c[1], c[2], c[3])


def _varint_scan_wal_slack(db, tablename, recovery_parameters):
    ''' yield varint candidates from the WAL slack
    '''

    startcolumn, endcolumn = recovery_parameters.common_columns
    if startcolumn != 1:
        raise ValueError("startcolumn should be 1")
    included_columns = endcolumn

    varint_candidates = _scan_wal_slack_for_varints(db, included_columns)
    for c in varint_candidates:
        yield _varint_candidate(c[0], ScanType.WalSlack, startcolumn, endcolumn, c[1], c[2], c[3])


####################
# varint filtering #
####################

# This section contains functionality related to filtering out false positives
# while scanning over the free space in a database for potential recordheaders,
# based on the recovery_parameters for the given table

_filtered_candidate = _nt('filtered_candidate', 'containing_object scantype startcol '
                                                'endcol offset varints stypes rejected reason')


def _matches_signature(stypes, signature):
    ''' return False if stypes does not match signature, True otherwise '''

    for idx, stype in enumerate(stypes):
        if stype not in signature[idx]:
            return False
    return True


def _has_reserved_stype(stypes):
    ''' return True if stypes contains 10 or 11 (reserved) '''

    if 10 in stypes or 11 in stypes:
        return True
    return False


def _filter_varint_candidates(varint_candidates, recovery_parameters):
    ''' run the given sequence of varint_candidates through a chain of filters

    The filters are ordered from less strict to most strict, and when a
    candidate is rejected, the RejectReason indicates what type of check led to
    the rejection. This can be used to include some of the records that are
    rejected by the more strict filters (but accepted by the less strict
    filters) in further recovery steps.  '''

    # first candidate determines startcol and endcol
    try:
        candidate = next(varint_candidates)
    except StopIteration:
        # no candidates available, stop condition
        return

    startcol = candidate.startcol
    endcol = candidate.endcol
    # the total number of columns is endcol, if startcol is 1
    if startcol != 1:
        raise ValueError("startcol should be 1")
    colcount = endcol

    # determine the various allowed serialtypes based on selected columns
    schema_signature = recovery_parameters.schema_serialtypes[startcol:endcol+1]
    loose_signature = recovery_parameters.loose_observed_serialtypes[startcol:endcol+1]
    strict_signature = recovery_parameters.strict_observed_serialtypes[startcol:endcol+1]

    # filter the first candidate

    if _has_reserved_stype(candidate.stypes) is True:
        yield _filtered_candidate(*candidate, True, RejectReason.ReservedSerialType)
    if _matches_signature(candidate.stypes, schema_signature) is False:
        yield _filtered_candidate(*candidate, True, RejectReason.SchemaBasedSignature)
    elif _matches_signature(candidate.stypes, loose_signature) is False:
        yield _filtered_candidate(*candidate, True, RejectReason.LooseObservedSignature)
    elif _matches_signature(candidate.stypes, strict_signature) is False:
        yield _filtered_candidate(*candidate, True, RejectReason.StrictObservedSignature)
    else:
        yield _filtered_candidate(*candidate, False, RejectReason.NotRejected)

    for candidate in varint_candidates:

        if len(candidate.stypes) != colcount:
            raise ValueError("varint_candidate has different length than first candidate")

        if _has_reserved_stype(candidate.stypes) is True:
            yield _filtered_candidate(*candidate, True, RejectReason.ReservedSerialType)
        elif _matches_signature(candidate.stypes, schema_signature) is False:
            yield _filtered_candidate(*candidate, True, RejectReason.SchemaBasedSignature)
        elif _matches_signature(candidate.stypes, loose_signature) is False:
            yield _filtered_candidate(*candidate, True, RejectReason.LooseObservedSignature)
        elif _matches_signature(candidate.stypes, strict_signature) is False:
            yield _filtered_candidate(*candidate, True, RejectReason.StrictObservedSignature)
        else:
            yield _filtered_candidate(*candidate, False, RejectReason.NotRejected)


def _drop_rejected_candidates(filtered_candidates, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' drops rejected candidates, except those that have a RejectReason > max_drop_reason

    This extra filter can be used to exclude rejected candidates from the
    sequence, which might not always be desireable, for example when one wants
    to log all potential locations that have been considered. However, this can
    also be solved by lowering the max_drop_reason to below the
    SchemaBasedSignature value so that all valid varint seqeunces are included
    in the output sequence.

    The max_drop_reason argument is used to include filtered_candidates that
    are rejected for a more strict reason than the given max_drop_reason. The
    reasons are enumerated in the RejectReason enum and a higher number
    indicates a more stringent requirement. If a candidate has a RejectReason
    enum value less than or equal to given max_drop_reason, it is excluded from
    further consideration. If the RejectReason is higher, it is included for
    further consideration.  '''

    for c in filtered_candidates:
        if c.rejected is False:
            yield c
        elif c.reason.value > max_drop_reason.value:
            yield c


###############################
# recordheader reconstruction #
###############################

# This section contains functionality for reconstruction of recordheaders for
# varint sequence candidates

_filtered_recheader = _nt('filtered_recordheader', 'offset prepended serialtypes rejected reason')


def _valid_header_sizes(candidate, recovery_parameters):
    ''' returns a tuple of the possible header_sizes for the given candidate

    The first part of the recordheader that is most likely to be (partially)
    overwritten is the recordheader size field. In order to reconstruct a
    record, we need to determine which values can potentially be correct for
    the given recordheader candidate. This function generates a sequence of
    record_header_size varints that would fit for the candidate based on the
    recovery parameters for the given table. It only takes the table schema
    into account, no observations of allocated records are used.
    '''

    # The minimum size is determined by the width consumed by the candidate varints
    # incremented with a byte for the missing varint at the start and for the
    # recordheader size field itself
    minsize = sum([v[1] for v in candidate.varints]) + 2

    # the maximum is determined by 4 optional extra varint bytes for the first
    # column and 5 optional varint bytes for each extra column added by ALTER TABLE
    maxsize = minsize + recovery_parameters.added_columns * 5
    if recovery_parameters.ipk_col != 0:
        # if first column is INTEGER PRIMARY KEY column, it's size is 1 byte
        # (it is very common for first column to be IPK column)
        maxsize += 4

    # make a tuple of valid headersizes for this particular candidate
    valid_sizes = []
    for sz in range(minsize, maxsize + 1):
        if sz not in recovery_parameters.possible_headersizes:
            continue
        else:
            valid_sizes.append(sz)

    return tuple(valid_sizes)


def _header_sequences(candidate, recovery_parameters):
    ''' yields sequences of varints that contain the given candidate '''

    # The candidate starts at column 1, skipping over column 0, since the varint for
    # this column can be (partially) overwritten, along with the recordheader_size field
    # that precedes the serialtypes in the recordheader.

    # We know that in most cases, only the first two bytes of a recordheader are overwritten at
    # most. There are some conceivable exceptions, for example when the last added record is
    # deleted, leading not to a freeblock but to an increase of the unallocated area. Then,
    # after the deletion of this record if it is overwritten by multiple smaller records, the
    # cellpointers for these new records can overwrite more than the first two bytes. For this
    # to happen, the record should be overwritten by at least 3 smaller records. In this case,
    # the record is probably beyond reconstruction, because the data part has been mostly
    # overwritten.

    # Also, since we are scanning for signatures based on column 1 through n (excluding column
    # 0), we will not find such sequences when multiple varints have been overwritten. So, for
    # these candidates, we can safely assume that at most the first 2 bytes of the recordheader
    # where overwitten.

    # So, consider the following original data (prior to deletion):

    # +---------+-------+----------------------
    # | hdrsize | col0  | candidate varints
    # +---------+-------+----------------------

    # Now, we have found a candidate, and we need to find out if the hdrsize and col0 varint
    # are still intact or if we should try to reconstruct these. Since both could be still
    # intact or completely overwritten *and* because both could be only a single byte or
    # multi-byte varints, we have to rely on some heuristics.

    # Roughly, we have the following three scenario's when both the headersize *and* the
    # first serialtype only consume 1 byte:

    # A) both are 1 byte, both overwritten or unavailable
    # +---------+-------+----------------------
    # | xxxxxxx | xxxxx | candidate varints
    # +---------+-------+----------------------

    # B) both are 1 byte, only hdr_size overwritten (i.e. because rowid takes 2 bytes)
    # +---------+-------+----------------------
    # | xxxxxxx | col0  | candidate varints
    # +---------+-------+----------------------

    # C) both are 1 byte, none are overwritten (i.e. because cell is now in unallocated area)
    # +---------+-------+----------------------
    # | hdrsize | col0  | candidate varints
    # +---------+-------+----------------------

    # Before we consider other scenario's we need to make an observation concerning
    # the hdrsize. The headersize indicates the total width of the header, including
    # the headersize field itself. With knowledge about the number of columns in the table
    # and knowing the size of our varint candidate, we can know the mimimum and maximum size
    # required for al the serialtypes in the header. In most cases, these sizes will all
    # fit within varint of a single byte. Only if we have a record with over 25 columns that
    # all contain TEXT or BLOB values that all require a varint of 5 bytes to express their
    # size will we need a 2-byte varint for the header size (5*25 = 125 + 2 byte hdrsize = 127)
    # So, for the remainder of this discussion, we will assume that the hdrsize varint is
    # always 1 byte (but we check if this assumption is broken)

    # So now we know that hdrsize is always 1 byte, but the first varint
    # can still be up to 5 bytes. This gives us the following scenario's:

    # D) hdrsize is 1 byte, first serialtype is > 1 byte, first byte overwritten:
    # +---------+--------+----------------------
    # | xxxxxxx | xx |   | candidate varints
    # +---------+--------+----------------------

    # E) hdrsize is 1 byte, first serialtype is > 1 byte, only hdrsize overwritten:
    # +---------+--------+----------------------
    # | xxxxxxx | col0   | candidate varints
    # +---------+--------+----------------------

    # F) hdrsize is 1 byte, first serialtype is > 1 byte, none are overwritten
    # +---------+--------+----------------------
    # |         | col0   | candidate varints
    # +---------+--------+----------------------

    # In all scenario's A through F above, we assume that at most the first 2 bytes
    # have been overwritten. If the headersize is not overwritten, then the first
    # column is also not overwritten. And if the headersize is overwritten, then
    # the first column may or may not be (partially) overwritten.

    # Unless we are dealing with an INTEGER PRIMARY KEY column, we can not be certain
    # about the width of the varint for the first column, without using knowledge on
    # the allocated data. This means that we the first column serialtype can consume
    # 1 through 5 bytes. Add to this the 1 byte for the headersize, and we conclude that
    # we need to start scanning 6 bytes before the candidate in order to see if we
    # can obtain a valid recordheader that contains the candidate.

    # so, start scanning for varint sequences that include our candidate and is preceded
    # by two additional varints (headersize and col0)
    data = candidate.containing_object.data.bytes

    # start at most 6 bytes prior to the candidate
    startoffset = candidate.offset - 6
    if startoffset < 0:
        startoffset = 0

    # create a dictionary with the data slices for each offset
    slicecount = candidate.offset - startoffset
    data_slices = {}
    # create slices of the data for each offset
    slice_idx = 0
    for _offset in range(candidate.offset, startoffset-1, -1):
        data_slices[slice_idx] = (_offset, data[_offset:])
        slice_idx += 1

    # the width of the first varint in our candidate
    col1_width = candidate.varints[0][1]
    col1_varint = candidate.varints[0][0]

    # now, for each slice, read the extra_bytes + col1 as varints and determine
    # if it makes any sense to try to find a recordheader there
    droplist = []
    slice_varints={}
    for extra_bytes, dslice in data_slices.items():
        try:
            varints = _structures.varints(dslice[1], 0, extra_bytes+col1_width, maxwidth=5)
        except:
            # if parsing fails for some reason, the extra_bytes count can not be correct
            droplist.append(extra_bytes)
            continue
        if varints[-1] != candidate.varints[0]:
            # if the last varint is not our col1_varint, we know that
            # the byte prior to our col1 varint has it's upper bit set, which
            # means that this byte can not be part of a recordheader that results
            # in our desired sequence of varints. This in turn means, we do not
            # have to attempt any prepending, we can simply discard this offset
            droplist.append(extra_bytes)
        elif len(varints) > 3:
            # next, we know that we need at most 2 varint values prior to our
            # col1 value. This means that if there are already 3 values prior to
            # our col1 value, the sequence will never lead to a proper recordheader,
            # regardless of what we prepend to it. This means that we can discard all
            # offsets that result in 4 or more varints
            droplist.append(extra_bytes)
        elif len(varints) > 2:
            # furthermore, if we have 3 varints, this means that any prepend
            # operations will only alter the first varint (headersize), leaving
            # the second varint (col0) as is. This means that col0 should conform
            # to the schema based signature. If it does not, there is no use in
            # prepending any bytes.
            # (BUGFIX: use slice [0] since we need the first (and only) element)
            col0_stype = _varints_to_generic_stypes([varints[1]])[0]
            # (BUGFIX: use not in, since schema_serialtypes is a set)
            if col0_stype not in recovery_parameters.schema_serialtypes[0]:
                droplist.append(extra_bytes)
            else:
                slice_varints[extra_bytes] = varints
        else:
            slice_varints[extra_bytes] = varints

    # drop the slices that are not relevant
    for extra_bytes in droplist:
        data_slices.pop(extra_bytes)

    # if we get here, we have hopefully drastically reduced the set of
    # extra_bytes we should read prior to our candidate in order to reconstruct
    # a record header. The next step is to reconstruct recordheaders for each
    # offset

    # based on width of the candidate, we can adjust the allowed sizes
    allowed_sizes = _valid_header_sizes(candidate, recovery_parameters)

    # first check if any of the slices would be valid without prepending
    for extra_bytes, dslice in data_slices.items():
        _offset = dslice[0]
        subdata = dslice[1]

        # take the first byte as headersize
        # (BUGFIX: we need the varint value from the first element, thus the [0][0])
        hdrsize = slice_varints[extra_bytes][0][0]

        if hdrsize in allowed_sizes:
            try:
                # parse hdrsize bytes worth of varints
                varints = _structures.varints(subdata, 0, hdrsize, maxwidth=5)
                if len(varints) <= recovery_parameters.max_varints_in_header:
                    yield (_offset, None, varints)
            except:
                pass

    # before attempting to add headersizes, make a single run over each
    # slice and prepend with the acceptable first bytes for col0. This is
    # done to determine which bytes mess up our col1 value so we don't have
    # to try these later when prepending a headersize as well
    col0_allowed_prepend = {}
    for extra_bytes, dslice in data_slices.items():

        # don't prepend anything if we already have 5 or 6 bytes,
        # since we need the space for the headersize and can not use
        # it for col0
        if extra_bytes > 4:
            continue

        # create a list of allowed extra bytes
        col0_allowed_prepend[extra_bytes] = []

        _offset = dslice[0]
        subdata = dslice[1]
        datalen = len(subdata)

        for p in recovery_parameters.col0_prepend_list:
            newdata = p.bytes + subdata

            # read the first two bytes and check if this doesn't mess
            # with our col1 varint
            varints = _structures.varints(newdata, 0, datalen, limit=2, maxwidth=5)
            if varints[1] != candidate.varints[0]:
                continue
            else:
                col0_allowed_prepend[extra_bytes].append(p)

    # next, check if any of the slices would be valid by prepending hdrsize and/or col0
    for extra_bytes, dslice in data_slices.items():

        # don't prepend anything if we already have 6 bytes
        if extra_bytes == 6:
            continue

        _offset = dslice[0]
        subdata = dslice[1]

        for hdrsize in allowed_sizes:
            prepend = recovery_parameters.possible_headersizes[hdrsize][1]

            try:
                # we know that the hdrsize is valid, no need to parse separately
                varints = _structures.varints(prepend + subdata, 0, hdrsize, maxwidth=5)
                if len(varints) <= recovery_parameters.max_varints_in_header:
                    yield (_offset, prepend, varints)
            except:
                pass

            # now, if we have read 5 bytes prior to our candidate, we do not
            # have to attempt to add the first byte of the col0 varint, since
            # we need at most 6 bytes, and we have already added one for the hdrsize
            if extra_bytes == 5:
                continue

            # Now, for each added hdrsize, try to parse the bytes as a recordheader by
            # inserting every possible value for the first varint byte
            for p in col0_allowed_prepend[extra_bytes]:
                prepend = recovery_parameters.possible_headersizes[hdrsize][1] + p.bytes
                newdata = prepend+subdata
                try:
                    # if we get here, we can try to parse the entire sequence
                    # we know that the hdrsize is valid, no need to parse separately
                    varints = _structures.varints(newdata, 0, hdrsize, maxwidth=5)
                    if len(varints) <= recovery_parameters.max_varints_in_header:
                        yield (_offset, prepend, varints)
                except:
                      pass


def _only_valid_header_sequences(header_sequences, candidate, recovery_parameters):
    ''' drop varint header sequences for the candidate that are invalid '''

    # We now have a list of header sequences that could represent potential record headers
    # in de vicinity of our candidate, that include the bytes of that particular candidate.
    # However we will most likely have included many false positives, as well as duplicate
    # candidates (i.e. when we prepended a byte that actually exists one byte prior to our
    # current offset). This has to be filtered out.

    # collect the serialtypes of our candidate
    candidate_varints = [v[0] for v in candidate.varints]
    # and the maximum number of columns from the recovery parameters
    maxcols = len(recovery_parameters.columns)

    remaining_headers = []

    # remove impossible recordheaders from the list of header sequences
    for offset, prepended, serialtypes in header_sequences:
        if serialtypes[2:len(candidate_varints)+2] != candidate.varints:
            # the reconstructed header does not have our candidate at proper offset
            continue
        else:
            # next, check if the reconstructed header matches the schema-based
            # signature (which takes ipk_column into account as well)
            mysig = _varints_to_generic_stypes(serialtypes[1:])
            if _matches_signature(mysig, recovery_parameters.schema_serialtypes) is False:
                continue
            remaining_headers.append((offset, prepended, serialtypes))

    # in the remaining headers, we can have exact duplicates (both headersize and serialtypes
    # are equal). In this case, prefer the reconstructed header to which the least amount of
    # bytes where pre-pended, since apparently these same bytes are also present just prior
    # to the candidate. In effect, we can thus choose the recordheader with the lowest offset
    # since this implies that less bytes where added, so sort by offset and yield only unique

    remaining_headers.sort()
    yielded = set()
    for offset, prepended, serialtypes in remaining_headers:
        hsize = serialtypes[0]
        stypes = tuple(serialtypes[1:])
        if (hsize, stypes) not in yielded:
            yielded.add((hsize, stypes))
            yield (offset, prepended, serialtypes)


def _filter_recordheaders(recordheaders, candidate, recovery_parameters):
    ''' run the sequence of recordheaders through a chain of filters
    '''

    # shortcuts for allowed serialtypes
    loose_signature = recovery_parameters.loose_observed_serialtypes
    strict_signature = recovery_parameters.strict_observed_serialtypes
    schema_signature = recovery_parameters.schema_serialtypes

    for (offset, prepended, serialtypes) in recordheaders:
        generic_stypes = _varints_to_generic_stypes(serialtypes[1:])

        if _matches_signature(generic_stypes, schema_signature[:len(generic_stypes)]) is False:
            yield _filtered_recheader(offset, prepended, serialtypes, True,
                                      RejectReason.SchemaBasedSignature)
        if _matches_signature(generic_stypes, loose_signature[:len(generic_stypes)]) is False:
            yield _filtered_recheader(offset, prepended, serialtypes, True,
                                      RejectReason.LooseObservedSignature)
        elif _matches_signature(generic_stypes, strict_signature[:len(generic_stypes)]) is False:
            yield _filtered_recheader(offset, prepended, serialtypes, True,
                                      RejectReason.StrictObservedSignature)
        else:
            yield _filtered_recheader(offset, prepended, serialtypes, False,
                                      RejectReason.NotRejected)


def _drop_rejected_headers(record_headers, max_drop_reason):
    ''' drops rejected headers, except those that have a RejectReason > max_drop_reason
    '''

    for c in record_headers:
        if c.rejected is False:
            yield c
        elif c.reason.value > max_drop_reason.value:
            yield c


def _recordheaders_from_candidate(candidate, recovery_parameters,
                                  max_drop_reason=RejectReason.LooseObservedSignature):
    ''' generate sequence of potential recordheaders for the given candidate '''

    g = _header_sequences(candidate, recovery_parameters)
    h = _only_valid_header_sequences(g, candidate, recovery_parameters)
    l = _filter_recordheaders(h, candidate, recovery_parameters)
    m = _drop_rejected_headers(l, max_drop_reason)
    for rh in m:
        yield rh


################
### scanners ###
################

# This section combines the varint scanning functionality and the recordheader reconstruction
# to generate (candidate, recordheader) tuples from various regions in a database file.


_scan_result = _nt('scan_result', 'varint_candidate recordheader')


def _native_btree_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' generate sequence of (candidate, recordheader) tuples for given table from its own btree '''

    # search for varint sequences in the
    varint_candidates = _varint_scan_native_btree(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _alien_btree_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' generate sequence of (candidate, recordheader) tuples for given table from other btrees '''

    # search for varint sequences in the
    varint_candidates = _varint_scan_alien_btrees(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _index_btree_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' generate sequence of (candidate, recordheader) typles for given table from index btrees '''

    # search for varint sequences in the
    varint_candidates = _varint_scan_index_btrees(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _allocated_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' scan through allocated cells to generate (candidate, recordheader) tuples

    The purpose for this function is to test recovery on allocated cells '''

    # search for varint sequences in the
    varint_candidates = _varint_scan_allocated_btree(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _freelist_scan(db, tablename, recov_params, 
                   max_drop_reason=RejectReason.LooseObservedSignature, debug=False):
    ''' scan through freelist pages to generate (candidate, recordheader) tuples
    '''

    # search for varint sequences in the
    varint_candidates = _varint_scan_freelist_pages(db, tablename, recov_params, debug)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _superseded_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' scan superseded pages to generate (candidate, recordheader) tuples
    '''

    # search for varint sequences in the superseded pages
    varint_candidates = _varint_scan_superseded_pages(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _outdated_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' scan outdated pages in the WAL file to generate (candidate, recordheader) tuples
    '''

    # search for varint sequences in outdated pages
    varint_candidates = _varint_scan_outdated_pages(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _walslack_scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature):
    ''' scan the slack in a WAL file to generate (candidate, recordheader) tuples
    '''

    # search for varint sequences in the slack of the wal file
    varint_candidates = _varint_scan_wal_slack(db, tablename, recov_params)
    # filter by comparing to the various signatures in the recovery parameters
    filtered_candidates = _filter_varint_candidates(varint_candidates, recov_params)
    # discard the candidates with a reject reason lower or equal to max_drop_reason
    remaining_candidates = _drop_rejected_candidates(filtered_candidates, max_drop_reason)

    # for each candidate, we can have multiple potential recordheaders
    for c in remaining_candidates:
        recordheaders = _recordheaders_from_candidate(c, recov_params, max_drop_reason)
        for rh in recordheaders:
            yield _scan_result(c, rh)


def _scan(db, tablename, recov_params, max_drop_reason=RejectReason.LooseObservedSignature, debug=False):
    ''' generate sequence of (candidate, recordheader) tuples for given table using all strategies
    '''

    for r in _native_btree_scan(db, tablename, recov_params, max_drop_reason):
        yield r

    for r in _alien_btree_scan(db, tablename, recov_params, max_drop_reason):
        yield r

    for r in _index_btree_scan(db, tablename, recov_params, max_drop_reason):
        yield r

    for r in _freelist_scan(db, tablename, recov_params, max_drop_reason, debug):
        yield r

    if hasattr(db, 'walfile'):
        # superseded pages only exist if we have a WAL file
        for r in _superseded_scan(db, tablename, recov_params, max_drop_reason):
            yield r
        # the same is true for outdated pages from the WAL file
        for r in _outdated_scan(db, tablename, recov_params, max_drop_reason):
            yield r
        # finally, if the walfile has slack, attempt to carve there as well
        if hasattr(db.walfile, 'slack'):
            for r in _walslack_scan(db, tablename, recov_params, max_drop_reason):
                yield r


#############################
### record reconstruction ###
#############################

# This section contains functionality for reconstructing records based on the
# scan results


class RecoveredRecord:
    ''' class representing a recovered record

    The RecoveredRecord object contains full details on how the record was
    reconstructed and where it was found.
    '''

    def __init__(s,  scan_result):
        ''' initialize a reconstructe record from a scan result '''

        # obtain the pagenumber and pageoffset from the containing object
        containing_object = scan_result.varint_candidate.containing_object
        s.pagenumber = containing_object.pagenumber
        s.pageoffset = containing_object.pageoffset
        s.pagesource = containing_object.pagesource

        # allocated cells in freelist pages still have a rowid
        if hasattr(containing_object, 'rowid'):
            s.rowid = containing_object.rowid
        else:
            # the rowid can not be reliably reconstructed from freeblocks
            s.rowid = "<UNKNOWN>"

        # allocated cells in freelist pages still have a cellnumber
        if hasattr(containing_object, 'cellnumber'):
            s.cellnumber = containing_object.cellnumber
        else:
            s.cellnumber = None

        # allocated cells in freelist pages might have overflow
        if hasattr(containing_object, 'has_overflow'):
            # NOTE: when parsing allocated cells from freelist btree pages
            #       we might have a payloadsize that indicates that overflow
            #       is used. We can not reliably recover the overflow however,
            #       since the target page may have been used for something else.
            s.has_overflow = containing_object.has_overflow
        else:
            s.has_overflow = None

        # info on the object in which the record was found
        s.containing_object_type = type(containing_object)
        s.containing_object_header_offset_in_page = containing_object.header_offset
        s.containing_object_data_offset_in_page = containing_object.data_offset
        s.containing_object_total_size = containing_object.size
        s.containing_object_data_size = containing_object.data_size

        # the parameters used in scanning
        s.scan_type = scan_result.varint_candidate.scantype
        s.scan_firstcol = scan_result.varint_candidate.startcol
        s.scan_lastcol = scan_result.varint_candidate.endcol
        s.scan_colcount = s.scan_lastcol - s.scan_firstcol + 1
        s.scan_match_offset_in_containing_object = scan_result.varint_candidate.offset
        s.scan_match_offset_in_page = s.scan_match_offset_in_containing_object + \
                                      s.containing_object_data_offset_in_page
        s.scan_rejected = scan_result.varint_candidate.rejected
        s.scan_reject_reason = scan_result.varint_candidate.reason

        # results of recordheader reconstruction
        s.recheader_offset_in_containing_object = scan_result.recordheader.offset
        s.recheader_offset_in_page = scan_result.recordheader.offset + \
                                     s.containing_object_data_offset_in_page
        s.recheader_prepended_bytes = scan_result.recordheader.prepended
        if s.recheader_prepended_bytes is not None:
            s.recheader_prepended_bytecount = len(s.recheader_prepended_bytes)
        else:
            s.recheader_prepended_bytecount = 0
        s.recheader_rejected = scan_result.recordheader.rejected
        s.recheader_rejectreason = scan_result.recordheader.reason
        # the total size of the recordheader, including prepended bytes
        s.recheader_size = sum([v[1] for v in scan_result.recordheader.serialtypes])
        # the size consumed in the containing object
        s.recheader_consumed_size = s.recheader_size - s.recheader_prepended_bytecount
        # determine the total number of bytes needed for the body
        stypes = [_structures.serialtype(t[0]) for t in scan_result.recordheader.serialtypes[1:]]
        s.required_bytes_for_body = sum([s[0] for s in stypes])
        s.required_bytes_for_record = s.recheader_consumed_size + s.required_bytes_for_body

        # reconstruct the bitstream that starts with the (prepended)
        # recordheader and includes all remaining bytes of the containing object
        bytes_ = containing_object.data.bytes
        # and cut of everything prior to where the header was found
        start_offset = s.recheader_offset_in_containing_object
        end_offset = s.required_bytes_for_record + start_offset
        bytes_ = bytes_[start_offset: end_offset]

        # total number of bytes consumed by this recovered record
        s.consumed_bytes = len(bytes_)

        s.required_bytes_available = False
        if s.consumed_bytes == s.required_bytes_for_record:
            s.required_bytes_available = True

        # prepend with the proper amount of bytes
        if s.recheader_prepended_bytes is not None:
            bytes_ = s.recheader_prepended_bytes + bytes_

        s.reconstructed_data = _bitstring.BitStream(bytes_)
        s.reconstructed_data_size = len(s.reconstructed_data)//8

        # and attempt to reconstruct a record from it
        s._reconstruct_record()

        # the detailed_decoder needs a field inlinesize and payloadsize
        s.inlinesize = s.consumed_bytes
        s.payloadsize = s.required_bytes_for_record


    def _reconstruct_record(s):
        ''' Attempts to reconstruct the record in the scan result
        '''

        bstream = s.reconstructed_data

        # first try to to parse using the normal parser
        try:
            parsed = _structures.recordformat(bstream, 0)
            # if we get here, we are done
            s.header = parsed.header
            s.body = parsed.body
            s.is_partial = False
            s.last_column_is_truncated = False
            return
        except _bitstring.ReadError as e:
            if not e.args[0].startswith('Reading off the end of the data'):
                raise

        # if we get here, we could not parse the full record, but we can try to
        # read a partial record

        # first parse the recordheader
        bytes_ = bstream.bytes
        recheader = _structures.recordheader(bytes_, 0)
        body_offset = recheader.headersize

        # make list of sizes, storageclases and a parser command from serialtypes
        stypes = [_structures.serialtype(t) for t in recheader.serialtypes]
        sizes = [s[0] for s in stypes]
        sclasses = [s[1] for s in stypes]
        plist = [s[2] for s in stypes]

        # increment columns and keep reading until we encounter our read error
        for i in range(len(plist)+1):
            # prepare the parse command for less columns
            pcommand = ','.join([p for p in plist[:i] if p is not None])
            # move to the start of the body in the bitstream (bit offset)
            bstream.pos = body_offset * 8
            try:
                bstream.readlist(pcommand)
            except _bitstring.ReadError as e:
                # there are bytes missing at the end. Determine how many bytes we are missing by
                # parsing the error message :-o
                start,end = _re.search('read [0-9]* bits', e.args[0]).span()
                attempted = int(e.args[0][start+5:end-5])

                start,end = _re.search('only [0-9]* avail', e.args[0]).span()
                avail = int(e.args[0][start+5:end-5])

                if attempted % 8 != 0 or avail % 8 != 0:
                    raise ValueError("byte-alignement expected")

                attempted = attempted // 8
                avail = avail // 8
                break

        # the failure occured when parsing column i - 1
        failed_column = i - 1
        # read up to and including the failed column
        partial_sizes = sizes[:failed_column]
        partial_plist = plist[:failed_column]

        # check if the column is a text or blob storageclass, in which case we can add
        # the remaining bytes
        truncated = False
        storageclass = stypes[failed_column].storageclass
        if storageclass == _structures._text or storageclass == _structures._blob:
            # make sure that we are dealing with the proper directive
            if int(plist[failed_column].split('bytes:')[1]) != attempted:
                raise ValueError("mistake in partial parsing")
            # reduce the amount of bytes to available bytes
            reduced_directive = 'bytes:{:d}'.format(avail)
            partial_plist.append(reduced_directive)
            partial_sizes.append(avail)
            truncated = True

        # construct a new parser directive
        partial_pcommand = ','.join([p for p in partial_plist[:i] if p is not None])

        # read data from bitstream and restore position
        bstream.pos = body_offset * 8
        parsedcolumns = bstream.readlist(partial_pcommand)

        # add the non-space-consuming column values in the appropriate slots
        columns = []
        for i in range(len(partial_plist)):
            tc = recheader.serialtypes[i]
            sclass = sclasses[i]
            size = partial_sizes[i]
            if tc == 0:
                val = None
            elif tc == 8:
                val = 0
            elif tc == 9:
                val = 1
            else:
                val = parsedcolumns.pop(0)
            columns.append(sclass(size, val))

        # create a recordformat struct from the recordheader and the columns
        parsed = _structures._recordformat(recheader, columns)

        # set the properties in the RecoveredRecord object
        s.header = parsed.header
        s.body = parsed.body
        s.is_partial = True
        s.last_column_is_truncated = truncated
