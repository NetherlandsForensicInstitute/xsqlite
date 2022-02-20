''' _decode.py - module containing functionality to decode records

Copyright (c) 2022 Netherlands Forensic Institute - MIT License
'''

from collections import namedtuple as _nt
from collections import OrderedDict as _OD
import binascii as _binascii

from . import _structures


class BodyDecoder():
    ''' decoder for record body values '''

    def __init__(s, textencoding, affinities=[]):
        ''' initialize the body decoder

        The textencoding argument should be the database textencoding,
        and the affinities argument should be a list of column affinities as
        text strings

        Note that the affinities are only used for detecting when a value that is
        stored as integer should be converted to a REAL value at the moment. When
        the list of affinities is left empty, the values are all decoded according
        to their storage class without any postprocessing.
        '''

        s.textencoding = textencoding
        s.affinities = affinities


    def decode(s, body):
        ''' decode the fields in the given body, returns a tuple of decoded fields and error_columns

        The body argument should be a list of field values as returned in recordformat

        Decoding of fields is based on their type and affinity. TEXT values are
        decoded using the database text encoding. Note that NULL fields are
        represented by the value None in the returned list.

        The following storage rules related to column affinity are known from
        https://www.sqlite.org/datatype3.html#affinity

        - columns with TEXT affinity store everything as NULL, TEXT or BLOB, also
          numeric data. No conversion upon read-out is needed.

        - columns with NUMERIC affinity can store in all 5 storage classes. Text is
          converted to REAL or INTEGER if NUMERIC data if possible (see link for
          rules). Experiments show that this is indeed the case and that even
          SQLite no longer 'remembers' that the original inserted value was TEXT
          (checked with the 'dump' command). So here too, no conversion upon
          read-out is needed. The storage class determines the type. Note that
          NUMERIC is the default affinity if no other affinity rule is matched,
          but only if a Typename *is* provided.

        - columns with INTEGER affinity behave the same as columns with NUMERIC
          affinity.

        - columns with REAL affinity store integers in the INTEGER storage class,
          but upon representation these are forced back into floating point
          representation. Experiments show this behaviour as well. So here:
          conversion is actually needed based on the column affinity if the storage
          class was integer.

        - columns with NONE affinity have no conversion rules.

        When a column can not be decoded using the database text encoding, it is
        hexlified instead and the column number is added to the list of error_columns
        '''
        values = [v.value for v in body]
        stypes = [type(v) for v in body]

        # 1) convert integer values in columns with REAL affinity to floats
        realcols = [i for i in range(len(s.affinities)) if s.affinities[i] == 'REAL']
        for col, value in enumerate(values):
            if stypes[col] == _structures._integer:
                if col in realcols:
                    values[col] = float(values[col])

        # 2) decode text values according to db textencoding
        txtcls = [i for i in range(len(stypes)) if stypes[i] == _structures._text]
        error_cols = []
        for col in txtcls:
            try:
                values[col] = values[col].decode(s.textencoding)
            except:
                error_cols.append(col)
                # keep the values as binary, it will be hexlified on export
                continue

        return values, error_cols


class RecordViewer():
    ''' class with functionality to create a different views of a record '''

    def __init__(s, colnames, bodydecoder, ipk_col):
        ''' initialize the RecordViewer '''

        s.colnames = colnames
        s.decoder = bodydecoder
        s.ipk_col = ipk_col

        # a simple view of a rowid record, consisting of only rowid and value dict
        s._user_view = _nt('record', 'rowid values')

        # a detailed view of a rowid record, including info on location and size
        s._detailed_view = _nt('record', 'recovered decode_errors has_overflow '
                                         'pagenumber pagesource cellnumber headersize '
                                         'inlinesize totalsize rowid values')

        # a forensic view of a record that includes recovery information
        s._forensic_view = _nt('forensic_view', 'recovered recovery_type recovery_source '
                                                'scan_filter_result recheader_result is_partial '
                                                'last_col_is_truncated scan_match_offset prepended '
                                                'decode_errors has_overflow '
                                                'pagenumber pagesource cellnumber '
                                                'pageoffset recordoffset '
                                                'headersize consumed_bytes totalsize '
                                                'serialtypes rowid values')


    def user_view(s, record):
        ''' Represent given record as simple 'user' record.

        After running this function  on a record object we obtain a simple view
        of the record in which the columns are all converted according to their
        affinity, and the INTEGER PRIMARY KEY column (if any) is extracted from the
        rowid. All metadata, inluding location and serialtypes is removed from this
        view of the record.
        '''

        # decode the text fields according to text encoding
        values, errors = s.decoder.decode(record.body)

        # due to ALTER TABLE statements, we may have less values than columns
        # but not the other way around
        if len(values) > len(s.colnames):
            raise ValueError('more values than column definitions')

        # replace NULL value in INTEGER PRIMARY KEY column with rowid
        if s.ipk_col is not None:
            values[s.ipk_col] = record.rowid

        # store the values in an ordered dictionary
        _values = _OD()
        # we use zip here, because we may have less values than columns
        for (n, v) in zip(s.colnames, values):
            # remove the quotes from the column names
            unquoted_colname = n.lstrip('"\'[`').rstrip('"\']`')
            _values[unquoted_colname] = v

        return s._user_view(record.rowid, _values)


    def detailed_view(s, record):
        ''' Represent given record with some more detail.

        This is similar to the user_view but, in addition, some metadata is
        included in this view of the record. This includes the pagenumber, the
        cellnumber, size information and whether the record uses overflow pages.
        This kind of information is useful for forensic purposes, for example to
        answer the question where a specific record is located and whether or not
        there where decode_errors in any of the columns
        '''

        # decode the text fields according to text encoding
        values, errors = s.decoder.decode(record.body)

        # due to ALTER TABLE statements, we may have less values than columns
        # but not the other way around
        if len(values) > len(s.colnames):
            raise ValueError('more values than column definitions')

        # replace NULL value in INTEGER PRIMARY KEY column with rowid
        if s.ipk_col is not None:
            values[s.ipk_col] = record.rowid

        # store the values in an ordered dictionary
        _values = _OD()
        # we use zip here, because we may have less values than columns
        for (n, v) in zip(s.colnames, values):
            # remove the quotes from the column names
            unquoted_colname = n.lstrip('"\'[`').rstrip('"\']`')
            _values[unquoted_colname] = v

        if len(errors) != 0:
            decode_errors = True
        else:
            decode_errors = False

        if hasattr(record, 'scan_type'):
            recovered = True
        else:
            recovered = False

        return s._detailed_view(recovered, decode_errors, record.has_overflow,
                                record.pagenumber, record.pagesource.name, record.cellnumber,
                                record.header.headersize, record.inlinesize,
                                record.payloadsize, record.rowid, _values)


    def forensic_view(s, record):
        ''' Represent given record with full detail. '''

        # decode the text fields according to text encoding
        values, errors = s.decoder.decode(record.body)

        # due to ALTER TABLE statements, we may have less values than columns
        # but not the other way around
        if len(values) > len(s.colnames):
            raise ValueError('more values than column definitions')

        # replace NULL value in INTEGER PRIMARY KEY column with rowid
        if s.ipk_col is not None:
            values[s.ipk_col] = record.rowid

        # store the values in an ordered dictionary
        _values = _OD()
        # we use zip here, because we may have less values than columns
        # NOTE: some record may thus have a different number of values, which is
        # why the values field is at the end. The exporter function must take this
        # into account by first scanning for all fieldnames before writing the
        # header.
        for (n, v) in zip(s.colnames, values):
            # remove the quotes from the column names
            unquoted_colname = n.lstrip('"\'[`').rstrip('"\']`')
            _values[unquoted_colname] = v

        if len(errors) != 0:
            decode_errors = True
        else:
            decode_errors = False

        if hasattr(record, 'scan_type'):
            recovered = True
            recovery_type = record.scan_type.name
            recovery_source = record.containing_object_type.__name__
            scan_filter_result = record.scan_reject_reason.name
            recordheader_result = record.recheader_rejectreason.name
            is_partial = record.is_partial
            lastcol_is_truncated = record.last_column_is_truncated
            scan_match_offset = record.scan_match_offset_in_page
            # offset where the recordheader is detected to start (excl. prepended bytes)
            offset = record.recheader_offset_in_page
            consumed_bytes = record.consumed_bytes
            # size, including prepended bytes
            total_size = record.reconstructed_data_size
            prepended = record.recheader_prepended_bytes

        else:
            recovered = False
            recovery_type = None
            recovery_source = None
            scan_filter_result = None
            recordheader_result = None
            is_partial = None
            lastcol_is_truncated = None
            scan_match_offset = None
            # record starts at payloadoffset
            offset = record.payloadoffset
            consumed_bytes = record.payloadsize
            total_size = record.payloadsize
            prepended = None


        return s._forensic_view(recovered, recovery_type, recovery_source,
                                scan_filter_result, recordheader_result, is_partial,
                                lastcol_is_truncated, scan_match_offset, prepended,
                                decode_errors, record.has_overflow,
                                record.pagenumber, record.pagesource.name,
                                record.cellnumber, record.pageoffset,
                                offset, record.header.headersize,
                                consumed_bytes, total_size,
                                record.header.serialtypes, record.rowid, _values)
