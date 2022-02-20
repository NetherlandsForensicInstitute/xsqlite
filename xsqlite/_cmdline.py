#!/usr/bin/env python3

''' _cmdline.py - minimal commandline interface for xsqlite

Copyright (c) 2022 Netherlands Forensic Institute - MIT License
'''

import sys as _sys
import argparse as _argparse
from sys import stdout as _stdout
from pprint import pprint as _pprint
from os import path as _path

from ._database import Database
from ._export import dumpdb as _dumpdb
from . import _recovery
from . import _exceptions


def _parser():
    ''' argument parser '''

    parser = _argparse.ArgumentParser(
        prog='xsqlite',
        formatter_class = _argparse.RawDescriptionHelpFormatter,
        description = 'SQLite3 database recovery. ',
        epilog = 'Example usage: \n' +\
                 ' xsqlite dump database.db\n' +\
                 ' xsqlite recover database.db tablename output.xlsx\n' +\
                 '\n'
        )

    parser.add_argument('--version', help='print version and exit', action='store_true',
                        default=False)

    subparsers = parser.add_subparsers(help='sub-command help')

    # options related to conversion/importing into database
    dump = subparsers.add_parser('dump', help='dump database to stdout')
    dump.add_argument('dbfile', metavar='DBFILE', help='main database file')
    dump.add_argument('--table', metavar='TABLE', help='limit to single table')
    d_assoc = dump.add_mutually_exclusive_group()
    d_assoc.add_argument('--wal', metavar='WALFILE', help='wal file associated with dbfile')
    #d_assoc.add_argument('--journal', metavar='JOURNAL', help='journal file associated with dbfile')

    recover = subparsers.add_parser('recover', help='recover unallocated records from database')
    recover.add_argument('dbfile', metavar='DBFILE', help='main database file')
    recover.add_argument('table', metavar='TABLE', help='name of table to recover')
    recover.add_argument('outfile', metavar='OUTFILE', help='output filename (xlsx) or nameprefix (tsv)')
    recover.add_argument('--tsv', action="store_true", help='export to tsv instead of xlsx')
    recover.add_argument('--alloc', action="store_true", help='include allocated records in export')
    recover.add_argument('--refcount', metavar='REFCOUNT', help='minimal required allocated messages to learn from')
    recover.add_argument('--refdb', metavar='REFDB', help='database to use in signature learning')
    r_assoc = recover.add_mutually_exclusive_group()
    r_assoc.add_argument('--wal', metavar='WALFILE', help='wal file associated with dbfile')
    #r_assoc.add_argument('--journal', metavar='JOURNAL', help='journal file associated with dbfile')

    info = subparsers.add_parser('info', help='show information about database')
    info.add_argument('dbfile', metavar='DBFILE', help='main database file')
    info.add_argument('--tables', action="store_true", help='print list of tables to stdout')
    info.add_argument('--table_info', action="store_true", help='print list of tables to stdout')
    i_assoc = info.add_mutually_exclusive_group()
    i_assoc.add_argument('--wal', metavar='WALFILE', help='wal file associated with dbfile')
    #r_assoc.add_argument('--journal', metavar='JOURNAL', help='journal file associated with dbfile')

    return parser


def main():
    ''' entry point '''

    parser = _parser()
    args = parser.parse_args()

    if hasattr(args, 'table_info'):
        dbinfo(args)
    elif hasattr(args, 'alloc'):
        recover(args)
    elif hasattr(args, 'table'):
        dump(args)
    elif args.version is True:
        version()
    else:
        parser.print_help()


def dbinfo(args):
    ''' List tables and exit '''

    db = Database(args.dbfile, wal=args.wal)

    if args.tables is True:
        for tbln in db.tablenames:
            _pprint(tbln)

    if args.table_info is True:
        for tbln in db.tablenames:
            _pprint(tbln)
            _pprint("="*len(tbln))
            _pprint("rootpage: %d" % (db.tables[tbln].rootpage,))
            _pprint("ipk_col : %s" % (db.tables[tbln].ipk_col,))
            _pprint([(c.name,c.typename, c.affinity) for c in db.tables[tbln].columns])
    _sys.exit()


def dump(args):
    ''' Dump sqlite3 database to stdout and exit. '''

    db = Database(args.dbfile, wal=args.wal)
    _dumpdb(db, _stdout)
    _sys.exit()


def recover(args):
    ''' recover sqlite3 database to target file '''

    if isinstance(args.outfile, str):
        filename = _path.abspath(_path.expanduser(args.outfile))
        if _path.exists(filename):
            raise RuntimeError('refusing to overwrite output file')
    else:
        raise _exceptions.InvalidArgumentException("provide filename")

    db = Database(args.dbfile, wal=args.wal)
    if args.refdb is None:
        refdb = db
    else:
        refdb = Database(args.refdb)

    try:
        if args.refcount is not None:
            refcount = int(args.refcount)
            _recovery.recover_table(db, refdb, args.table, args.outfile,
                                    args.alloc, refcount, tsv=args.tsv)
        else:
            _recovery.recover_table(db, refdb, args.table, args.outfile,
                                    args.alloc, tsv=args.tsv )
    except _exceptions.UserFeedbackException as e:
        print(e)
    _sys.exit()


def version():
    ''' return the version of xsqlite '''

    _modulepath = _path.abspath(__file__)
    _moduledir = _path.split(_modulepath)[0]
    _versionfile = _path.join(_moduledir, 'VERSION')
    with open(_versionfile, 'rt') as f:
        version = f.readline()
        print(version)
    _sys.exit()


if __name__ == "__main__":
    main()
