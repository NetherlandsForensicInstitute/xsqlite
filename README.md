# xsqlite

Xsqlite is a Python 3 package that can be used for forensic analysis of SQLite
database files. It's main purpose is to recover deleted records, but it can
also be used to analyse the low-level file structure for forensic purposes. The
package includes a simple command-line tool for basic record recovery, but for
more advanced usage it can be used as Python module or in the interactive
Python shell.

## Usage examples

Recovery of deleted records from the 'message' table in a database called
'sms.db':

```
xsqlite recover sms.db message result.xlsx
```

This results in an Excel file with two worksheets. The first worksheet holds
the recovered records with some additional metadata, such as whether or not the
record is truncated (records can be partially overwritten). The second
worksheet contains more metadata on each recovered record, such as the exact
method used to recover the record and the location within the database file.

An additional worksheet with allocated records can be included in the result as
follows:

```
xsqlite recover --alloc sms.db message result.xlsx
```

Recovery uses both the database schema and allocated records to understand the
type of data that is stored in the table for which records are being recovered.
By default, a minimum of 30 allocated records are needed for this. If not
enough allocated records are available, we can use a reference database to
obtain the recovery parameters. This, of course, requires the reference
database and the data stored in the target table to be similar to the data
stored in the database under investigation.

```
xsqlite recover --refdb reference.db sms.db message result.xlsx
```

If a -wal file is present in the same directory as the main database file,
xsqlite will normally automatically detect it and include it in the recovery.
Alternatively it can be explicitly included using the '--wal' argument.

For additional information on how to use the CLI tool, see:

```
xsqlite -h
```

For use as Python module or in the interactive shell please read the
documentation in the code.

## Limitations

* The current version only supports main database files and their associated
  WAL-file. Support for journal files has not been implemented in this release.

* The recovery may produce false positives that require some post-processing
  step to filter and/or classify further.

* In some cases, deleted records are instantly overwritten with zeroes. In
  this case xsqlite can not recover any deleted records.

## Dependencies

This package was written for Python 3. Note that it is created and tested on a
Linux system. It should work on any Linux system with the proper Python version
and dependencies installed. It may or may not work under Windows.

* Python3

* bitstring for all binary file interaction:
  https://pypi.python.org/pypi/bitstring/3.1.3. Note that version < 3.1.2
  contains a critical bug for xsqlite. On debian based systems you can probably
  install with: apt install python3-bitstring, otherwise use pip3 install.

* bigfloat package for proper handling of floating point formatting:
  https://pypi.python.org/pypi/bigfloat/. The bigfloat module requires the
  lbimpfr-dev package (apt install libmpfr-dev) after which you can install
  bigfloat with pip3.

* xlsxwriter for exporting records to Excel files:
  https://xlsxwriter.readthedocs.io/.

* modgrammar: http://code.google.com/p/modgrammar/. This module is
  needed for parsing SQL statements.

## Installation

Run the following from the checked out repository:

	sudo make install

## Related work

The first version of xsqlite was written in 2014 when tools for SQLite database
recovery were not widely available. The few tools that did exist where either
specific for certain types of data or had some other limitations. In recent
years several projects have been made public. Examples of these are:

* https://github.com/bring2lite/bring2lite

* https://github.com/Defense-Cyber-Crime-Center/sqlite-dissect

Several commercial tools also exist.

## License

Copyright (C) 2022 Netherlands Forensic Institute - MIT License
