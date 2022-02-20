''' _sql.py - Functionality to parse a subset of SQLite's SQL language.

Copyright (c) 2022 Netherlands Forensic Institute - MIT License

Only the subset needed to accurately parse the CREATE TABLE statement is
implemented at the moment. This is needed for parsing the sql statements in
the sqlite_master table.

The modgrammar module is used to define the required grammars. The grammars are
based on the SQLite language diagrams and the sources that can be found on the
sqlite.org website. For example, the CREATE TABLE grammar is based on diagrams
found at https://www.sqlite.org/lang_createtable.html, on the sourcecode in the
sqlite version 3.11.0 amalgamation file sqlite3.c and on the lemon grammar
source file parse.y from the same sqlite version.

NOTE: the CHECK statement is not implemented, since it requires a significant
portion of SQLite's SQL vocabulaire, such as the SELECT statement. As a
workaround everything related to the CHECK statement is placed in a single
object using _AllInBraces and ignored completely.

NOTE: the AS statement is not implemented. I've tested that when CREATE TABLE
is used with the 'AS' clause, the schema is still stored in the normal
fashion, parseable with above grammar. So for parsing the sqlite_master
CREATE statements, we don't have to implement the 'AS' clause. '''

from modgrammar import Grammar as _Grammar
from modgrammar import WORD as _W
from modgrammar import LITERAL as _L
from modgrammar import OPTIONAL as _OPTIONAL
from modgrammar import LIST_OF as _LIST_OF
from modgrammar import ANY_EXCEPT as _ANY_EXCEPT
from modgrammar import ANY as _ANY
from modgrammar import REPEAT as _REPEAT
from modgrammar import EXCEPT as _EXCEPT
from modgrammar import WHITESPACE as _WS
from modgrammar import ParseError as _ParseError
from re import findall as _findall
from collections import namedtuple as _nt


###########
# Grammar #
###########

# set default behavior for whitespace handling to explicit
grammar_whitespace_mode = 'explicit'


class _Keyword(_Grammar):
    ''' Grammar for SQLite reserved keywords.

    These keywords may not occur as names, unless quoted. See:
        https://www.sqlite.org/lang_keywords.html
    '''

    grammar = (_L('ABORT') | _L('ACTION') | _L('ADD') | _L('AFTER') |
               _L('ALL') | _L('ALTER') | _L('ANALYZE') | _L('AND') |
               _L('AS') | _L('ASC') | _L('ATTACH') | _L('AUTOINCREMENT') |
               _L('BEFORE') | _L('BEGIN') | _L('BETWEEN') | _L('BY') |
               _L('CASCADE') | _L('CASE') | _L('CAST') | _L('CHECK') |
               _L('COLLATE') | _L('COLUMN') | _L('COMMIT') | _L('CONFLICT') |
               _L('CONSTRAINT') | _L('CREATE') | _L('CROSS') |
               _L('CURRENT_DATE') | _L('CURRENT_TIME') |
               _L('CURRENT_TIMESTAMP') | _L('DATABASE') | _L('DEFAULT') |
               _L('DEFERRABLE') | _L('DEFERRED') | _L('DELETE') | _L('DESC') |
               _L('DETACH') | _L('DISTINCT') | _L('DROP') | _L('EACH') |
               _L('ELSE') | _L('END') | _L('ESCAPE') | _L('EXCEPT') |
               _L('EXCLUSIVE') | _L('EXISTS') | _L('EXPLAIN') | _L('FAIL') |
               _L('FOR') | _L('FOREIGN') | _L('FROM') | _L('FULL') |
               _L('GLOB') | _L('GROUP') | _L('HAVING') | _L('IF') |
               _L('IGNORE') | _L('IMMEDIATE') | _L('IN') | _L('INDEX') |
               _L('INDEXED') | _L('INITIALLY') | _L('INNER') | _L('INSERT') |
               _L('INSTEAD') | _L('INTERSECT') | _L('INTO') | _L('IS') |
               _L('ISNULL') | _L('JOIN') | _L('KEY') | _L('LEFT') |
               _L('LIKE') | _L('LIMIT') | _L('MATCH') | _L('NATURAL') |
               _L('NO') | _L('NOT') | _L('NOTNULL') | _L('NULL') | _L('OF') |
               _L('OFFSET') | _L('ON') | _L('OR') | _L('ORDER') |
               _L('OUTER') | _L('PLAN') | _L('PRAGMA') | _L('PRIMARY') |
               _L('QUERY') | _L('RAISE') | _L('RECURSIVE') | _L('REFERENCES') |
               _L('REGEXP') | _L('REINDEX') | _L('RELEASE') | _L('RENAME') |
               _L('REPLACE') | _L('RESTRICT') | _L('RIGHT') | _L('ROLLBACK') |
               _L('ROW') | _L('SAVEPOINT') | _L('SELECT') | _L('SET') |
               _L('TABLE') | _L('TEMP') | _L('TEMPORARY') | _L('THEN') |
               _L('TO') | _L('TRANSACTION') | _L('TRIGGER') | _L('UNION') |
               _L('UNIQUE') | _L('UPDATE') | _L('USING') | _L('VACUUM') |
               _L('VALUES') | _L('VIEW') | _L('VIRTUAL') | _L('WHEN') |
               _L('WHERE') | _L('WITH') | _L('WITHOUT'))


class _Fallback_ID(_Grammar):
    ''' Grammar for keywords that are allowed as element name '''

    # The lemon grammar for such names is (from parse.y in version 3.11.0 of
    # the sqlite source zip)::
    # %type nm {Token}
    # nm(A) ::= id(X).         {A = X;}
    # nm(A) ::= STRING(X).     {A = X;}
    # nm(A) ::= JOIN_KW(X).    {A = X;}
    #
    # The first grammar rule leads to the following grammar rule:
    # %token_class id  ID|INDEXED.
    #
    # After this, the fallback ID is defined (not entirely shown here). This
    # causes a subset of keywords to fallback to 'ID' when they will not parse
    # as their original value. A snippet::
    #
    # %fallback ID
    #  ABORT ACTION AFTER ANALYZE ASC ATTACH BEFORE BEGIN BY CASCADE CAST
    #  COLUMNKW CONFLICT DATABASE DEFERRED DESC DETACH EACH END EXCLUSIVE
    #  EXPLAIN FAIL FOR
    #
    # If I understand this correctly, this means that some reserved keywords
    # can occur as table names, even if they are unquoted. I took the list from
    # the 3.11.0 source file parse.y and created a new grammar class with these
    # 'allowed' words.
    #
    # NOTE: I assumed COLUMNKW in the file parse.y to correspond to the string
    #       COLUMN here, similar for LIKE_KW which corresponds to LIKE.

    grammar = (_L('ABORT') | _L('ACTION') | _L('AFTER') |
               _L('ANALYZE') | _L('ASC') | _L('ATTACH') |
               _L('BEFORE') | _L('BEGIN') | _L('BY') |
               _L('CASCADE') | _L('CAST') | _L('COLUMN') | _L('CONFLICT') |
               _L('DATABASE') | _L('DEFERRED') | _L('DESC') |
               _L('DETACH') | _L('EACH') | _L('END') | _L('EXCLUSIVE') |
               _L('EXPLAIN') | _L('FAIL') | _L('FOR') |
               _L('IGNORE') | _L('IMMEDIATE') | _L('INITIALLY') |
               _L('INSTEAD') | _L('LIKE') |
               _L('MATCH') | _L('NO') | _L('PLAN') |
               _L('QUERY') | _L('KEY') | _L('OF') | _L('OFFSET') |
               _L('PRAGMA') | _L('RAISE') | _L('RECURSIVE') |
               _L('RELEASE') | _L('REPLACE') | _L('RESTRICT') |
               _L('ROW') | _L('ROLLBACK') | _L('SAVEPOINT') |
               _L('TEMP') | _L('TRIGGER') | _L('VACUUM') |
               _L('VIEW') | _L('VIRTUAL') | _L('WITH') | _L('WITHOUT'))


class _SingleQuoted(_Grammar):
    ''' Grammar for single quoted strings (or empty quotes). '''
    grammar = ((_L("'"), _W("^'"), _L("'")) | _L("''"))


class _DoubleQuoted(_Grammar):
    ''' Grammar for double quoted strings. '''
    grammar = ((_L('"'), _W('^"'), _L('"')) | _L('""'))


class _BackQuoted(_Grammar):
    ''' Grammar for single quoted strings using the backquote (or empty quotes). '''
    grammar = ((_L("`"), _W("^`"), _L("`")) | _L("``"))


class _BlockQuoted(_Grammar):
    ''' Grammar for block quoted strings. '''
    grammar = (_L('['), _W('^[]'), _L(']'))


class _StringLiteral(_Grammar):
    ''' Grammar for string-literal. '''
    grammar = (_SingleQuoted | _DoubleQuoted | _BackQuoted)


class _Name(_Grammar):
    ''' Grammar for elements such as database-name, table-name and column-name.

    This grammar assumes that table names contain alphanumeric characters
    and underscore only. In reality, valid tables names may include special
    characters when the name is escaped in brackets. This is currently not
    supported by this parser.
    '''

    # The rules are as follows:
    # 1. allow some of the 'fallback ID' reserved Keywords as names (unquoted)
    # 2. allow any quoted string (StringLiteral)
    # 3. allow block-quoted string as names
    # 4. allow unquoted alphanumeric names that are not reserved keywords

    grammar = (_Fallback_ID |
               _StringLiteral |
               _BlockQuoted |
               _EXCEPT(_W('A-Za-z0-9_'), _Keyword))


class _Real(_Grammar):
    ''' Gammar for numeric-literal containing decimals. '''
    grammar = (_W('0-9'), _L('.'), _W('0-9'))


class _Exp(_Grammar):
    ''' Grammar for numeric-literal containing an exponent character ('e') '''
    grammar = (_W('0-9') | _Real), _L('e'), _W('0-9')


class _NumericLiteral(_Grammar):
    ''' Grammar for numeric-literal.'''
    grammar = (_W('0-9') | _Real | _Exp)


class _SignedNumber(_Grammar):
    ''' Grammar for signed-number. '''
    grammar = (_OPTIONAL(_L('+') | _L('-')), _NumericLiteral)


class _TypeName(_Grammar):
    ''' Grammar for type-name. '''
    grammar = (_LIST_OF(_Name, sep=_WS),
               _OPTIONAL(_OPTIONAL(_WS), _L('('), _OPTIONAL(_WS),
                         _LIST_OF((_OPTIONAL(_WS), _SignedNumber,
                                   _OPTIONAL(_WS)), sep=','),
                         _OPTIONAL(_WS), _L(')')))


class _ConflictClause(_Grammar):
    ''' Grammar for conflict-clause. '''
    grammar = _OPTIONAL(_L('ON CONFLICT '),
                        (_L('ROLLBACK') | _L('ABORT') | _L('FAIL') |
                         _L('IGNORE') | _L('REPLACE')))


class _BlobLiteral(_Grammar):
    ''' Grammar for quoted blob-literal (i.e. X'ABCD' notation). '''
    grammar = (_L("X'"), _W('0-9A-F'), _L("'"))


class _EmptyBlobLiteral(_Grammar):
    ''' Grammar for quoted blob-literal (i.e. X'ABCD' notation). '''
    grammar = (_L("X''"))


class _LiteralValue(_Grammar):
    ''' Grammar for literal-value elements. '''
    grammar = (_StringLiteral | _BlobLiteral | _L('NULL') |
               _L('CURRENT_TIME') | _L('CURRENT_DATE') |
               _L('CURRENT_TIMESTAMP'))


class _AllInBraces(_Grammar):
    ''' Grammar to skip over unimplemented stuff that sits between braces. '''
    grammar = (_W('('), _OPTIONAL(_W('^)')), _W(')'))


class _Check(_Grammar):
    ''' Grammar for the CHECK element in both column-constraint and
    table-constraint. This is not implemented and only used to ignore
    everything between braces (expr), since expr is rather complex as it
    requires implementing SELECT as well. '''
    grammar = (_L('CHECK'), _OPTIONAL(_WS), _AllInBraces)


class _ON(_Grammar):
    ''' Grammar for the ON statement in the foreign-key-clause. '''
    grammar = (_L('ON '), (_L('DELETE ') | _L('UPDATE ')),
               (_L('SET NULL') | _L('SET DEFAULT') |
                _L('CASCADE') | _L('RESTRICT') |
                _L('NO ACTION')))


class _MATCH(_Grammar):
    ''' Grammar for the MATCH statement in the foreign-key-clause. '''
    grammar = (_L('MATCH '), _Name)


class _NamesInBraces(_Grammar):
    ''' Grammar to parse a list of names in braces. '''
    grammar = (_L('('),
               _LIST_OF((_OPTIONAL(_WS), _Name, _OPTIONAL(_WS)), sep=","),
               _L(')'))


class _ForeignKey(_Grammar):
    ''' Grammar for foreign-key-clause. '''

    class _DEFER(_Grammar):
        grammar = (_OPTIONAL(_L('NOT ')), _L('DEFERRABLE'),
                   _OPTIONAL(_L(' INITIALLY DEFERRED') |
                             _L(' INITIALLY IMMEDIATE')))

    class _ONMATCH(_Grammar):
        grammar = (_LIST_OF(_ON | _MATCH, sep=_WS, min=1))

    grammar = (_L('REFERENCES '), _Name,
               _OPTIONAL(_OPTIONAL(_WS), _NamesInBraces),
               _OPTIONAL(_OPTIONAL(_WS), _ONMATCH),
               _OPTIONAL(_OPTIONAL(_WS), _DEFER))


class _NOTNULL(_Grammar):
    ''' Grammar for NOT NULL statement in ColumnConstraint. '''
    # NOTE: this is not correct if we follow the diagrams at
    # sqlite.org strictly, but I've seen one case where someone
    # defined one of the column constraints as 'NULL' and it still worked
    # grammar = (_L('NOT NULL'), _OPTIONAL(_WS), _ConflictClause)
    grammar = ((_L('NULL') | _L('NOT NULL')), _OPTIONAL(_WS), _ConflictClause)


class _PKEY(_Grammar):
    ''' Grammar for PRIMARY KEY clause '''
    grammar = (_L('PRIMARY KEY'),
               _OPTIONAL(_L(' ASC') | _L(' DESC')),
               _OPTIONAL(_WS),
               _ConflictClause,
               _OPTIONAL(_L(' AUTOINCREMENT')))


class _UNIQUE(_Grammar):
    ''' grammar for the UNIQUE statement in ColumnConstraint. '''
    grammar = (_L('UNIQUE'), _OPTIONAL(_WS), _ConflictClause)


class _DEFAULT(_Grammar):
    ''' Grammar for DEFAULT statement '''
    grammar = (_L('DEFAULT '),
               (_SignedNumber | _LiteralValue | _AllInBraces | _BlobLiteral | _EmptyBlobLiteral) | _Name )


class _ColumnConstraint(_Grammar):
    ''' Grammar for column-constraint in column-def statement. '''

    class _COLLATE(_Grammar):
        grammar = (_L('COLLATE '), _Name)

    grammar = (_OPTIONAL(_L('CONSTRAINT '), _Name, _WS),
               (_PKEY | _NOTNULL | _UNIQUE |
                _DEFAULT | _COLLATE | _ForeignKey | _Check))


class _ColumnDef(_Grammar):
    ''' Grammar for column-def elements in the CREATE TABLE statement. '''
    grammar = (_Name,
               _OPTIONAL((_WS, _TypeName)),
               _OPTIONAL(_OPTIONAL(_WS),
                         _LIST_OF(_ColumnConstraint, sep=_WS, min=0)))


class _Indexed_Column(_Grammar):
    ''' Grammar for indexed columns '''
    grammar = (_Name,
               _OPTIONAL(_L(' COLLATE '), _Name),
               _OPTIONAL(_L(' ASC') | _L(' DESC')))


class _PKEYUNIQUE(_Grammar):
    ''' Gammar for PRIMARY KEY or UNIQUE clause '''
    grammar = (_L('PRIMARY KEY') | _L('UNIQUE'),
               _OPTIONAL(_WS), _L('('), _OPTIONAL(_WS),
               _LIST_OF((_OPTIONAL(_WS), _Indexed_Column,
                         _OPTIONAL(_WS)), sep=","),
               _L(')'),
               _OPTIONAL(_WS), _ConflictClause)


class _TableConstraint(_Grammar):
    ''' Grammar for table-constraint clause. '''

    class _FKEY(_Grammar):
        grammar = (_L('FOREIGN KEY'), _OPTIONAL(_WS),
                   _NamesInBraces, _OPTIONAL(_WS),
                   _ForeignKey)

    grammar = (_OPTIONAL(_L('CONSTRAINT '), _Name, _WS),
               (_PKEYUNIQUE | _FKEY | _Check))


class _CreateTable(_Grammar):
    ''' Grammar for SQLite's CREATE TABLE statement. '''

    grammar = (_L('CREATE '),
               _OPTIONAL(_L('TEMP ') | _L('TEMPORARY ')),
               _L('TABLE '),
               _OPTIONAL(_L('IF NOT EXISTS ')),
               _OPTIONAL(_Name, _L('.')),
               _Name,
               _OPTIONAL(_WS),
               _L('('),
               _OPTIONAL(_WS),
               _LIST_OF((_OPTIONAL(_WS),
                         _ColumnDef,
                         _OPTIONAL(_WS)), sep=","),
               _OPTIONAL(_WS),
               _OPTIONAL(_L(','),
                         _LIST_OF((_OPTIONAL(_WS),
                                   _TableConstraint,
                                   _OPTIONAL(_WS)), sep=",")),
               _OPTIONAL(_WS),
               _L(')'),
               _OPTIONAL(_WS),
               _OPTIONAL(_L(' WITHOUT ROWID')),
               _OPTIONAL(_WS),
               _OPTIONAL(_L(';')),
               _OPTIONAL(_WS)
               )


class _CreateVirtualTable(_Grammar):
    ''' Grammar for SQLite's CREATE VIRTUAL TABLE statement. '''

    grammar = (_L('CREATE '),
               _L('VIRTUAL '),
               _L('TABLE '),
               _OPTIONAL(_L('IF NOT EXISTS ')),
               _OPTIONAL(_Name, _L('.')),
               _Name,
               _OPTIONAL(_WS),
               _L('USING '),
               # assumption: module-name conforms to same rules as other
               # identifiers (table name, column name)
               _Name,
               _OPTIONAL(_WS),
               # ignore all the module-arguments
               _OPTIONAL(_AllInBraces),
               _OPTIONAL(_WS),
               _OPTIONAL(_L(';')),
               _OPTIONAL(_WS)
               )


###########
# Parsing #
###########

# namedtuple for holding a parsed table definition
_tbldef = _nt('tabledef', 'dbname tblname temp columns tblconstraints '
                          'withoutrowid ipk_column')

# namedtuple for holding a parsed table constraints
_tbl_constraints = _nt('tableconstraints', 'primary_key unique other')

# namedtuple for holding a parsed column definition
_coldef = _nt('columndef', 'name coltype affinity primary pkey_sort '
                           'pkey_autoincrement notnull unique default '
                           'constraints')

# namedtuple for holding info on the primary key column
_pkey_col = _nt('pkey_col', 'colname sort')


def parse_create_table_statement(sql):
    ''' Returns table definition based on given sql CREATE TABLE statement.

    Note that most of the CREATE TABLE grammar is implemented and parsed
    properly, but not all individual elements are fully unpacked, such as some
    of the column constraints and the table constraints. This will be added
    when needed. Also note that no sanity checking on the parsed SQL is
    performed, other than checking if it conforms to SQLite's defined SQL
    language. '''

    # NOTE: the list indexes in the functions that translate parsed structures
    # into python objects are not magic, they follow from the defined grammars.
    # Every element is *always* at the same position in the nested list
    # structure as long as the grammar doesn't change.

    res = _parse_sql(sql)

    # we ignore CREATE VIRTUAL TABLE statements completely
    if type(res) == _CreateVirtualTable:
        return None

    # if we get here, we should be dealing with a CREATE TABLE statement
    if type(res) != _CreateTable:
        raise ValueError('sql statement is not a CREATE TABLE statement')

    # preinit optional results
    temp, withoutrowid = (False, False)
    dbname, tableconst = (None, None)

    # first element defines whether this is temporary table or not
    if res[1] is not None:
        temp = True

    # fourth element contains database name in first element
    if res[4] is not None:
        dbname = res[4][0].string

    # fith element contains table name
    tblname = res[5].string

    # 9th element contains column definitions
    columns = res[9].elements
    # drop the comma's between column definition (uneven items)
    columns = [columns[i] for i in range(0, len(columns), 2)]
    # drop whitespace elements from colelements and interpret definitions
    columns = [_column_definition(c[1]) for c in columns]

    # 11th element contains table constraints (or None if not present)
    tblcon = None
    if res[11] is not None:
        tableconst = res[11][1].elements
        # drop the comma's between table constraints (uneven items)
        tableconst = [tableconst[i] for i in range(0, len(tableconst), 2)]
        # interpret the table constraints (first elements contain whitespace).
        tableconst = [_table_constraint(t[1][1]) for t in tableconst]
        # collect table constraints by type of constraint:
        # 1) start with primary key constraints
        pkey = [t.primary_key for t in tableconst if t.primary_key is not None]
        if len(pkey) > 1:
            raise ValueError('more than two PRIMARY KEY clauses in '
                             'table constraints')
        if len(pkey) > 0:
            pkey = pkey[0]
        else:
            pkey = None
        # 2) then the UNIQUE constraints
        unique = [t.unique for t in tableconst if t.unique is not None]
        # 3) and any other constraints
        other = [t.other for t in tableconst if t.other is not None]
        tblcon = _tbl_constraints(pkey, unique, other)

    # last element is without rowid statement
    if res.elements[15] is not None:
        withoutrowid = True

    # determine column number for integer primary key column
    ipk_col = _integer_primary_key_col(columns, tblcon)

    return _tbldef(dbname, tblname, temp, columns, tblcon, withoutrowid,
                   ipk_col)


def _correct_fallback_ids(parsed_sql, orig_sql, offset=0, new_sql=''):
    ''' iterate over the parsed_sql, replace all _Fallback_ID subelements
    that are uppercased with the original casing as used in orig_sql in order
    to preserve original element names (i.e. prevent uppercased columnname,
    whereas the original was lower or mixed-case).
    '''

    for subel in parsed_sql.elements:
        if subel is None:
            continue

        if subel.grammar == _Fallback_ID.grammar:
            # the token is parsed as Fallback_ID, replace with original
            new_sql += orig_sql[offset:offset+len(subel.string)]
            offset += len(subel.string)

        elif len(subel.elements) != 0:
            offset, new_sql = _correct_fallback_ids(subel, orig_sql,
                                                      offset, new_sql)
        else:
            # add the consumed string to the new_sql statement
            new_sql += subel.string
            offset += len(subel.string)

    return offset, new_sql


def _parse_sql(sql):
    ''' parse given sql statement

    This function tries to parse the given sql statement using the currently
    supported SQL statements in the following order:

        - CREATE VIRTUAL TABLE
        - CREATE TABLE

    When the SQL statement type can successfully parse the given statement,
    this object is returned and the other types are not tried. When no SQL
    statement parser matches the given sql statement, a ValueError will be
    raised.

    Note that limited support is built in for CREATE VIRTUAL TABLE statements,
    but only up to the level that we can detect these in the sqlite_master
    table. The workaround for dealing with lower or mixed-case names for tables
    and columns and correcting these after parsing is written entirely towards
    the CREATE TABLE statements. This means that in some cases the names of the
    returned VIRTUAL table element may have been mangled and it should be
    ignored by the caller.  '''

    # remove extra whitespace and newlines from sql statement
    sql = " ".join(sql.rstrip().split())

    # Translate lower or mixed-case keywords to uppercase since our grammar
    # uses upper case for these keywords. A problem with this approach is that
    # some keywords may be used as column or table identifiers (names). Still,
    # we need to convert to uppercase in order for the parser to work.
    words = sql.split()
    newwords = []
    changed = []
    for idx, word in enumerate(words):
        # Remove punctuation and round brackets that are part of the syntax in
        # order to be able to test for keywords. Note that this does not affect
        # quoted keywords. These quotes ('') are not stripped, since quoted
        # keywords can only be identifiers (names).
        token = word.upper().lstrip(',(.').rstrip('.,);')
        try:
            # try to parse as keyword, and if this works add it to the list of
            # uppercase words. In addition add the index of the changed word to
            # the list of changed word indices if it differs from the original
            # casing
            res = _Keyword.parser().parse_string(token)
            # add the entire word, including punctuation and round brackets,
            # since we want to rebuild the entire sql statement (we are not
            # dealing with 'tokens' here, just white-space separated words)
            upcase = word.upper()
            newwords.append(upcase)
            if upcase != word:
                changed.append(idx)
        except:
            newwords.append(word)

    # parse the converted sql statement
    converted_sql = " ".join(newwords)

    parsers = [_CreateVirtualTable.parser(),
               _CreateTable.parser()]
    results = []
    for p in parsers:
        try:
            res = p.parse_string(converted_sql)
            results.append(res)
        except:
            results.append(None)

    # check if any of the parsers resulted in success
    if results == [None, None]:
        print(sql)
        raise ValueError('not a SQL statement i can parse')
    elif results[0] is not None and results[1] is not None:
        raise ValueError('logic error in sql parsing')
    elif results[0] is not None:
        # this is a CREATE VIRTUAL TABLE statement,
        # return the partially parsed result
        return results[0]
    elif results[1] is not None:
        # this is a normal table, fall through..
        pass
    else:
        raise ValueError('logic error in sql parsing')

    # if we get here, we have a normal CREATE TABLE statement, proceed
    res = results[1]

    # Due to changing the case of all keywords, we might have the situation
    # that one of the keywords is actually a column or table name (identifier).
    # This should be corrected back to the original casing. Whenever this
    # situation occurs, the parser will have a FallBack_ID element, which we
    # can use to replace the string consumed by that parser to it's original
    # casing (char_count retval is ignored, only used for recursion internally)
    char_count, corrected_sql = _correct_fallback_ids(res, sql)

    # now, reparse this corrected_sql statement
    res = _CreateTable.parser().parse_string(corrected_sql)

    return res


def _integer_primary_key_col(columns, tblconst):
    ''' Determines column number of INTEGER PRIMARY KEY column, if present.

    Returns None if given columns and tableconstraints do not define
    an INTEGER PRIMARY KEY column.

    Determination of the PRIMARY KEY and the way in which it is defined is
    important for knowing in which manner the PRIMARY KEY is stored. There
    are some imporant rules, rephrased from:
    https://www.sqlite.org/lang_createtable.html

    - Each table has at most 1 primary key
    - Primary Key can be defined in column definition, in which case the
      primary key is that single column
    - Primary Key can be defined in table constraint, in which case the
      primary key is the (combination of) column(s) defined in that clause.
    - Primary Key is obligated for without rowid tables
    - NULLs are allowed in most PRIMARY KEY columns (bug-related!)
    - All records in rowid tables have 64-bit rowid
    - WITHOUT ROWID tables have no rowid
    - When the PRIMARY KEY is defined to a single column (either in column
      definition or in table-constraint and *if and only if* the declared
      type is exactly "INTEGER" (case-insensitive), then the column becomes
      an alias for the rowid. For example: UNSIGNED INTEGER PRIMARY KEY does
      not lead to the rowid being an alias for the primary key column (!)
    - As an exception: When the column is declared with type 'INTEGER' and a
      'PRIMARY KEY DESC" clause in the column definition (!), then the column
      isn't an alias for the rowid. (bug-related)

    Why is this imporant? From: http://www.sqlite.org/fileformat.html
     - ONLY when an SQL table has an INTEGER PRIMARY KEY column, the column
       appears in the record as NULL value and the rowid (b-tree key) is the
       actual column value.
     - In all other cases the records still have a rowid, but this is not
       related to the PRIMARY KEY.
    '''

    # first check if a primary key is defined in the column definitions
    primary_key = [i for i in range(0, len(columns))
                   if columns[i].primary is True]

    ipk_column = None

    if len(primary_key) == 1:
        is_ipk = True
        # we have PRIMARY KEY in column definition, check sort order
        pkcol = primary_key[0]
        pkey_sort = columns[pkcol].pkey_sort
        pkey_auto = columns[pkcol].pkey_autoincrement
        if columns[pkcol].coltype.upper() != 'INTEGER':
            is_ipk = False
        if pkey_sort == 'DESC':
            is_ipk = False
        if is_ipk is True:
            ipk_column = pkcol

    elif len(primary_key) == 0:
        # if there are no table constraints, we have no IPK
        if tblconst is None:
            return ipk_column
        # check the tableconstraints
        tblpkey = tblconst.primary_key
        if tblpkey is None:
            return ipk_column
        pcolnames = [p.colname for p in tblpkey]
        colnames = [c.name for c in columns]
        pcolnums = [colnames.index(p) for p in pcolnames]
        # INTEGER PRIMARY KEY can only be a single column
        if len(pcolnums) == 1:
            # now if typename is 'INTEGER', this is IPK column
            if columns[pcolnums[0]].coltype.upper() == 'INTEGER':
                ipk_column = pcolnums[0]
    else:
        raise ValueError('more than one PRIMARY KEYs found')

    return ipk_column


def _column_definition(colelement):
    ''' Creates a columndef object from the given column element in the parsed
    CREATE TABLE statement. '''

    colname = colelement[0].string
    # NOTE:the last [0] drops everything in parenthesis from the _TypeName.
    # This is intentional, since SQLite ignores such directives and affinity is
    # based on textual part of the type-name only.
    typename = None
    if colelement[1] is not None:
        typename = colelement[1][1][0].string

    affinity = _affinity(typename)

    # preinit some variables
    primary, notnull, unique = (False, ) * 3
    default = None
    pksort, pkauto = None, None
    other = []

    # constraints are in a list
    if colelement[2] is not None:
        colconst = colelement[2][1].elements
        colconst = [colconst[i] for i in range(0, len(colconst), 2)]
        for cc in colconst:
            ccname, constraint = cc.elements
            if ccname is not None:
                ccname = ccname[1].string
            if type(constraint) == _NOTNULL:
                notnull = True
            elif type(constraint) == _PKEY:
                primary = True
                if constraint[1] is not None:
                    pksort = constraint[1].string.lstrip().rstrip()
                if constraint[4] is not None:
                    pkauto = True
            elif type(constraint) == _UNIQUE:
                unique = True
            elif type(constraint) == _DEFAULT:
                # for now, store grammar result including
                # type (i.e. _LiteralValue or _SignedNumber
                default = constraint[1]
            else:
                # other constraints added as string for now
                other.append(cc.string)

    return _coldef(colname, typename, affinity, primary, pksort, pkauto,
                   notnull, unique, default, other)


def _affinity(type_name):
    ''' Returns the column affinity for the given type_name based on the
    affinity rules as defined in SQLite documentation. '''

    if type_name is None:
        return None

    type_name = type_name.upper()

    # These are exactly the rules as defined in the documentation
    # Note that order of evaluation is important as well!

    if 'INT' in type_name:
        return 'INTEGER'
    elif 'CHAR' in type_name:
        return 'TEXT'
    elif 'CLOB' in type_name:
        return 'TEXT'
    elif 'TEXT' in type_name:
        return 'TEXT'
    elif 'BLOB' in type_name:
        return None
    elif 'REAL' in type_name:
        return 'REAL'
    elif 'FLOA' in type_name:
        return 'REAL'
    elif 'DOUB' in type_name:
        return 'REAL'
    else:
        return 'NUMERIC'


def _table_constraint(table_constraint):
    ''' Creates a tbl_constraint object from the given table_constraint element
    in the parsed CREATE TABLE statement. '''

    # only primary key and unique constraints are handled.
    primary = unique = other = None

    if type(table_constraint) == _PKEYUNIQUE:

        # the primary key may consist of multiple columns
        if table_constraint[0].string == 'PRIMARY KEY':
            primary_key = []
            pkey_elements = table_constraint[4].elements
            # the elements are separated by comma's (uneven items)
            for i in range(0, len(pkey_elements), 2):
                pkel = pkey_elements[i][1].elements
                colname = pkel[0].string
                sort = None
                if pkel[2] is not None:
                    sort = pkel[2].string.lstrip().rstrip()
                primary_key.append(_pkey_col(colname, sort))
            primary = primary_key

        elif table_constraint[0].string == 'UNIQUE':
            u_elements = table_constraint[4].elements
            unique = []
            # elements are spearated by comma's (uneven items)
            for i in range(0, len(u_elements), 2):
                unique.append(u_elements[i][1][0].string)

    else:
        # drop whitespace elements from tableconstraints and store as string
        other = (table_constraint.string)

    return _tbl_constraints(primary, unique, other)
