''' __init__.py - initialize package

Copyright (c) 2022 Netherlands Forensic Institute - MIT License
'''

def _modcheck():
    ''' check if we have at least version 3.1.3 of bitstring module and some version of bigfloat '''

    try:
        import bitstring as _bitstring
    except:
        raise ImportError('this package requires the bitstring module')

    major, minor, patch = _bitstring.__version__.split('.')
    err = 'bitstring version >= 3.1.2 required'
    if int(major) < 3:
        raise ImportError(err)
    elif int(major) == 3 and int(minor) < 1:
        raise ImportError(err)
    elif int(major) == 3 and int(patch) < 2:
        raise ImportError(err)

    try:
        import bigfloat as _bigfloat
    except:
        raise ImportError('this package requires the bigfloat module')

    try:
        import xlsxwriter
    except:
        raise ImportError('this packages requires xlsxwriter')

    try:
        import modgrammar
    except:
        raise ImportError('this packages requires modgrammar')


_modcheck()

#######
# API #
#######

from ._database import Database
from ._recovery import determine_recovery_parameters
from ._recovery import recover_records
from ._recovery import recover_table
