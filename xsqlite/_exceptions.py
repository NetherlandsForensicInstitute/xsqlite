''' _exceptions.py - module specific exceptions

Copyright (c) 2022 Netherlands Forensic Institute - MIT License
'''

class InvalidArgumentException(Exception):
    ''' raised when a function receives an invalid argument '''
    pass


class NotYetImplementedException(Exception):
    ''' raised when some functionality is not yet implemented '''
    pass


class UserFeedbackException(Exception):
    ''' raised when the user can fix the exception by providing different input '''
    pass


class AssumptionBrokenException(Exception):
    ''' raised when an assumption is broken '''
    pass
