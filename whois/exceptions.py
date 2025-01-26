class PywhoisError(Exception):
    pass

#backwards compatibility
class WhoisError(PywhoisError):
    pass


class UnknownTldError(WhoisError):
    pass


class WhoisDomainNotFoundError(WhoisError):
    pass


class FailedParsingWhoisOutputError(WhoisError):
    pass


class WhoisQuotaExceededError(WhoisError):
    pass


class WhoisUnknownDateFormatError(WhoisError):
    pass


class WhoisCommandFailedError(WhoisError):
    pass
