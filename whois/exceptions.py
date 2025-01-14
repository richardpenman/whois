class PywhoisError(Exception):
    pass


class UnknownTldError(PywhoisError):
    pass


class WhoisDomainNotFoundError(PywhoisError):
    pass


class FailedParsingWhoisOutputError(PywhoisError):
    pass


class WhoisQuotaExceededError(PywhoisError):
    pass


class UnknownDateFormatError(PywhoisError):
    pass


class WhoisCommandFailedError(PywhoisError):
    pass
