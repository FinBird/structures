class Error(Exception):
    """
    Generic error, base class for all library errors.
    """


class BuildingError(Error):
    """
    Raises when building fails.
    """


class ParsingError(Error):
    """
    Raises when parsing fails.
    """


class SizeofError(Error):
    """
    Raises when sizeof fails.
    """


class PrefixedError(Error):
    """
    Raised when parsing Prefixed.
    """


class ContextualError(Error):
    """
    Raises when a contextual function fails.
    """


class ValidationError(Error):
    """
    Raises when a compute function fails.
    """
