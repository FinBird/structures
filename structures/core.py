import pdb
from binascii import hexlify
from collections.abc import Sequence
from io import BytesIO
from math import ceil
from struct import Struct as _Struct
from sys import version_info, exc_info
from typing import Any, Callable, List, Union, Tuple, Type, Dict, Mapping

from error import *

if version_info >= (3, 6):
    from collections import ChainMap

    OrderedDict = dict
else:
    from collections import ChainMap, OrderedDict

__version__ = '0.9.5'

__all__ = [
    'Construct', 'SubConstruct', 'Context', 'Error',
    'BuildingError', 'ParsingError', 'SizeofError', 'ContextualError', 'ValidationError',
    'Pass', 'Flag', 'Bytes', 'Integer', 'Float', 'Padding', 'Repeat', 'RepeatExactly',
    'Adapted', 'Prefixed', 'Padded', 'Aligned', 'String', 'PascalString',
    'CString', 'Line', 'Struct', 'Contextual', 'Computed', 'BitFields',
    'Const', 'Raise', 'If', 'Switch', 'Enum', 'Offset', 'Tell', 'Checksum',
    'Debug', 'Bit', 'BitPadding', 'BitFieldStruct', 'Varint', 'Optional', 'Probe',
]


class Context(ChainMap):
    """
    Special object that tracks building/parsing process, contains relevant
    values to build and already parsed values: fields parameters can depend
    upon them via a contextual function instead of being statically defined.
    """


ContextOrNone = Context | None

# Base classes.
class Construct:
    """
    Base class for all kinds of constructs.

    Subclasses must implement the following methods:

        * _build_stream(self, obj, stream, context)
        * _parse_stream(self, stream, context)
        * _sizeof(self, context)
        * _repr(self)

    """
    __slots__ = ('_embedded',)  # 使用 __slots__ 节省内存

    def __init__(self):
        self._embedded = False

    def build(self, obj, context: ContextOrNone = None) -> bytes:
        """
        Build bytes from the python object.

        :param obj: Python object to build bytes from.
        :param context: Optional context dictionary.
        """
        stream = BytesIO()
        self.build_stream(obj, stream, context)
        return stream.getvalue()

    def parse(self, data: bytes, context: ContextOrNone = None) -> Any:
        """
        Parse some python object from the data.

        :param data: Data to be parsed.
        :param context: Optional context dictionary.
        """
        stream = BytesIO(data)
        return self.parse_stream(stream, context)

    def build_stream(self, obj, stream: BytesIO, context: ContextOrNone = None) -> Any:
        """
        Build bytes from the python object into the stream.

        :param obj: Python object to build bytes from.
        :param stream: A ``io.BytesIO`` instance to write bytes into.
        :param context: Optional context dictionary.
        """
        context = context if isinstance(context, Context) else Context(context or {})  # 简化 Context 创建
        try:
            self._build_stream(obj, stream, context)
        except Error:
            raise
        except Exception as exc:
            raise BuildingError(str(exc))

    def parse_stream(self, stream: BytesIO, context: ContextOrNone = None) -> Any:
        """
        Parse some python object from the stream.

        :param stream: Stream from which the data is read and parsed.
        :param context: Optional context dictionary.
        """
        context = context if isinstance(context, Context) else Context(context or {})  # 简化 Context 创建
        try:
            return self._parse_stream(stream, context)
        except Error:
            raise
        except Exception as exc:
            raise ParsingError(str(exc))

    def sizeof(self, context=None) -> int:
        """
        Return the size of the construct in bytes.

        :param context: Optional context dictionary.
        """
        context = context if isinstance(context, Context) else Context(context or {})  # 简化 Context 创建
        try:
            return self._sizeof(context)
        except Exception as exc:
            raise SizeofError(str(exc)) from exc

    def __repr__(self):
        return self._repr()

    def __getitem__(self, item):
        """
        Used to make repeaters of constructs:

            SomeConstruct()[2:5] == Repeat(SomeConstruct(), 2, 5)

        """
        if isinstance(item, slice):
            if item.step is not None:
                raise ValueError('cannot make a Repeat with a step')
            return Repeat(self, item.start, item.stop)
        if isinstance(item, int):
            return RepeatExactly(self, item)
        raise TypeError(f"'can make a Repeat only from an int or a slice, got {type(item)}")

    def _build_stream(self, obj, stream, context):  # pragma: nocover
        raise NotImplementedError

    def _parse_stream(self, stream, context):  # pragma: nocover
        raise NotImplementedError

    def _sizeof(self, context):  # pragma: nocover
        raise NotImplementedError

    def _repr(self):  # pragma: nocover
        raise NotImplementedError


class SubConstruct(Construct):
    """
    Non-trivial constructs often wrap other constructs and add
    transformations on top of them. This class helps to reduce boilerplate
    by providing default implementations for build, parse and sizeof:
    its proxies calls to the provided construct.

    Note that _repr still has to be implemented.

    :param construct: Wrapped construct.

    """
    __slots__ = ('construct',)

    def __init__(self, construct):
        super().__init__()
        self.construct = construct
        self._embedded = construct._embedded  # 直接赋值，避免重复判断

    def _build_stream(self, obj, stream, context):
        return self.construct._build_stream(obj, stream, context)

    def _parse_stream(self, stream, context):
        return self.construct._parse_stream(stream, context)

    def _sizeof(self, context):
        return self.construct._sizeof(context)

    def _repr(self):  # pragma: nocover
        raise NotImplementedError


# Primitive constructs
class Pass(Construct):
    """
    The simplest construct ever: it does nothing when building
    or parsing, its size is 0.
    Useful as default cases for conditional constructs (Enum, Switch, If, etc.).
    """
    __slots__ = ()

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        return obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> None:
        pass

    def _sizeof(self, context: ContextOrNone) -> int:
        return 0

    def _repr(self) -> str:
        return 'Pass()'


class Flag(Construct):
    """
    Build and parse a single byte, interpreting 0 as ``False``
    and everything else as ``True``.

    """
    __slots__ = ()

    def _build_stream(self, obj: bool, stream: BytesIO, context: ContextOrNone) -> None:
        stream.write(b'\x01' if obj else b'\x00')

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> bool:
        data: bytes = stream.read(1)
        if data == b'':
            raise ParsingError(
                'could not read enough bytes, expected 1, found 0'
            )
        return data != b'\x00'

    def _sizeof(self, context: ContextOrNone) -> int:
        return 1

    def _repr(self) -> str:
        return 'Flag()'


class Bytes(Construct):
    """
    Build and parse raw bytes with the specified length.

    :param length: a number of bytes to build and to parse, if -1 then parsing
    consumes the stream to its end (see examples).

    """
    __slots__ = ('length',)

    def __init__(self, length: int = -1):
        super().__init__()
        if length < -1:
            raise ValueError(f"length must be >= -1, got {length}")
        self.length: int = length

    def _build_stream(self, obj: bytes, stream: BytesIO, context: ContextOrNone) -> bytes:
        if self.length == 1 and isinstance(obj, int):
            obj = bytes([obj])
        if self.length != -1 and len(obj) != self.length:
            raise BuildingError(f'must build {self.length!r} bytes, got {len(obj)!r}')
        stream.write(obj)
        return obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> bytes:
        obj = stream.read(self.length)
        if self.length != -1 and len(obj) != self.length:
            raise ParsingError(f'could not read enough bytes, expected {self.length}, found {len(obj)}')
        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        if self.length == -1:
            raise SizeofError('Bytes() has no fixed size')
        return self.length

    def _repr(self) -> str:
        return f"Bytes({self.length if self.length != -1 else ''})"


class Integer(Construct):
    """
    Build bytes from integers, parse integers from bytes.

    :param length: the integer is represented using so many number of bytes.
    Currently only 1, 2, 4, and 8 bytes are supported.

    :param byteorder: the byteorder argument determines the byte order used
    to represent the integer. If byteorder is 'big', the most significant
    byte is at the beginning of the byte array. If byteorder is 'little',
    the most significant byte is at the end of the byte array. To request
    the native byte order of the host system, use `sys.byteorder`
    as the byte order value.

    :param signed: The signed keyword-only argument determines whether
    two's complement is used to represent the integer. If signed is False
    and a negative integer is given, a struct.error is raised, wrapped
    in a BuildingError/ParsingError.

    """
    __slots__ = ('length', 'byteorder', 'signed', '_fmt')

    def __init__(self, length: int, byteorder: str = 'big',
                 signed: bool = False):
        super().__init__()
        if length not in (1, 2, 4, 8):
            raise ValueError(f'length must be 1, 2, 4, or 8, got {length}')
        self.length: int = length
        if byteorder not in ('big', 'little'):
            raise ValueError(f"byteorder must be 'big' or 'little', got {byteorder!r}")
        self.byteorder: str = byteorder
        self.signed: bool = signed
        self._fmt: _Struct = _Struct(('>' if byteorder == 'big' else '<') + {
            (1, True): 'b',
            (1, False): 'B',
            (2, True): 'h',
            (2, False): 'H',
            (4, True): 'l',
            (4, False): 'L',
            (8, True): 'q',
            (8, False): 'Q',
        }[(length, signed)])

    def _build_stream(self, obj: int, stream: BytesIO, context: ContextOrNone) -> None:
        try:
            obj: bytes = self._fmt.pack(obj)
            stream.write(obj)
        except BuildingError as e:
            raise BuildingError(str(e))

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> int:
        data = stream.read(self.length)
        return self._fmt.unpack(data)[0]

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.length

    def _repr(self) -> str:
        return f'Integer({self.length}, byteorder={self.byteorder!r}, signed={self.signed})'


class Float(Construct):
    """
    Build bytes from floats, parse floats from bytes.

    :param length: the float is represented using so many number of bytes.
        Currently only 4 and 8 bytes are supported.

    :param byteorder: the byteorder argument determines the byte order used
        to represent the float. If byteorder is 'big', the most significant
        byte is at the beginning of the byte array. If byteorder is 'little',
        the most significant byte is at the end of the byte array. To request
        the native byte order of the host system, use `sys.byteorder`
        as the byte order value.

    """
    __slots__ = ('length', 'byteorder', '_fmt')

    def __init__(self, length: int, byteorder: str = 'big'):
        super().__init__()
        if length not in (4, 8):
            raise ValueError(f"length must be 4 or 8, got {length}")
        self.length: int = length
        if byteorder not in ('big', 'little'):
            raise ValueError(f"byteorder must be 'big' or 'little', got {byteorder!r}")
        self.byteorder: str = byteorder
        _format_map: Dict[Tuple[int, str], str] = {
            (4, 'big'): '>f',
            (4, 'little'): '<f',
            (8, 'big'): '>d',
            (8, 'little'): '<d',
        }
        self._fmt: _Struct = _Struct(_format_map[(length, byteorder)])

    def _build_stream(self, obj: float, stream: BytesIO, context: ContextOrNone) -> None:
        try:
            obj: bytes = self._fmt.pack(obj)
            stream.write(obj)
        except BuildingError as e:
            raise BuildingError(str(e))

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> float:
        data = stream.read(self.length)
        return self._fmt.unpack(data)[0]

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.length

    def _repr(self) -> str:
        return f'Float({self.length}, byteorder={self.byteorder!r})'


class Padding(Construct):
    """
    Null bytes that are being ignored during building/parsing.

    :param pad_char: Pad using this char. Default is b"\x00" (zero byte).

    """
    __slots__ = ('length', 'pad_char')

    def __init__(self, length: int, pad_char: bytes = b'\x00'):
        super().__init__()
        if length < 0:
            raise ValueError(f'length must be >= 0, got {length}')
        self.length: int = length
        if len(pad_char) != 1:
            raise ValueError(f'pad_char must be a single-length bytes, got {pad_char!r}')
        self.pad_char: bytes = pad_char

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> None:
        stream.write(self.pad_char * self.length)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> bytes:
        data: bytes = stream.read(self.length)
        expected_padding: bytes = self.pad_char * self.length
        if data != expected_padding:
            raise ParsingError(f'expected to parse {expected_padding!r}, got {data!r} instead')
        return data

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.length

    def _repr(self) -> str:
        return f'Padding({self.length}, pad_char={self.pad_char!r})'


# Adapters.
class Repeat(Construct):
    """
    Repeat a construct for the specified range of times (semantics follows
    built-in ``range`` function except the step is always 1
    and negative values can't be specified).

    :param construct: Construct to repeat.

    :param start: Must repeat build/parse at least this number of times.
    Must not be negative.

    :param stop: Must repeat build/parse at most this number of times.
    Must not be negative and must be greater than `start`.

    :param until: A predicate function of a single argument (list of items
    built/parsed so far), called during building/parsing and if the returned
    value is True, stops building/parsing. Default is None, meaning no
    predicate function is called during building/parsing.

    """
    __slots__ = ('construct', 'start', 'stop', 'until')

    def __init__(self, construct: Construct | Type[Construct], start: int, stop: int,
                 until: Callable[[List[Construct | Type[Construct]]], bool] | None = None):
        super().__init__()
        self.construct = construct
        if start < 0:
            raise ValueError(f'start must be >= 0, got {start}')
        self.start = start
        if stop < 0:
            raise ValueError(f'stop must be >= 0, got {stop}')
        if stop < start:
            raise ValueError(f'stop must be >= start, got stop:{stop}, start:{start}')
        self.stop = stop
        self.until = until

    def _build_stream(self, obj: Sequence[Any], stream: BytesIO, context: ContextOrNone) -> None:
        if not self.start <= len(obj) < self.stop:
            raise BuildingError(
                f'length of the object to build must be in range [{self.start}, {self.stop}), got {len(obj)}'
            )
        items: List[Construct | Type[Construct]] = []

        if self.until is not None:
            for item in obj:
                self.construct._build_stream(item, stream, context)
                items.append(item)
                if self.until(items):
                    break
        else:
            for item in obj:
                self.construct._build_stream(item, stream, context)
                items.append(item)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> List[Any]:
        obj: List[Any] = []
        try:
            while len(obj) < self.stop - 1:
                parsed_item = self.construct._parse_stream(stream, context)
                obj.append(parsed_item)
                if self.until is not None and self.until(obj):
                    break
        except ParsingError as exc:
            if len(obj) < self.start:
                raise ParsingError(
                    f'required to parse at least {self.start} of {self.construct}, '
                    f'parsed {len(obj)} instead; error was: {exc}'
                )
            return obj
        if len(obj) < self.start:
            raise ParsingError(
                f'required to parse at least {self.start} of {self.construct}, parsed '
                f'{len(obj)} instead; exited due to \'until\' predicate'
            )
        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        if self.start != self.stop - 1 or self.until is not None:
            raise SizeofError(
                'cannot determine size of variable sized Repeat()'
            )
        return self.start * self.construct._sizeof(context)

    def _repr(self) -> str:
        if self.until is None:
            return f'Repeat({self.construct}, start={self.start}, stop={self.stop})'
        return f'Repeat({self.construct}, start={self.start}, stop={self.stop}, until={self.until})'


class RepeatExactly(Repeat):
    """
    Repeat the specified construct exactly n times.

    :param construct: Construct to repeat.

    :param n: Repeat building/parsing exactly this number of times.

    :param until: A predicate function of a single argument (list of items
    built/parsed so far), called during building/parsing and if the returned
    value is True, stops building/parsing. Default is None, meaning no
    predicate function is called during building/parsing.

    """
    __slots__ = ()

    def __init__(self, construct: Construct | Type[Construct], n: int,
                 until: Callable[[List[Construct | Type[Construct]]], bool] | None = None):
        super().__init__(construct, n, n + 1, until)

    def _repr(self) -> str:
        return f'RepeatExactly({self.construct}, {self.start})'


class Adapted(SubConstruct):
    """
    Adapter helps to transform objects before building and/or after parsing
    of the provided construct.

    :param construct: Construct to adapt.

    :param before_build: A function of a single argument, called before
    building bytes from an object.
    Default is None, meaning no building adaption is performed.

    :param after_parse: A function of a single argument, called after parsing
    an object from bytes.
    Default is None, meaning no parsing adaption is performed.

    """
    __slots__ = ('before_build', 'after_parse')

    def __init__(self, construct: Type[Construct] | Construct,
                 before_build: Callable[[Any], Any] = None, after_parse: Callable[[Any], Any] = None):
        super().__init__(construct)
        self.before_build = before_build
        self.after_parse = after_parse

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> bytes:
        if self.before_build is not None:
            obj = self.before_build(obj)
        return self.construct._build_stream(obj, stream, context)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        obj = self.construct._parse_stream(stream, context)
        if self.after_parse is not None:
            obj = self.after_parse(obj)
        return obj

    def _repr(self) -> str:
        return f'Adapted({self.construct}, before_build={self.before_build!r}, after_parse={self.after_parse!r})'


class Prefixed(SubConstruct):
    """
    Length-prefixed construct.
    Parses the length field first, then reads that amount of bytes
    and parses the provided construct using only those bytes.
    Constructs that consume entire remaining stream (like Bytes()) are
    constrained to consuming only the specified amount of bytes.
    When building, data is prefixed by its length.

    :param construct: Construct to be prefixed with its length.

    :param length_field: Construct used to build/parse the length.

    """
    __slots__ = ('length_field',)

    def __init__(self, construct: Type[Construct] | Construct, length_field: Type[Construct] | Construct):
        super().__init__(construct)
        self.length_field = length_field

    def _build_stream(self, obj, stream: BytesIO, context: ContextOrNone) -> bytes:
        self.length_field._build_stream(len(obj), stream, context)
        return self.construct._build_stream(obj, stream, context)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        length: int = self.length_field._parse_stream(stream, context)
        data: bytes = stream.read(length)
        if len(data) != length:
            raise ParsingError(
                f'could not read enough bytes, expected {length}, found {len(data)}'
            )
        return self.construct._parse_stream(BytesIO(data), context)

    def _sizeof(self, context: ContextOrNone) -> int:
        """TODO:Returns the size of the construct, if fixed ?"""
        return self.length_field._sizeof(context) + self.construct._sizeof(context)

    def _repr(self) -> str:
        return f'Prefixed({self.construct}, length_field={self.length_field})'


class Padded(Construct):
    """
    Appends additional null bytes to achieve a fixed length.

    :param construct: A construct to be padded.

    :param length: Pad to achieve exactly this number of bytes.

    :param pad_byte: The byte used for padding. Defaults to b"\x00".
    """
    __slots__ = ('construct', 'length', 'pad_byte')

    def __init__(self, construct: Type[Construct] | Construct, length: int, pad_byte: bytes = b'\x00'):
        super().__init__()
        self.construct = construct
        if length < 0:
            raise ValueError(f'length must be >= 0, got {length}')
        self.length = length
        self.pad_byte = pad_byte

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        sub_stream = BytesIO()
        ctx_value = self.construct._build_stream(obj, sub_stream, context)
        data: bytes = sub_stream.getvalue()
        padded_data = data.ljust(self.length, self.pad_byte)
        stream.write(padded_data)
        return ctx_value

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        data: bytes = stream.read(self.length)
        if len(data) != self.length:
            raise ParsingError(f'could not read enough bytes, expected {self.length}, found {len(data)}')

        no_padded_data = data[:self.construct.sizeof()]
        padding_len = self.length - len(no_padded_data)

        if data[-padding_len:] != (
                padded_data := self.pad_byte * padding_len):  # Simpler and more correct padding check
            raise ParsingError(
                f"Trailing bytes are not all pad bytes {self.pad_byte!r}. Expected {padding_len} bytes: {padded_data}, but found invalid padding: {data[-padding_len:]}."
            )

        return self.construct._parse_stream(BytesIO(no_padded_data), context)

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.length

    def _repr(self) -> str:
        return f'Padded({self.construct}, length={self.length})' if self.pad_byte == b'\x00' else f'Padded({self.construct}, length={self.length}, pad_byte={self.pad_byte!r})'


class Aligned(Construct):
    """
    Appends additional null bytes to achieve a length that is
    the shortest multiple of a length.

    """
    __slots__ = ('construct', 'length', 'pad_byte')

    def __init__(self, construct: Type[Construct] | Construct, length: int, pad_byte: bytes = b'\x00'):
        super().__init__()
        self.construct: Construct = construct
        if length < 0:
            raise ValueError(f'length must be >= 0, got {length}')
        self.length: int = length
        self.pad_byte: bytes = pad_byte

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        before: int = stream.tell()
        ctx_value = self.construct._build_stream(obj, stream, context)
        after: int = stream.tell()

        pad_len: int = -(after - before) % self.length

        stream.write(self.pad_byte * pad_len)
        return ctx_value

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        before = stream.tell()
        obj = self.construct._parse_stream(stream, context)
        after = stream.tell()

        pad_len = -(after - before) % self.length
        padding = stream.read(pad_len)

        if padding != (padding_expected := self.pad_byte * pad_len):
            raise ParsingError(
                "must read padding of b'" + ' '.join(f'{b:02X}' for b in padding_expected) + "', got b'" + ' '.join(
                    f'{b:02X}' for b in padding) + "'"
            )

        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        size = self.construct._sizeof(context)
        return size + (-size % self.length)

    def _repr(self) -> str:
        return f"Aligned({self.construct}, length={self.length})"


# Strings
class String(Construct):
    """
    String constrained only by the specified constant length.
    Null bytes are padded/trimmed from the right side.

    :param length: Number of bytes taken by the string. Not that the actual
    string can be less than this number. In that case the string will be
    padded with zero bytes.

    :param encoding: Encode/decode using this encoding. By default, no
    encoding/decoding happens (encoding is None).

    """
    __slots__ = ('length', 'encoding')

    def __init__(self, length: int, encoding: str | None = None):
        super().__init__()
        if length < 0:
            raise ValueError(f'length must be >= 0, got {length}')
        self.length: int = length
        self.encoding: str | None = encoding

    def _build_stream(self, obj: str | bytes, stream: BytesIO, context: ContextOrNone) -> bytes:
        if self.encoding is not None:
            obj = obj.encode(self.encoding)
        if not 1 <= len(obj) <= self.length:
            raise BuildingError(
                f'length of the string to build must be in range [1, {self.length + 1}), got {len(obj)}')

        helper = Padded(Bytes(len(obj)), self.length)
        return helper._build_stream(obj, stream, context)  # noqa

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> str | bytes:
        data: bytes = stream.read(self.length)
        if len(data) != self.length:
            raise ParsingError(f'could not read enough bytes, expected {self.length}, found {len(data)}')
        obj: bytes = data.rstrip(b'\x00')
        if self.encoding is not None:
            obj: str = obj.decode(self.encoding)
        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.length

    def _repr(self) -> str:
        if self.encoding is not None:
            return f'String(length={self.length}, encoding={self.encoding!r})'

        return f'String(length={self.length})'


class PascalString(Construct):
    """
    Length-prefixed string.

    :param length_field: Construct used to build/parse the length.

    :param encoding: Encode/decode using this encoding. By default, no
    encoding/decoding happens (encoding is None).

    """
    __slots__ = ('construct', 'length_field', 'encoding')

    def __init__(self, length_field: Construct, encoding: str | None = None):
        super().__init__()
        self.length_field = length_field
        self.construct = Prefixed(Bytes(), length_field)
        self.encoding = encoding

    def _build_stream(self, obj: str | bytes, stream: BytesIO, context: ContextOrNone) -> Bytes:
        if self.encoding is not None:
            obj = obj.encode(self.encoding)
        return self.construct._build_stream(obj, stream, context)  # noqa

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> str | bytes:
        obj = self.construct._parse_stream(stream, context)  # noqa
        if self.encoding is not None:
            return obj.decode(self.encoding)
        else:
            return obj

    def _sizeof(self, context: ContextOrNone):
        raise SizeofError('PascalString has no fixed size')

    def _repr(self) -> str:
        if self.encoding is None:
            return f'PascalString(length_field={self.length_field})'
        return f'PascalString(length_field={self.length_field}, encoding={self.encoding!r})'


class CString(Construct):
    """
    String ending in a zero byte.

    :param encoding: Encode/decode using this encoding. By default, no
    encoding/decoding happens (encoding is None).

    """
    __slots__ = ('encoding',)

    def __init__(self, encoding: str | None = None):
        super().__init__()
        self.encoding = encoding

    def _build_stream(self, obj: str | bytes, stream: BytesIO, context: ContextOrNone) -> bytes:
        if self.encoding is None and not isinstance(obj, bytes):
            obj = obj.encode('utf8')
        elif self.encoding is not None:
            obj = obj.encode(self.encoding)
        obj += b'\x00'
        stream.write(obj)
        return obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> str | bytes:
        obj = bytearray()
        while (byte := stream.read(1)) != b'\x00':
            if not byte:
                raise ParsingError('could not read enough bytes, the stream has ended')
            obj += byte
        obj_bytes = bytes(obj)
        if self.encoding is not None:
            try:
                return obj_bytes.decode(self.encoding)
            except UnicodeDecodeError as e:
                raise ParsingError(f"'{self.encoding}' codec can't decode: {e}")
        return obj_bytes

    def _sizeof(self, context: ContextOrNone) -> None:
        raise SizeofError('CString has no fixed size')

    def _repr(self) -> str:
        if self.encoding is not None:
            return f'CString(encoding={self.encoding!r})'
        return 'CString()'


class Line(Construct):
    """
    String ending in 'Carriage Return and Line Feed' (b'\r\n'). 
    Useful for building and parsing text-based network protocols.

    :param encoding: Encode/decode using this encoding. Default is 'latin-1'.

    """
    __slots__ = ('encoding',)

    def __init__(self, encoding: str | None = 'latin-1'):
        super().__init__()
        self.encoding = encoding

    def _build_stream(self, obj: str | bytes, stream: BytesIO, context: ContextOrNone) -> bytes:
        if self.encoding is not None and isinstance(obj, str):
            encoded_obj = obj.encode(self.encoding)
        elif isinstance(obj, bytes):
            encoded_obj = obj
        else:
            raise TypeError("Object to build must be str or bytes")
        encoded_obj += b'\r\n'
        stream.write(encoded_obj)
        return encoded_obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> str | bytes:
        obj = bytearray()
        while True:
            byte = stream.read(1)
            if not byte:
                raise ParsingError('could not read enough bytes, the stream has ended')
            obj += byte
            if obj[-2:] == b'\r\n':
                break
        obj_bytes = bytes(obj[:-2])
        if self.encoding is not None:
            return obj_bytes.decode(self.encoding)
        return obj_bytes

    def _sizeof(self, context: ContextOrNone) -> None:
        raise SizeofError('Line has no fixed size')

    def _repr(self) -> str:
        if self.encoding != 'latin-1':
            return f'Line(encoding={self.encoding!r})'
        return 'Line()'


# Structs.
class StructMeta(type):
    """
    Metaclass for Struct, a mandatory machinery to maintain an ordered
    class namespace and __slots__.
    """

    # CLASS_NAMESPACE_ORDERED
    if not version_info >= (3, 6):  # pragma: nocover
        @classmethod
        def __prepare__(mcs, name: str, bases: Tuple[Type[Any], ...]) -> OrderedDict:
            return OrderedDict()

    def __new__(mcs: Type['StructMeta'],
                name: str, bases: Tuple[Type[Any], ...],
                namespace: Dict[str, Any]) -> 'StructMeta':
        fields: OrderedDict[str, Construct] = OrderedDict([
            (key, value) for key, value in namespace.items()
            if isinstance(value, Construct)
        ])
        namespace['__struct_fields__'] = fields
        slots = namespace.get('__slots__')
        if slots is None:
            # Make sure user defined structs aren't eating memory.
            namespace['__slots__'] = ()
        return type.__new__(mcs, name, bases, namespace)


class Bit(Construct):
    """
    class Bit, to be used in the context of a BitFieldStruct.
    """

    __slots__ = Construct.__slots__ + ('bit_size',)

    def __init__(self, bit_size: int):
        super().__init__()
        self.bit_size: int = bit_size

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> None:
        pass

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> None:
        pass

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.bit_size

    def _repr(self) -> str:
        return 'Bit()'


class BitPadding(Bit):
    """
    BitPadding class, to be used in the context of a BitFieldStruct.
    """

    def _repr(self):
        return 'BitPadding()'


class BitFieldStructMeta(type):
    """
    Metaclass for BitFieldStruct, a mandatory machinery to maintain an ordered
    class namespace and __slots__.
    """

    if not version_info >= (3, 6):  # pragma: nocover
        @classmethod
        def __prepare__(mcs, name: str, bases: Tuple[Type[Any], ...]) -> OrderedDict:
            return OrderedDict()

    def __new__(mcs: Type['BitFieldStructMeta'], name: str,
                bases: Tuple[Type[Any], ...], namespace: Dict[str, Any]) -> 'BitFieldStructMeta':
        fields: OrderedDict[str, Union[Bit, BitPadding]] = OrderedDict([
            (key, value) for key, value in namespace.items()
            if isinstance(value, (Bit, BitPadding))
        ])
        namespace['__bit_fields__'] = fields
        slots = namespace.get('__slots__')
        if slots is None:
            # Make sure user defined structs aren't eating memory.
            namespace['__slots__'] = Construct.__slots__
        return type.__new__(mcs, name, bases, namespace)


class Struct(Construct, metaclass=StructMeta):
    """
    Sequence of named constructs, similar to structs in C.
    The elements are parsed and built in the order they are defined.

    Size is the sum of all construct sizes, unless some construct raises
    SizeofError.

    :param embedded: If True, this struct will be embedded into another struct.

    """
    __slots__ = ('_embedded', '_ordered')

    def __init__(self, *, embedded: bool = False, _ordered: bool = True):
        super().__init__()
        self._embedded: bool = embedded
        self._ordered = _ordered

    @property
    def fields(self) -> OrderedDict[str, Construct | Type[Construct]]:
        return self.__struct_fields__  # noqa

    def _build_stream(self, obj: Context, stream: BytesIO, context: ContextOrNone) -> BytesIO:
        if not self._embedded:
            context = context.new_child()

        if self._ordered:
            self._build_ordered_fields(obj, stream, context)
        else:
            self._build_unordered_fields(obj, stream, context)

        return stream

    def _build_ordered_fields(self, obj: Context, stream: BytesIO, context: ContextOrNone) -> None:
        """ Build fields in order."""
        for name, field in self.fields.items():
            sub_obj = obj.get(name) if not field._embedded else obj

            if isinstance(field, Struct):
                field._build_stream(sub_obj, stream, context)
                context[name] = sub_obj
            else:
                ctx_value = field._build_stream(sub_obj, stream, context)
                context[name] = ctx_value if ctx_value is not None else sub_obj

            if field._embedded:
                context.update(sub_obj)

    def _build_unordered_fields(self, obj: Context, stream: BytesIO, context: ContextOrNone) -> None:
        """Build fields not in order"""
        # Preprocess, put context in global
        for name, value in obj.items():
            context[name] = value

        for name, field in self.fields.items():
            sub_obj = obj.get(name)
            ctx_value = field._build_stream(sub_obj, stream, context)

            # Renew context immediately
            context[name] = ctx_value if ctx_value is not None else sub_obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Context:
        if not self._embedded:
            context = context.new_child()
        obj = dict()
        for name, field in self.fields.items():
            sub_obj = field._parse_stream(stream, context)
            if not field._embedded:
                obj[name] = sub_obj
                context[name] = sub_obj  # Renew context only in no_embedded fields
            else:
                obj.update(sub_obj)
                for k, v in sub_obj.items():
                    context[k] = v
        return Context(obj)

    def _sizeof(self, context: ContextOrNone) -> int:
        return sum(field._sizeof(context) for field in self.fields.values())

    def _repr(self) -> str:
        # TODO: return f"{self.__class__.__name__}({', '.join(f'{k}={v!r}' for k, v in self.fields.items())})" if self._embedded else f'{self.__class__.__name__}()'
        return f'{self.__class__.__name__}(embedded=True)' if self._embedded else f'{self.__class__.__name__}()'


class BitFieldStruct(Construct, metaclass=BitFieldStructMeta):
    """
    Build and parse named bit-wise fields that can be given as in C.
    The bitfields must be given from LSB to MSB order (top to bottom).
    The bitfields can span over byte boundaries, and the missing bits will be
    handled as don't care paddings.

    :param embedded: If True, this construct will be embedded into the
    enclosed struct.

    """

    __slots__ = Construct.__slots__ + ('_bit_size', '_actual_bit_size', '_length')

    def __init__(self, *, embedded: bool = False):
        super().__init__()
        self._embedded: bool = embedded
        _bit_size = 0
        for name, bit in self.fields.items():
            if not isinstance(bit, (Bit, BitPadding)):
                raise TypeError('Only Bit or BitPadding can be in BitFieldStruct!')
            _bit_size += bit.sizeof()
        # fill bits up to the next byte boundary
        _fill_bits = ceil(_bit_size / 8) * 8 - _bit_size
        self._actual_bit_size: int = _bit_size
        self._bit_size: int = _bit_size + _fill_bits
        self._length: int = self._bit_size // 8

    @property
    def fields(self) -> OrderedDict[str, Bit | BitPadding]:
        return self.__bit_fields__  # noqa

    @staticmethod
    def _bitmask(bit_len: int) -> int:
        return (2 << (bit_len - 1)) - 1

    def _build_stream(self, obj: Dict[str, int], stream: BytesIO, context: ContextOrNone) -> None:
        bit_pos: int = 0
        int_data: int = 0
        for name, bit in self.fields.items():
            mask: int = self._bitmask(bit.bit_size)
            bit_value: int = obj.get(name, 0)
            if isinstance(bit, BitPadding):
                pass
            elif isinstance(bit, Bit):
                if bit_value > mask:
                    raise BuildingError(f'Cannot pack {bit_value} into {bit.bit_size} bits!')
                int_data += (bit_value & self._bitmask(bit.bit_size)) << bit_pos
            else:
                raise TypeError('Only Bit or BitPadding can be in BitFieldStruct!')
            bit_pos += bit.bit_size
        stream.write(int_data.to_bytes(length=self._length, byteorder='little'))

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Dict[str, int]:
        data: bytes = stream.read(self._length)
        if len(data) < self._length:
            raise ParsingError(f'Insufficient data length for parsing BitFieldStruct! '
                               f'Expected {self._length} got {len(data)}.')

        int_data: int = int.from_bytes(data, byteorder='little')
        obj: Dict[str, int] = {}
        bit_pos: int = 0
        for name, bit in self.fields.items():
            if isinstance(bit, BitPadding):
                pass
            elif isinstance(bit, Bit):
                obj[name] = (int_data >> bit_pos) & self._bitmask(bit.bit_size)
            else:
                raise TypeError('Only Bit or BitPadding can be in BitFieldStruct!')
            bit_pos += bit.bit_size
        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        return self._length

    def _repr(self) -> str:
        bitfields: List[str] = []
        bit_pos: int = 0
        for name, bit in self.fields.items():
            if isinstance(bit, BitPadding):
                bitfields.append(f"_PAD_[{bit_pos}:{bit_pos + bit.bit_size - 1}]")
            else:
                bitfields.append(f"{name}[{bit_pos}:{bit_pos + bit.bit_size - 1}]")
            bit_pos += bit.bit_size
        bitfields_str = ", ".join(bitfields)
        return f'{self.__class__.__name__}(embedded=True, {bitfields_str})' if self._embedded else f'{self.__class__.__name__}({bitfields_str})'


class Contextual(Construct):
    """
    Construct that makes other construct dependent of the context.
    Useful in structs.

    :param to_construct: Construct subclass to be instantiated during
    building/parsing.

    :param *args_funcs: Functions of context (or constant values) to be
    called during building/parsing, returned values form positional arguments
    to be passed to ``to_construct`` class.

    :param **kwargs_funcs: Functions of context (or constant values) to be
    called during building/parsing, returned values form keyword arguments
    to be passed to ``to_construct`` class.

    """
    __slots__ = ('to_construct', 'args_func')

    def __init__(self, to_construct: Callable[..., Construct],
                 args_func: Callable[[Context], Any | Sequence[Any]]) -> None:
        super().__init__()
        self.to_construct = to_construct
        self.args_func = args_func

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        try:
            args = self.args_func(context)
        except Exception as exc:
            raise ContextualError(str(exc)) from exc

        args = args if isinstance(args, (tuple, list)) else (args,)

        construct = self.to_construct(*args)
        construct._build_stream(obj, stream, context)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        try:
            args = self.args_func(context)
        except Exception as exc:
            raise ContextualError(str(exc))

        if not isinstance(args, (list, tuple)):
            args = (args,)

        construct = self.to_construct(*args)
        return construct._parse_stream(stream, context)

    def _sizeof(self, context: ContextOrNone) -> int:
        try:
            args = self.args_func(context)
        except Exception as exc:
            raise ContextualError(str(exc)) from exc

        args = [args] if not isinstance(args, (list, tuple)) else args

        construct = self.to_construct(*args)
        return construct._sizeof(context)

    def _repr(self) -> str:
        return f'Contextual({self.to_construct.__name__}, {self.args_func})'


class Computed(Construct):
    """
    Computed fields do not participate in building, but return computed values
    when parsing and populate the context with computed values:

    :param value: Computed value. A function of context can be specified
    to compute values dynamically.

    """
    __slots__ = ('value',)

    def __init__(self, value: Callable[[Context], Any] | bytes):
        super().__init__()
        self.value = value

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        if obj is None:
            if callable(self.value):
                try:
                    obj = self.value(context)
                except KeyError as e:
                    raise ValidationError(f"KeyError in Computed field: {e}")
                except Exception as e:  # Catch other potential errors during computation.
                    raise ValidationError(f"Error computing Computed field value: {e}")
            else:
                obj = self.value
        return obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        if callable(self.value):
            try:
                return self.value(context)
            except KeyError as e:
                raise ValidationError(f"KeyError in Computed field: {e}")
            except Exception as e:
                raise ValidationError(f"Error computing Computed field value: {e}")
        else:
            return self.value

    def _sizeof(self, context: dict) -> int:
        return 0

    def __repr__(self) -> str:
        return f'Computed({self.value!r})'


class BitFields(Construct):
    """
    Build and parse named bit-wise fields. Values are always built from
    unsigned big-byteorder integers and parsed as unsigned
    big-byteorder integers.

    :param spec: Fields definition, a comma separated list of
    name:length-in-bits pairs. Spaces between commas are allowed.

    :param embedded: If True, this construct will be embedded into the
    enclosed struct.

    """
    __slots__ = ('spec', 'fields', '_length', '_bit_lengths')

    def __init__(self, spec: str, embedded: bool = False):
        super().__init__()
        self.spec = spec
        self._embedded = embedded
        self.fields = OrderedDict()
        self._bit_lengths = []  # added for performance optimization

        for field in map(str.strip, spec.split(',')):
            name, length_str = field.split(':')
            length = int(length_str)
            self.fields[name] = length
            if length < 0:
                raise ValueError(f"'{name}' bit length must be >= 0, got {length}")
            self._bit_lengths.append(length)  # added for performance optimization

        self._length = ceil(sum(self._bit_lengths) / 8)

    def _build_stream(self, obj: dict, stream: BytesIO, context: ContextOrNone):
        bits: str = ""
        for name, length in self.fields.items():
            sub_obj = obj.get(name, 0)
            bin_sub_obj = bin(sub_obj)[2:].zfill(length)
            if len(bin_sub_obj) != length:
                raise BuildingError(f"cannot pack {sub_obj} into {length} bit{'s' if length > 1 else ''}")
            bits += bin_sub_obj

        bits += "0" * ((self._length * 8) - len(bits))
        bit_obj = []
        for i in range(self._length):
            part = bits[i * 8: (i + 1) * 8]
            bit_obj.append(bytes([int(part, 2)]))
        bit_obj = b''.join(bit_obj)
        stream.write(bit_obj)
        return bit_obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Context:
        data: bytes = stream.read(self._length)
        bits: str = "".join(bin(byte)[2:].zfill(8) for byte in data)
        obj: Dict[str, int] = {}
        idx: int = 0
        for name, length in self.fields.items():
            obj[name] = int(bits[idx:idx + length], 2)
            idx += length
        return Context(obj)

    def _sizeof(self, context: ContextOrNone) -> int:
        return self._length

    def _repr(self) -> str:
        return f'BitFields({self.spec!r})'


# Conditionals
class Const(SubConstruct):
    """
    Build and parse constant values using the given construct.
    ``None`` can be specified for building.

    :param construct: Construct used to build and parse the constant value.

    :param value: Constant value to be built and parsed.

    """
    __slots__ = ('value', '_construct_sizeof')

    def __init__(self, construct: bytes | int | Construct | Type[Construct], value: bool | bytes | None = None):
        if value is None:
            if isinstance(construct, bytes):
                construct, value = Bytes(len(construct)), construct
        super().__init__(construct)
        self.value = value
        self._construct_sizeof = self.construct.sizeof()  # added for performance

    def _build_stream(self, obj: bool | bytes | None, stream: BytesIO, context: ContextOrNone) -> bytes:
        if obj not in (None, self.value):
            raise BuildingError(f'provided value must be None or {self.value!r}, got {obj!r}')
        return self.construct._build_stream(self.value, stream, context)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> bool | bytes:
        obj = self.construct._parse_stream(stream, context)
        if obj != self.value:
            raise ParsingError(f'parsed value must be {self.value!r}, got {obj!r}')
        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        return self._construct_sizeof  # added for performance

    def _repr(self) -> str:
        return f'Const({self.construct}, value={self.value!r})'


class Raise(Construct):
    """
    Construct that unconditionally raises BuildingError when building,
    ParsingError when parsing and SizeofError when calculating the size
    with the given message.
    Useful in conditional constructs (Enum, Switch, If, etc.).

    :param message: Message to be shown when raising the errors. Use
    ``Contextual`` construct to specify dynamic messages.

    """
    __slots__ = ('message',)

    def __init__(self, message: str):
        super().__init__()
        self.message: str = message

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> None:
        raise BuildingError(self.message)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> None:
        raise ParsingError(self.message)

    def _sizeof(self, context: ContextOrNone) -> None:
        raise SizeofError(self.message)

    def _repr(self) -> str:
        return f'Raise(message={self.message!r})'


class If(Construct):
    """
    A conditional building and parsing of a construct depending
    on the predicate.

    :param predicate: Function of context called during building/parsing/sizeof
    calculation. If the returned value is True, ``then_construct`` is used.
    Otherwise, ``else_construct`` is used.

    :param then_construct: Positive branch construct.

    :param else_construct: Negative branch construct.

    """
    __slots__ = ('predicate', 'then_construct', 'else_construct')

    def __init__(self, predicate: Callable[[Context], bool],
                 then_construct: Construct | Type[Construct],
                 else_construct: Construct | Type[Construct] | None = None):
        super().__init__()
        self.predicate = predicate
        self.then_construct = then_construct
        self.else_construct = else_construct if else_construct is not None else Pass()

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        construct = self.then_construct if self.predicate(context) else self.else_construct
        return construct._build_stream(obj, stream, context)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        construct = self.then_construct if self.predicate(context) else self.else_construct
        return construct._parse_stream(stream, context)

    def _sizeof(self, context: ContextOrNone) -> int:
        construct = self.then_construct if self.predicate(context) else self.else_construct
        return construct._sizeof(context)

    def _repr(self) -> str:
        if isinstance(self.else_construct, Pass):
            return f'If({self.predicate}, {self.then_construct})'
        return f'If({self.predicate}, then_construct={self.then_construct!r}, else_construct={self.else_construct!r})'


class Switch(Construct):
    """
    Construct similar to switches in C.
    Conditionally build and parse bytes depending on the key function.

    :param key: Function of context, used to determine the appropriate case
    to build/parse/calculate sizeof.

    :param cases: Mapping between cases and constructs to build/parse/calculate
    sizeof.

    :param default: Construct used when the key is not found in cases.
    Default is Raise().

    """
    __slots__ = ('key', 'cases', 'default')

    def __init__(self, key: Callable[[Context], Any],
                 cases: Mapping[Any, Construct | Type[Construct]],
                 default: Construct | None = None):
        super().__init__()
        self.key = key
        self.cases = cases
        self.default = default if default is not None else Raise('no default case specified')

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        construct = self.cases.get(self.key(context), self.default)
        return construct._build_stream(obj, stream, context)

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        construct = self.cases.get(self.key(context), self.default)
        return construct._parse_stream(stream, context)

    def _sizeof(self, context: ContextOrNone) -> int:
        construct = self.cases.get(self.key(context), self.default)
        return construct._sizeof(context)

    def _repr(self) -> str:
        if isinstance(self.default, Raise):
            return f'Switch({self.key}, cases={self.cases})'
        return f'Switch({self.key}, cases={self.cases}, default={self.default})'


class Enum(SubConstruct):
    """
    Like a built-in ``Enum`` class, maps string names to values.

    :param construct: Construct used to build/parse/calculate sizeof.

    :param cases: Mapping between names and values.

    :param default: Construct used when the name is not found in cases.
    Default is Raise().

    """
    __slots__ = ('cases', 'build_cases', 'parse_cases', 'default')

    def __init__(self, construct: Construct, cases: Dict[Any, Any],
                 default: Construct | Type[Construct] | None = None):
        super().__init__(construct)
        # For building we need k -> v and v -> v mapping
        self.cases = cases.copy()
        self.build_cases = cases.copy()
        self.build_cases.update({v: v for v in cases.values()})
        # For parsing we need v -> k mapping
        self.parse_cases = {v: k for k, v in cases.items()}
        self.default = default if default is not None else Raise('no default case specified')

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> Any:
        try:
            obj2 = self.build_cases[obj]
        except KeyError:
            self.default._build_stream(obj, stream, context)
            return None
        fallback = stream.tell()
        try:
            self.construct._build_stream(obj2, stream, context)
        except BuildingError:
            stream.seek(fallback)
            self.default._build_stream(obj2, stream, context)
            return None
        # always put in context the name, not value
        return self.parse_cases[obj2]

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Any:
        fallback = stream.tell()
        try:
            obj = self.construct._parse_stream(stream, context)
        except ParsingError:
            stream.seek(fallback)
            return self.default._parse_stream(stream, context)
        try:
            obj = self.parse_cases[obj]
        except KeyError:
            stream.seek(fallback)
            return self.default._parse_stream(stream, context)
        return obj

    def _repr(self) -> str:
        return f'Enum({self.construct}, cases={self.cases}{", default=" + repr(self.default) if not isinstance(self.default, Raise) else ""})'


# Stream manipulation and inspection
class Offset(SubConstruct):
    """
    Changes the stream to a given offset where building or parsing
    should take place, and restores the stream position when finished.
    Mostly useful in structs.

    Size is defined by the size of the provided construct, although it may
    seem that building/parsing do not consume this exact number of bytes.
    The reason why size is defined like that is that the primary use-case
    for ``Offset`` is to support building/parsing of formats like ELF32
    when the payload comes after a variable-sized header, and its position
    and length are defined in the first section of the header.

    :param construct: Construct to build/parse/calculate sizeof at the given
    offset.

    :param offset: Offset to seek the stream to (from the current position).

    """
    __slots__ = ('offset',)

    def __init__(self, construct: Construct, offset: int):
        super().__init__(construct)
        if offset < 0:
            raise ValueError("offset must be >= 0, got {}".format(offset))
        self.offset: int = offset

    def _build_stream(
            self, obj: Any, stream: BytesIO, context: ContextOrNone
    ) -> Any:
        fallback = stream.tell()
        stream.seek(self.offset)
        ctx_value = self.construct._build_stream(obj, stream, context)
        stream.seek(fallback)
        return ctx_value

    def _parse_stream(
            self, stream: BytesIO, context: ContextOrNone
    ) -> Any:
        fallback = stream.tell()
        stream.seek(self.offset)
        obj = self.construct._parse_stream(stream, context)
        stream.seek(fallback)
        return obj

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.construct._sizeof(context)

    def _repr(self) -> str:
        return f"Offset({self.construct!r}, offset={self.offset})"


class Tell(Construct):
    """
    Gets the stream position when building or parsing.
    Tell is useful for adjusting relative offsets to absolute positions,
    or to measure sizes of Constructs. To get an absolute pointer,
    use a Tell plus a relative offset. To get a size, place two Tells
    and measure their difference using a Contextual field.
    Mostly useful in structs.

    """
    __slots__ = ()

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> int:
        return stream.tell()

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> int:
        return stream.tell()

    def _sizeof(self, context: ContextOrNone) -> int:
        return 0

    def _repr(self) -> str:
        return 'Tell()'


class Checksum(SubConstruct):
    """
    Build and parse a checksum of data using a given ``hashlib``-compatible
    hash function.

    """
    __slots__ = ('hash_func', 'data_func')

    # TODO: hash func protocols
    def __init__(self, construct: Construct, hash_func: Callable[[bytes], Any], data_func: Callable[[Any], bytes]):
        super().__init__(construct)
        self.hash_func = hash_func
        self.data_func = data_func

    def _build_stream(self, obj: Any, stream: BytesIO, context: ContextOrNone) -> bytes:
        data = self.data_func(context)
        digest = self.hash_func(data).digest()
        if obj is None:
            obj = digest
        elif obj != digest:
            raise BuildingError(
                f'wrong checksum, provided {hexlify(obj)!r} but expected {hexlify(digest)!r}'
            )
        self.construct._build_stream(obj, stream, context)
        return obj

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> bytes:
        parsed_hash = self.construct._parse_stream(stream, context)
        data = self.data_func(context)
        expected_hash = self.hash_func(data).digest()
        if parsed_hash != expected_hash:
            raise ParsingError(
                f'wrong checksum, parsed {hexlify(parsed_hash)!r} but expected {hexlify(expected_hash)!r}'
            )
        return parsed_hash

    def _sizeof(self, context: ContextOrNone) -> int:
        return self.construct._sizeof(context)

    def _repr(self) -> str:
        return f'Checksum({self.construct}, hash_func={self.hash_func}, data_func={self.data_func!r})'


# Debugging utilities
class Debug(SubConstruct):
    """
    In case of an error, launch a pdb-compatible debugger.

    """
    __slots__ = ('debugger', 'on_exc')

    def __init__(self, construct, debugger=pdb, on_exc=Exception):
        super().__init__(construct)
        self.debugger = debugger
        self.on_exc = on_exc

    def _build_stream(self, obj, stream, context: ContextOrNone):
        try:
            super()._build_stream(obj, stream, context)
        except self.on_exc:  # noqa
            pdb.post_mortem(exc_info()[2])

    def _parse_stream(self, stream, context: ContextOrNone):
        try:
            super()._parse_stream(stream, context)
        except self.on_exc:  # noqa
            pdb.post_mortem(exc_info()[2])

    def _sizeof(self, context: ContextOrNone):
        try:
            super()._sizeof(context)
        except self.on_exc:  # noqa
            pdb.post_mortem(exc_info()[2])

    def _repr(self):
        return f'Debug({self.construct}, debugger={self.debugger}, on_exc={self.on_exc})'


class Optional(Struct):
    __slots__ = ('_embedded',)

    def __init__(self, *, embedded=False):
        super().__init__()
        self._embedded = embedded

    # TODO
    def _build_stream(self, obj, stream, context: ContextOrNone):
        raise NotImplementedError()

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> Context:
        if len(stream.getvalue()) - stream.tell() < self._sizeof(context):
            return Context()

        if not self._embedded:
            context = context.new_child()

        obj: Context = Context()
        for name, field in self.fields.items():
            try:
                obj[name] = field._parse_stream(stream, context)
            except Exception as e:
                raise ParsingError(f"Error parsing field {name} : {e}")
        return obj

    def _repr(self) -> str:
        # TODO: print inner struct name
        return f'Optional(embedded={self._embedded})'


class Varint(Construct):
    """
       Represents a variable-length integer.

       Uses a variable number of bytes to encode an integer value.
       Each byte (except the last) has a 7-bit payload and the highest bit set to 1.
       The last byte has the highest bit set to 0.
    """

    # TODO: auto calculate Varint size
    def __init__(self):
        super().__init__()

    def _build_stream(self, obj: int, stream: BytesIO, context: ContextOrNone) -> None:
        buf = bytearray()
        while True:
            towrite = obj & 0x7F
            obj >>= 7
            if obj:
                buf.append(towrite | 0x80)
            else:
                buf.append(towrite)
                break
        stream.write(bytes(buf))

    def _parse_stream(self, stream: BytesIO, context: ContextOrNone) -> int:
        shift = 0
        result = 0
        while True:
            single_byte = stream.read(1)
            if not single_byte:
                raise ParsingError("Unexpected EOF while reading bytes")
            ord_int = ord(single_byte)
            result |= (ord_int & 0x7F) << shift
            shift += 7
            if not (ord_int & 0x80):
                break
        return result

    def _sizeof(self, context: ContextOrNone) -> int:
        raise NotImplementedError("Varint has no fixed size")

    def _repr(self) -> str:
        return 'Varint()'


# Debugging constructs
class Probe(Construct):
    r"""
    Probe that dumps the context, and some stream content (peeks into it) to the screen to aid the debugging process. It can optionally limit itself to a single context entry, instead of printing entire context.

    :param into: optional, None by default, or a callable that takes the context as input.
                 If provided, the result of this callable will be printed.
    :param lookahead: optional, integer, number of bytes to dump from the stream.

    **Usage:**

    ```python
    from io import BytesIO

    class Header(Struct):
        magic = Bytes(4)
        version = Integer(8)
        payload_length = Integer(16)

    class PacketFormat(Struct):
        header = Header()
        payload = Bytes(lambda ctx: ctx.header.payload_length)

    data = b'\x12\x34\x56\x78\x01\x00\x0a\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'

    # Example 1: Print the entire context and peek into the stream before parsing payload
    class PacketFormatWithProbe1(Struct):
        header = Header()
        probe = Probe(lookahead=4)
        payload = Bytes(lambda ctx: ctx.header.payload_length)

    PacketFormatWithProbe1().parse_stream(BytesIO(data))
    # Expected Output (fragment):
    # --------------------------------------------------
    # Probe, path is <_io.BytesIO object at 0x...>
    # Stream peek: b'\x00\x01\x02\x03'
    # Context: {'header': {'magic': b'\x124Vx', 'version': 1, 'payload_length': 10}}
    # --------------------------------------------------

    # Example 2: Print a specific context variable (payload_length) before parsing payload
    class PacketFormatWithProbe2(Struct):
        header = Header()
        probe = Probe(into=lambda ctx: ctx.header.payload_length)
        payload = Bytes(lambda ctx: ctx.header.payload_length)

    PacketFormatWithProbe2().parse_stream(BytesIO(data))
    # Expected Output (fragment):
    # --------------------------------------------------
    # Probe, path is <_io.BytesIO object at 0x...>
    # Context: {'header': {'magic': b'\x124Vx', 'version': 1, 'payload_length': 10}}
    # Value of into: 10
    # --------------------------------------------------
    ```
    """
    __slots__ = ('into', 'lookahead')

    def __init__(self, into=None, lookahead=None):
        super().__init__()
        self.into = into
        self.lookahead = lookahead

    def _build_stream(self, obj, stream, context: Context | None):
        self._printout(stream, context)

    def _parse_stream(self, stream, context: Context | None):
        self._printout(stream, context)

    def _sizeof(self, context: Context | None):
        self._printout(None, context)
        return 0

    def _printout(self, stream, context: Context | None):
        print("--------------------------------------------------")
        print(f"Probe, path is {stream}")

        if self.lookahead is not None and stream is not None:
            current_position = stream.tell()
            peek_data = stream.read(self.lookahead)
            stream.seek(current_position)
            print(f"Stream peek: {' '.join(f'{b:02X}' for b in peek_data)}")

        print("Context:", context)

        if self.into is not None:
            try:
                into_value = self.into(context)
                print("Value of into:", into_value)
            except Exception as error:
                print(f"Failed to evaluate 'into' with context: {context}, reason:{error}")
        print("--------------------------------------------------")

    def _repr(self):
        return f"Probe(into={self.into!r}, lookahead={self.lookahead!r})"
