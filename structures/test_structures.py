import contextlib
import hashlib
import unittest
from binascii import hexlify
from io import BytesIO, StringIO
from sys import version_info

from structures import *

if version_info >= (3, 6):
    OrderedDict = dict
else:
    from collections import OrderedDict


class TestPass(unittest.TestCase):

    def test_build(self):
        p = Pass()
        self.assertEqual(p.build("foo"), b"")

    def test_parse(self):
        p = Pass()
        self.assertIsNone(p.parse(b"bar"))  # Assert that the return value is None

    def test_sizeof(self):
        p = Pass()
        self.assertEqual(p.sizeof(), 0)

    def test_repr(self):
        p = Pass()
        self.assertEqual(repr(p), "Pass()")


class TestFlag(unittest.TestCase):

    def test_build_true(self):
        f = Flag()
        self.assertEqual(f.build(True), b'\x01')

    def test_build_false(self):
        f = Flag()
        self.assertEqual(f.build(False), b'\x00')

    def test_parse_false(self):
        f = Flag()
        self.assertFalse(f.parse(b'\x00'))

    def test_parse_true(self):
        f = Flag()
        self.assertTrue(f.parse(b'\x10'))  # Any non-zero value is True

    def test_parse_empty(self):
        f = Flag()
        with self.assertRaises(ParsingError) as context:
            f.parse(b'')
        self.assertEqual(str(context.exception), "could not read enough bytes, expected 1, found 0")

    def test_sizeof(self):
        f = Flag()
        self.assertEqual(f.sizeof(), 1)

    def test_repr(self):
        f = Flag()
        self.assertEqual(repr(f), 'Flag()')


class TestBytes(unittest.TestCase):
    def test_fixed_length(self):
        b = Bytes(3)
        self.assertEqual(b.build(b"foo"), b"foo")
        self.assertEqual(b.parse(b"bar"), b"bar")
        with self.assertRaises(BuildingError) as context:
            b.build(b"foobar")
        self.assertEqual(str(context.exception), "must build 3 bytes, got 6")
        self.assertEqual(b.sizeof(), 3)

    def test_variable_length(self):
        stream = BytesIO(b"foobar")
        b = Bytes()
        self.assertEqual(b.parse_stream(stream), b"foobar")
        self.assertEqual(stream.read(1), b"")
        with self.assertRaises(SizeofError) as context:
            b.sizeof()
        self.assertEqual(str(context.exception), "Bytes() has no fixed size")

    def test_invalid_length(self):
        with self.assertRaises(ValueError, msg="length must be >= -1, got -10"):
            Bytes(-10)

    def test_single_byte_int(self):
        b = Bytes(1)
        self.assertEqual(b.build(ord('A')), b"A")  # 65 is ASCII for 'A'


class TestInteger(unittest.TestCase):

    def test_build_parse(self):
        i = Integer(1, byteorder='big', signed=False)
        self.assertEqual(i.build(0xff), b'\xff')
        self.assertEqual(i.parse(b'\x10'), 16)

    def test_byteorder(self):
        self.assertEqual(Integer(1, 'little').build(0xff), b'\xff')
        self.assertEqual(Integer(2, 'little').build(0xff), b'\xff\x00')
        self.assertEqual(Integer(2, 'big').build(0xff), b'\x00\xff')

    def test_signed(self):
        self.assertEqual(Integer(2, 'little', signed=True).build(-0x10ff), b'\x01\xef')

    def test_invalid_length(self):
        with self.assertRaises(ValueError) as context:
            Integer(3)
        self.assertEqual(str(context.exception), "length must be 1, 2, 4, or 8, got 3")

    def test_invalid_byteorder(self):
        with self.assertRaises(ValueError) as context:
            Integer(1, 'custom')
        self.assertEqual(str(context.exception), "byteorder must be 'big' or 'little', got 'custom'")

    def test_build_negative(self):
        # pypy/graal_python is different from cpython in behaviour
        with self.assertRaisesRegex(BuildingError,
                                    r"argument out of range for 1-byte integer format|ubyte format requires 0 <= number <= 255|'B' format requires 0 <= number <= 255"):
            Integer(1).build(-1)

    def test_sizeof(self):
        i = Integer(1, byteorder='big', signed=False)
        self.assertEqual(i.sizeof(), 1)


class TestFloat(unittest.TestCase):

    def test_build(self):
        i = Float(4, byteorder='big')
        self.assertEqual(i.build(2.2), b'@\x0c\xcc\xcd')

        j = Float(8, byteorder='little')
        self.assertEqual(j.build(-1970.31415), b"'\xa0\x89\xb0A\xc9\x9e\xc0")

    def test_parse(self):
        i = Float(4, byteorder='big')
        self.assertAlmostEqual(i.parse(b'\x01\x02\x03\x04'), 2.387939260590663e-38)

    def test_sizeof(self):
        i = Float(4, byteorder='big')
        self.assertEqual(i.sizeof(), 4)

    def test_invalid_length(self):
        with self.assertRaises(ValueError) as context:
            Float(5)
        self.assertEqual(str(context.exception), "length must be 4 or 8, got 5")

    def test_invalid_byteorder(self):
        with self.assertRaises(ValueError) as context:
            Float(4, byteorder='native')
        self.assertEqual(str(context.exception), "byteorder must be 'big' or 'little', got 'native'")

    def test_repr(self):
        i = Float(4, byteorder='big')
        self.assertEqual(repr(i), "Float(4, byteorder='big')")

    def test_parse_error(self):
        i = Float(4, byteorder='big')
        with self.assertRaises(ParsingError):
            i.parse(b"")  # Empty byte string


class TestAdapted(unittest.TestCase):

    def test_adapted(self):
        a = Adapted(Flag(),
                    before_build=lambda obj: obj != 'no',
                    after_parse=lambda obj: 'yes' if obj else 'no')
        self.assertEqual(a.build('yes'), b'\x01')
        self.assertEqual(a.parse(b'\x00'), 'no')
        self.assertEqual(a.sizeof(), 1)

    def test_no_adaptation(self):
        a = Adapted(Flag())  # Not before_build or after_parse
        self.assertEqual(a.build(True), b'\x01')
        self.assertEqual(a.parse(b'\x00'), False)
        self.assertEqual(a.sizeof(), 1)

    def test_before_build_only(self):
        a = Adapted(Flag(), before_build=lambda obj: int(obj))
        self.assertEqual(a.build(1), b'\x01')
        self.assertEqual(a.parse(b'\x00'), False)  # Parsing remains unchanged

    def test_after_parse_only(self):
        a = Adapted(Flag(), after_parse=lambda obj: 'yes' if obj else 'no')
        self.assertEqual(a.build(True), b'\x01')  # Building remains unchanged
        self.assertEqual(a.parse(b'\x00'), 'no')


class TestPadding(unittest.TestCase):
    def test_initialization(self):
        padding = Padding(4)
        self.assertEqual(padding.length, 4)
        self.assertEqual(padding.pad_char, b'\x00')

        padding = Padding(8, b'#')
        self.assertEqual(padding.length, 8)
        self.assertEqual(padding.pad_char, b'#')

        with self.assertRaisesRegex(ValueError, "length must be >= 0, got -1"):
            Padding(-1)

        with self.assertRaisesRegex(ValueError, "pad_char must be a single-length bytes, got b'aa'"):
            Padding(4, b'aa')

    def test_build_stream(self):
        padding = Padding(4)
        stream = BytesIO()
        padding._build_stream(None, stream, None)
        self.assertEqual(stream.getvalue(), b'\x00\x00\x00\x00')

        padding = Padding(3, b'#')
        stream = BytesIO()
        padding._build_stream(None, stream, None)
        self.assertEqual(stream.getvalue(), b'###')

    def test_parse_stream(self):
        padding = Padding(4)
        stream = BytesIO(b'\x00\x00\x00\x00')
        parsed_data = padding._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'\x00\x00\x00\x00')

        padding = Padding(3, b'#')
        stream = BytesIO(b'###')
        parsed_data = padding._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'###')

        padding = Padding(2, b'$')
        stream = BytesIO(b'$$')
        parsed_data = padding._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'$$')

        padding = Padding(3)
        stream = BytesIO(b'\x00\x00\x01')
        with self.assertRaisesRegex(ParsingError,
                                    r"expected to parse b'\\x00\\x00\\x00', got b'\\x00\\x00\\x01' instead"):
            padding._parse_stream(stream, None)

        padding = Padding(2, b'A')
        stream = BytesIO(b'AB')
        with self.assertRaisesRegex(ParsingError, r"expected to parse b'AA', got b'AB' instead"):
            padding._parse_stream(stream, None)

    def test_sizeof(self):
        padding = Padding(4)
        self.assertEqual(padding._sizeof(None), 4)

        padding = Padding(10)
        self.assertEqual(padding._sizeof(None), 10)

    def test_repr(self):
        padding = Padding(4)
        self.assertEqual(repr(padding), "Padding(4, pad_char=b'\\x00')")

        padding = Padding(2, b'#')
        self.assertEqual(repr(padding), "Padding(2, pad_char=b'#')")


class TestRepeat(unittest.TestCase):
    def test_initialization(self):
        repeat = Repeat(Flag(), 1, 4)
        self.assertEqual(repeat.start, 1)
        self.assertEqual(repeat.stop, 4)
        self.assertIsNone(repeat.until)

        repeat_until = Repeat(Flag(), 1, 5, until=lambda obj: not obj[-1])
        self.assertEqual(repeat_until.start, 1)
        self.assertEqual(repeat_until.stop, 5)
        self.assertIsNotNone(repeat_until.until)

        with self.assertRaisesRegex(ValueError, "start must be >= 0, got -1"):
            Repeat(Flag(), -1, 0)
        with self.assertRaisesRegex(ValueError, "stop must be >= 0, got -1"):
            Repeat(Flag(), 0, -1)
        with self.assertRaisesRegex(ValueError, "stop must be >= start"):
            Repeat(Flag(), 6, 2)

    def test_build_stream(self):
        repeat = Repeat(Flag(), 1, 4)
        stream = BytesIO()
        repeat._build_stream([True, True], stream, None)
        self.assertEqual(stream.getvalue(), b'\x01\x01')

        repeat_until = Repeat(Flag(), 1, 5, until=lambda obj: not obj[-1])
        stream = BytesIO()
        repeat_until._build_stream([True, True, False, True], stream, None)
        self.assertEqual(stream.getvalue(), b'\x01\x01\x00')

        with self.assertRaisesRegex(BuildingError, r"length of the object to build must be in range \[3, 5\), got 2"):
            Repeat(Flag(), 3, 5)._build_stream([True, True], BytesIO(), None)

    def test_parse_stream(self):
        repeat = Repeat(Flag(), 1, 4)
        stream = BytesIO(b'\x00\x01\x00')
        parsed_data = repeat._parse_stream(stream, None)
        self.assertEqual(parsed_data, [False, True, False])

        repeat_until = Repeat(Flag(), 1, 5, until=lambda obj: not obj[-1])
        stream = BytesIO(b'\x01\x00\x00')
        parsed_data = repeat_until._parse_stream(stream, None)
        self.assertEqual(parsed_data, [True, False])

        with self.assertRaisesRegex(ParsingError,
                                    r"required to parse at least 3 of Flag.*, parsed 2 instead; error was: could not read enough bytes, expected 1, found 0"):
            Repeat(Flag(), 3, 5)._parse_stream(BytesIO(b'\x01\x01'), None)

        with self.assertRaisesRegex(ParsingError,
                                    r"required to parse at least 3 of Flag.*, parsed 1 instead; exited due to 'until' predicate"):
            Repeat(Flag(), 3, 5, until=lambda items: not items[-1])._parse_stream(BytesIO(b'\x00'), None)

    def test_sizeof(self):
        repeat_fixed = Repeat(Flag(), 3, 4)
        self.assertEqual(repeat_fixed._sizeof(None), 3)

        with self.assertRaisesRegex(SizeofError, "cannot determine size of variable sized Repeat()"):
            Repeat(Flag(), 1, 4)._sizeof(None)

        with self.assertRaisesRegex(SizeofError, "cannot determine size of variable sized Repeat()"):
            Repeat(Flag(), 3, 5, until=lambda items: not items[-1])._sizeof(None)

    def test_repr(self):
        repeat = Repeat(Flag(), 2, 5)
        self.assertEqual(repr(repeat), "Repeat(Flag(), start=2, stop=5)")

        repeat_until = Repeat(Flag(), 1, 3, until=lambda obj: not obj[-1])
        self.assertRegex(repr(repeat_until), r"Repeat\(Flag\(\), start=1, stop=3, until=<function .*>\)")


class TestRepeatExactly(unittest.TestCase):
    def test_initialization(self):
        repeat_exactly = RepeatExactly(Flag(), 3)
        self.assertEqual(repeat_exactly.start, 3)
        self.assertEqual(repeat_exactly.stop, 4)
        self.assertIsNone(repeat_exactly.until)

        repeat_exactly_until = RepeatExactly(Flag(), 5, until=lambda obj: not obj[-1])
        self.assertEqual(repeat_exactly_until.start, 5)
        self.assertEqual(repeat_exactly_until.stop, 6)
        self.assertIsNotNone(repeat_exactly_until.until)

    def test_build_stream(self):
        repeat_exactly = RepeatExactly(Flag(), 3)
        stream = BytesIO()
        repeat_exactly._build_stream([True, False, True], stream, None)
        self.assertEqual(stream.getvalue(), b'\x01\x00\x01')

        with self.assertRaisesRegex(BuildingError, r"length of the object to build must be in range \[3, 4\), got 2"):
            repeat_exactly._build_stream([True, False], BytesIO(), None)

    def test_parse_stream(self):
        repeat_exactly = RepeatExactly(Flag(), 3)
        stream = BytesIO(b'\x00\x01\x00')
        parsed_data = repeat_exactly._parse_stream(stream, None)
        self.assertEqual(parsed_data, [False, True, False])

        with self.assertRaisesRegex(ParsingError,
                                    r"required to parse at least 3 of Flag.*, parsed 2 instead; error was: could not read enough bytes, expected 1, found 0"):
            repeat_exactly._parse_stream(BytesIO(b'\x00\x01'), None)

    def test_sizeof(self):
        repeat_exactly = RepeatExactly(Flag(), 3)
        self.assertEqual(repeat_exactly._sizeof(None), 3)

    def test_repr(self):
        repeat_exactly = RepeatExactly(Flag(), 3)
        self.assertEqual(repr(repeat_exactly), "RepeatExactly(Flag(), 3)")

        repeat_exactly_until = RepeatExactly(Flag(), 4, until=lambda obj: not obj[-1])
        self.assertRegex(repr(repeat_exactly_until), r"RepeatExactly\(Flag\(\), 4\)")


class TestPrefixed(unittest.TestCase):
    def test_initialization(self):
        length_field = Integer(1)
        prefixed = Prefixed(Bytes(), length_field)
        self.assertEqual(prefixed.length_field, length_field)

    def test_build_stream(self):
        length_field = Integer(1)
        prefixed = Prefixed(Bytes(), length_field)
        stream = BytesIO()
        prefixed._build_stream(b'foo', stream, None)
        self.assertEqual(stream.getvalue(), b'\x03foo')

        prefixed = Prefixed(Bytes(), Integer(2))
        stream = BytesIO()
        prefixed._build_stream(b'barbaz', stream, None)
        self.assertEqual(stream.getvalue(), b'\x00\x06barbaz')

    def test_parse_stream(self):
        length_field = Integer(1)
        prefixed = Prefixed(Bytes(), length_field)
        stream = BytesIO(b'\x06foobar')
        parsed_data = prefixed._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'foobar')

        prefixed = Prefixed(Bytes(), Integer(2))
        stream = BytesIO(b'\x00\x04test')
        parsed_data = prefixed._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'test')

        with self.assertRaisesRegex(ParsingError, r"could not read enough bytes, expected 6, found 3"):
            prefixed._parse_stream(BytesIO(b'\x00\x06baz'), None)

    def test_sizeof(self):
        prefixed_fixed = Prefixed(Integer(4), Integer(1))
        self.assertEqual(prefixed_fixed._sizeof(None), 5)

        with self.assertRaisesRegex(SizeofError, r"Bytes\(\) has no fixed size"):
            Prefixed(Bytes(), Prefixed(Integer(1), Integer(1)))._sizeof(None)

        with self.assertRaisesRegex(SizeofError, r"Bytes\(\) has no fixed size"):
            Prefixed(Bytes(), Integer(1))._sizeof(None)

    def test_repr(self):
        length_field = Integer(1)
        prefixed = Prefixed(Bytes(), length_field)
        self.assertEqual(repr(prefixed), f"Prefixed(Bytes(), length_field={length_field})")

        prefixed_bytes = Prefixed(Bytes(), Integer(2))
        self.assertEqual(repr(prefixed_bytes),
                         f"Prefixed(Bytes(), length_field={Integer(2, byteorder='big', signed=False)})")


class TestPadded(unittest.TestCase):
    def test_initialization(self):
        padded = Padded(Bytes(3), 6)
        self.assertEqual(padded.construct.sizeof(), 3)
        self.assertEqual(padded.length, 6)

        with self.assertRaisesRegex(ValueError, "length must be >= 0, got -2"):
            Padded(Bytes(3), -2)

    def test_build_stream(self):
        padded = Padded(Bytes(3), 6)
        stream = BytesIO()
        padded._build_stream(b'foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\x00\x00\x00')

        padded = Padded(Bytes(5), 8)
        stream = BytesIO()
        padded._build_stream(b'hello', stream, None)
        self.assertEqual(stream.getvalue(), b'hello\x00\x00\x00')

    def test_parse_stream(self):
        padded = Padded(Bytes(3), 6)
        stream = BytesIO(b'bar\x00\x00\x00')
        parsed_data = padded._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'bar')

        padded = Padded(Bytes(5), 8, pad_byte=b'X')  # Test with non-null padding
        stream = BytesIO(b'worldXXX')
        parsed_data = padded._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'world')

        with self.assertRaisesRegex(ParsingError, f"could not read enough bytes, expected 8, found {len(b'baz')}"):
            padded._parse_stream(BytesIO(b'baz'), None)

        with self.assertRaisesRegex(ParsingError,
                                    f"Trailing bytes are not all pad bytes b'X'. Expected 3 bytes: b'XXX', but found invalid padding: b'XXY'."):
            padded._parse_stream(BytesIO(b'worldXXY'), None)

    def test_sizeof(self):
        padded = Padded(Bytes(3), 6)
        self.assertEqual(padded._sizeof(None), 6)

        padded = Padded(Bytes(10), 15)
        self.assertEqual(padded._sizeof(None), 15)

    def test_repr(self):
        padded = Padded(Bytes(3), 6)
        self.assertEqual(repr(padded), "Padded(Bytes(3), length=6)")

        padded = Padded(Bytes(1), 4)
        self.assertEqual(repr(padded), "Padded(Bytes(1), length=4)")


class TestAligned(unittest.TestCase):
    def test_build(self):
        a = Aligned(Bytes(6), 4)
        assert a.build(b'foobar') == b'foobar\x00\x00'

        a = Aligned(Bytes(3), 4)
        assert a.build(b'foo') == b'foo\x00'
        a = Aligned(Bytes(4), 4)
        assert a.build(b'abcd') == b'abcd'  # No padding needed
        a = Aligned(Bytes(7), 4)
        assert a.build(b'abcdefg') == b'abcdefg\x00'

    def test_parse(self):
        a = Aligned(Bytes(6), 4)
        assert a.parse(b'foobar\x00\x00') == b'foobar'

        a = Aligned(Bytes(3), 4)
        assert a.parse(b'foo\x00') == b'foo'
        a = Aligned(Bytes(4), 4)
        assert a.parse(b'abcd') == b'abcd'
        a = Aligned(Bytes(7), 4)
        assert a.parse(b'abcdefg\x00') == b'abcdefg'

    def test_sizeof(self):
        a = Aligned(Bytes(6), 4)
        assert a.sizeof() == 8

        a = Aligned(Bytes(3), 4)
        assert a.sizeof() == 4
        a = Aligned(Bytes(4), 4)
        assert a.sizeof() == 4
        a = Aligned(Bytes(7), 4)
        assert a.sizeof() == 8

    def test_invalid_padding(self):
        a = Aligned(Bytes(6), 4)

        with self.assertRaisesRegex(ParsingError, "must read padding of b'00 00', got b'00 01'"):
            a.parse(b'foobar\x00\x01')

        with self.assertRaisesRegex(ParsingError, "must read padding of b'00 00', got b'01 00'"):
            a.parse(b'foobar\x01\x00')

        with self.assertRaisesRegex(ParsingError, "must read padding of b'00 00', got b''"):
            a.parse(b'foobar')

    def test_align(self):
        a = Aligned(Bytes(1)[2:8], 4)
        self.assertEqual(repr(a), "Aligned(Repeat(Bytes(1), start=2, stop=8), length=4)")
        self.assertEqual(a.build(b'foobar'), b'foobar\x00\x00')
        self.assertEqual(b''.join(a.parse(b'foo\x00')), b'foo\x00')
        with self.assertRaises(SizeofError):
            a.sizeof()

    def test_aligned_zero_length(self):
        a = Aligned(Bytes(0), 4)
        self.assertEqual(a.sizeof(), 0)
        self.assertEqual(a.build(b''), b'')
        self.assertEqual(b''.join(a.parse(b'')), b'')

    def test_aligned_various_lengths(self):
        for length in range(1, 10):
            for alignment in range(1, 5):
                a = Aligned(Bytes(length), alignment)
                expected_size = (length + alignment - 1) // alignment * alignment
                self.assertEqual(a.sizeof(), expected_size)
                data = b'A' * length
                built_data = a.build(data)
                self.assertEqual(len(built_data), expected_size)
                self.assertEqual(built_data[:length], data)
                self.assertEqual(built_data[length:], b'\x00' * (expected_size - length))
                parsed_data = a.parse(built_data)
                self.assertEqual(parsed_data, data)

    def test_aligned_nested_repeat(self):

        # Use a fixed-size Repeat (min_count = max_count)
        a = Aligned(Repeat(Bytes(2), 4, 5), 4)  # Repeat 4 times, align to 4

        data = [b'12', b'34', b'56', b'78']  # Correct data format: a list of bytes
        built_data = a.build(data)
        self.assertEqual(built_data, b'12345678')
        self.assertEqual(a.parse(b'12345678'), data)

    def test_aligned_nested_repeat_variable_build(self):
        a = Aligned(Repeat(Bytes(2), 1, 5), 4)

        data = [b'12', b'34']
        built_data = a.build(data)
        self.assertEqual(built_data, b'1234')

        data = [b'12', b'34', b'56', b'78']
        built_data = a.build(data)
        self.assertEqual(built_data, b'12345678')

    def test_aligned_nested_repeat_variable_parse(self):
        a = Aligned(Repeat(Bytes(2), 1, 5), 4)

        parsed_data = a.parse(b'1234')
        self.assertEqual(parsed_data, [b'12', b'34'])

        parsed_data = a.parse(b'12345678')
        self.assertEqual(parsed_data, [b'12', b'34', b'56', b'78'])

        parsed_data = a.parse(b'12\x00\x00')  # Test with padding
        self.assertEqual(parsed_data, [b'12', b'\x00\x00'])

        with self.assertRaisesRegex(ParsingError, "must read padding of b'00 00', got b''"):
            a.parse(b'12')

    def test_raise(self):
        a = Aligned(Bytes(6), 4)  # Fixed-size inner construct
        self.assertEqual(a.sizeof(), 8)  # Sizeof should work for fixed-size constructs
        with self.assertRaisesRegex(ParsingError, r"must read padding of b'00 00', got b'00 01'"):
            a.parse(b'foobar\x00\x01')

        a = Aligned(Repeat(Bytes(1), 2, 8), 4)  # Variable-sized inner construct
        with self.assertRaisesRegex(SizeofError, r"cannot determine size of variable sized Repeat"):
            a.sizeof()  # Sizeof should raise an error for variable-sized constructs


class TestString(unittest.TestCase):
    def test_initialization_unicode(self):
        s = String(8, encoding='utf-8')
        self.assertEqual(s.length, 8)
        self.assertEqual(s.encoding, 'utf-8')

    def test_initialization_bytes(self):
        s = String(8)
        self.assertEqual(s.length, 8)
        self.assertIsNone(s.encoding)

    def test_build_stream_unicode(self):
        s = String(8, encoding='utf-8')
        stream = BytesIO()
        s._build_stream('foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\x00\x00\x00\x00\x00')

    def test_build_stream_bytes(self):
        s = String(8)
        stream = BytesIO()
        s._build_stream(b'foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\x00\x00\x00\x00\x00')

    def test_parse_stream_unicode(self):
        s = String(8, encoding='utf-8')
        stream = BytesIO(b'foo\x00\x00\x00\x00\x00')
        parsed_data = s._parse_stream(stream, None)
        self.assertEqual(parsed_data, 'foo')

    def test_parse_stream_bytes(self):
        s = String(8)
        stream = BytesIO(b'foo\x00\x00\x00\x00\x00')
        parsed_data = s._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'foo')

    def test_build_stream_long_string_raises_error(self):
        s = String(8, encoding='utf-8')
        with self.assertRaisesRegex(BuildingError, r"length of the string to build must be in range \[1, 9\), got 15"):
            s._build_stream('foobarbazxxxyyy', BytesIO(), None)

    def test_build_with_adapter(self):
        s = String(8, encoding='utf-8')
        a = Adapted(s, before_build=lambda obj: obj[:8])
        self.assertEqual(a.build('foobarbazxxxyyy'), b'foobarba')

    def test_parse_stream_not_enough_bytes_raises_error(self):
        s = String(8)
        with self.assertRaisesRegex(ParsingError, r"could not read enough bytes, expected 8, found 3"):
            s._parse_stream(BytesIO(b'foo'), None)

    def test_sizeof(self):
        s = String(8)
        self.assertEqual(s._sizeof(None), 8)

    def test_repr_unicode(self):
        s = String(8, encoding='utf-8')
        self.assertEqual(repr(s), "String(length=8, encoding='utf-8')")

    def test_repr_bytes(self):
        s = String(8)
        self.assertEqual(repr(s), "String(length=8)")

    def test_initialization_negative_length_raises_error(self):
        with self.assertRaises(ValueError):
            String(-1)


class TestPascalString(unittest.TestCase):
    def test_initialization_unicode(self):
        length_field = Integer(1)
        p = PascalString(length_field, encoding='utf-8')
        self.assertEqual(p.length_field, length_field)
        self.assertEqual(p.encoding, 'utf-8')

    def test_initialization_bytes(self):
        length_field = Integer(1)
        p = PascalString(length_field)
        self.assertEqual(p.length_field, length_field)
        self.assertIsNone(p.encoding)

    def test_build_stream_unicode(self):
        length_field = Integer(1)
        p = PascalString(length_field, encoding='utf-8')
        stream = BytesIO()
        p._build_stream('foo', stream, None)
        self.assertEqual(stream.getvalue(), b'\x03foo')

    def test_build_stream_bytes(self):
        length_field = Integer(1)
        p = PascalString(length_field)
        stream = BytesIO()
        p._build_stream(b'foo', stream, None)
        self.assertEqual(stream.getvalue(), b'\x03foo')

    def test_parse_stream_unicode(self):
        length_field = Integer(1)
        p = PascalString(length_field, encoding='utf-8')
        stream = BytesIO(b'\x08\xd0\x98\xd0\xb2\xd0\xb0\xd0\xbd')
        parsed_data = p._parse_stream(stream, None)
        self.assertEqual(parsed_data, 'Иван')
        stream = BytesIO(b'\x12\xe5\x93\xbc\xe5\x93\xbc\xe5\x93\xbc\xe5\x95\x8a\xe5\x95\x8a\xe5\x95\x8a')
        parsed_data = p._parse_stream(stream, None)
        self.assertEqual(parsed_data, '哼哼哼啊啊啊')

    def test_parse_stream_bytes(self):
        length_field = Integer(1)
        p = PascalString(length_field)
        stream = BytesIO(b'\x06foobar')
        parsed_data = p._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'foobar')

    def test_sizeof(self):
        p = PascalString(Integer(1))
        with self.assertRaisesRegex(SizeofError, r"PascalString has no fixed size"):
            p._sizeof(None)

    def test_repr_unicode(self):
        length_field = Integer(1)
        p = PascalString(length_field, encoding='utf-8')
        self.assertEqual(repr(p),
                         f"PascalString(length_field=Integer(1, byteorder='big', signed=False), encoding='utf-8')")

    def test_repr_bytes(self):
        length_field = Integer(1)
        p = PascalString(length_field)
        self.assertEqual(repr(p), f"PascalString(length_field=Integer(1, byteorder='big', signed=False))")
        length_field = Integer(2)
        p = PascalString(length_field, encoding='utf8')
        self.assertEqual(repr(p),
                         f"PascalString(length_field=Integer(2, byteorder='big', signed=False), encoding='utf8')")


class TestCString(unittest.TestCase):
    def test_initialization_with_encoding(self):
        s = CString('utf-8')
        self.assertEqual(s.encoding, 'utf-8')

    def test_initialization_without_encoding(self):
        s = CString()
        self.assertIsNone(s.encoding)

    def test_build_stream_with_encoding(self):
        s = CString('utf-8')
        stream = BytesIO()
        s._build_stream('foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\x00')

    def test_build_stream_without_encoding(self):
        s = CString()
        stream = BytesIO()
        s._build_stream(b'foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\x00')

    def test_parse_stream_with_encoding(self):
        s = CString('utf-8')
        stream = BytesIO(b'bar\x00baz')
        parsed_data = s._parse_stream(stream, None)
        self.assertEqual(parsed_data, 'bar')

    def test_parse_stream_without_encoding(self):
        s = CString()
        stream = BytesIO(b'bar\x00')
        parsed_data = s._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'bar')

    def test_parse_stream_end_of_stream(self):
        s = CString()
        stream = BytesIO(b'bar')
        with self.assertRaisesRegex(ParsingError, r"could not read enough bytes, the stream has ended"):
            s._parse_stream(stream, None)

    def test_sizeof(self):
        s = CString()
        with self.assertRaisesRegex(SizeofError, r"CString has no fixed size"):
            s._sizeof(None)

    def test_repr_with_encoding(self):
        s = CString('utf-8')
        self.assertEqual(repr(s), "CString(encoding='utf-8')")

    def test_repr_without_encoding(self):
        s = CString()
        self.assertEqual(repr(s), "CString()")

    def test_build_stream_utf16le(self):
        s = CString('utf-16-le')
        stream = BytesIO()
        s._build_stream('foo', stream, None)
        self.assertEqual(stream.getvalue(), b'f\x00o\x00o\x00\x00')

    def test_parse_stream_utf16le_raises_error(self):
        s = CString('utf-16-le')
        built_data = b'f\x00o\x00o\x00\x00'
        with self.assertRaisesRegex(ParsingError,
                                    r"'utf-16-le' codec can't decode: 'utf16-le'|'utf-16-le'|'utf_16_le' codec can't decode byte 0x66 in position 0: truncated data"):
            s._parse_stream(BytesIO(built_data), None)


class TestLine(unittest.TestCase):
    def test_initialization_default_encoding(self):
        l = Line()
        self.assertEqual(l.encoding, 'latin-1')

    def test_initialization_custom_encoding(self):
        l = Line(encoding='utf-8')
        self.assertEqual(l.encoding, 'utf-8')

    def test_initialization_no_encoding(self):
        l = Line(encoding=None)
        self.assertIsNone(l.encoding)

    def test_build_stream_default_encoding(self):
        l = Line()
        stream = BytesIO()
        l._build_stream('foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\r\n')

    def test_build_stream_custom_encoding(self):
        l = Line(encoding='utf-8')
        stream = BytesIO()
        l._build_stream('你好', stream, None)
        self.assertEqual(stream.getvalue(), '你好'.encode('utf-8') + b'\r\n')

    def test_build_stream_no_encoding(self):
        l = Line(encoding=None)
        stream = BytesIO()
        l._build_stream(b'foo', stream, None)
        self.assertEqual(stream.getvalue(), b'foo\r\n')

    def test_parse_stream_default_encoding(self):
        l = Line()
        stream = BytesIO(b'bar\r\n')
        parsed_data = l._parse_stream(stream, None)
        self.assertEqual(parsed_data, 'bar')

    def test_parse_stream_custom_encoding(self):
        l = Line(encoding='utf-8')
        stream = BytesIO('你好'.encode('utf-8') + b'\r\n')
        parsed_data = l._parse_stream(stream, None)
        self.assertEqual(parsed_data, '你好')

    def test_parse_stream_no_encoding(self):
        l = Line(encoding=None)
        stream = BytesIO(b'bar\r\nbaz\r\n')
        parsed_data = l._parse_stream(stream, None)
        self.assertEqual(parsed_data, b'bar')

    def test_parse_stream_end_of_stream(self):
        l = Line()
        stream = BytesIO(b'bar')
        with self.assertRaisesRegex(ParsingError, r"could not read enough bytes, the stream has ended"):
            l._parse_stream(stream, None)

    def test_sizeof(self):
        l = Line()
        with self.assertRaisesRegex(SizeofError, r"Line has no fixed size"):
            l._sizeof(None)

    def test_repr_default_encoding(self):
        l = Line()
        self.assertEqual(repr(l), "Line()")

    def test_repr_custom_encoding(self):
        l = Line(encoding='utf-8')
        self.assertEqual(repr(l), "Line(encoding='utf-8')")

    def test_repr_no_encoding(self):
        l = Line(encoding=None)
        self.assertEqual(repr(l), "Line(encoding=None)")


class TestStructMeta(unittest.TestCase):
    def test_struct_fields_population(self):
        class MyConstruct(Construct):
            pass

        class MyStruct(Struct):
            __struct_fields__ = None  # Make type checker happy :)
            field1 = MyConstruct()
            field2 = MyConstruct()
            not_a_field = 1

        self.assertIsInstance(MyStruct.__struct_fields__, OrderedDict)
        self.assertEqual(list(MyStruct.__struct_fields__.keys()), ['field1', 'field2'])
        self.assertIsInstance(MyStruct.__struct_fields__['field1'], MyConstruct)
        self.assertIsInstance(MyStruct.__struct_fields__['field2'], MyConstruct)

    def test_slots_generation(self):
        class MyStructWithNoSlots(Struct):
            field1 = Construct()

        self.assertEqual(MyStructWithNoSlots.__slots__, ())

        class MyStructWithSlots(Struct):
            __slots__ = ('a', 'b')
            field1 = Construct()

        self.assertEqual(MyStructWithSlots.__slots__, ('a', 'b'))


class TestBitFieldStructMeta(unittest.TestCase):
    def test_bit_fields_population(self):
        class MyBit(Bit):
            pass

        class MyBitPadding(BitPadding):
            pass

        class MyBitFieldStruct(BitFieldStruct):
            __bit_fields__ = None  # Make type checker happy :)
            bit_field1 = MyBit(1)
            padding_field = MyBitPadding(1)
            not_a_bit_field = 1

        self.assertIsInstance(MyBitFieldStruct.__bit_fields__, OrderedDict)
        self.assertEqual(list(MyBitFieldStruct.__bit_fields__.keys()), ['bit_field1', 'padding_field'])
        self.assertIsInstance(MyBitFieldStruct.__bit_fields__['bit_field1'], MyBit)
        self.assertIsInstance(MyBitFieldStruct.__bit_fields__['padding_field'], MyBitPadding)

    def test_slots_inheritance(self):
        class MyBitFieldStructWithImplicitSlots(BitFieldStruct):
            bit_field1 = Bit(1)

        self.assertEqual(MyBitFieldStructWithImplicitSlots.__slots__, Construct.__slots__)

        class MyBitFieldStructWithExplicitSlots(BitFieldStruct):
            __slots__ = ('x', 'y')
            bit_field1 = Bit(1)

        self.assertEqual(MyBitFieldStructWithExplicitSlots.__slots__, ('x', 'y'))


class TestStruct(unittest.TestCase):
    def test_basic_struct(self):
        class Entry(Struct):
            key = Integer(1)
            value = Bytes(3)

        entry = Entry()
        self.assertEqual(entry.build({'key': 1, 'value': b'foo'}), b'\x01foo')
        self.assertEqual(entry.parse(b'\x10bar'), {'key': 16, 'value': b'bar'})
        self.assertEqual(entry.sizeof(), 4)
        self.assertIsInstance(entry.fields, OrderedDict)
        self.assertEqual(list(entry.fields.keys()), ['key', 'value'])
        self.assertIsInstance(entry.fields['key'], Integer)
        self.assertIsInstance(entry.fields['value'], Bytes)
        self.assertEqual(repr(entry), "Entry()")

    def test_contextual_struct(self):
        class Entry(Struct):
            length = Integer(1)
            data = Contextual(Bytes, lambda ctx: ctx['length'])

        entry = Entry()
        self.assertEqual(entry.build({'length': 3, 'data': b'foo'}), b'\x03foo')
        self.assertEqual(entry.build({'length': 6, 'data': b'abcdef'}), b'\x06abcdef')
        self.assertEqual(entry.parse(b'\x02barbaz'), {'length': 2, 'data': b'ba'})
        self.assertEqual(entry.sizeof(context=Context({'length': 10})), 11)

    def test_composed_struct(self):
        class Header(Struct):
            payload_size = Integer(1)

        class Message(Struct):
            header = Header()
            payload = Contextual(Bytes, lambda ctx: ctx['header']['payload_size'])

        message = Message()
        data = {'header': {'payload_size': 3}, 'payload': b'foo'}
        self.assertEqual(message.build(data), b'\x03foo')
        self.assertEqual(message.parse(b'\x03foo'), data)

    def test_embedded_struct(self):
        class Header(Struct):
            payload_size = Integer(1)

        class Message(Struct):
            header = Header(embedded=True)
            payload = Contextual(Bytes, lambda ctx: ctx['payload_size'])

        message = Message()
        data = {'payload_size': 3, 'payload': b'foo'}
        self.assertEqual(message.build(data), b'\x03foo')
        self.assertEqual(message.parse(b'\x03foo'), data)
        self.assertEqual(repr(message), "Message()")
        self.assertEqual(repr(Header(embedded=True)), "Header(embedded=True)")

    def test_adapted_embedded_struct(self):
        class Header(Struct):
            payload_size = Integer(1)

        def mul_by_3(obj):
            obj['payload_size'] *= 3
            return obj

        class Message(Struct):
            header = Adapted(
                Header(embedded=True),
                before_build=mul_by_3,
                after_parse=mul_by_3,
            )
            payload = Contextual(Bytes, lambda ctx: ctx['payload_size'])

        message = Message()
        self.assertEqual(message.build({'payload_size': 1, 'payload': b'foo'}), b'\x03foo')
        self.assertEqual(message.parse(b'\x01bar'), {'payload_size': 3, 'payload': b'bar'})

    def test_sizeof_error(self):
        class DynamicBytes(Construct):
            def _sizeof(self, context: Context) -> int:
                raise SizeofError("Dynamic size")

        class MyStruct(Struct):
            field1 = Integer(1)
            field2 = DynamicBytes()

        my_struct = MyStruct()
        with self.assertRaisesRegex(SizeofError, "Dynamic size"):
            my_struct.sizeof()


class TestBitFieldStruct(unittest.TestCase):
    def test_basic_bitfield_struct(self):
        class MyBitfields(BitFieldStruct):
            foo = Bit(1)
            _ = BitPadding(3)
            bar = Bit(3)
            overflow = Bit(4)

        b = MyBitfields()
        self.assertEqual(b.build({'foo': 1, 'bar': 0b101, 'overflow': 0b1111}), b'\xd1\x07')
        self.assertEqual(b.parse(b'\xf0\xff'), {'foo': 0, 'bar': 7, 'overflow': 15})
        self.assertEqual(b.sizeof(), 2)  # Corrected expected size
        self.assertIsInstance(b.fields, OrderedDict)
        self.assertEqual(list(b.fields.keys()), ['foo', '_', 'bar', 'overflow'])
        self.assertIsInstance(b.fields['foo'], Bit)
        self.assertIsInstance(b.fields['_'], BitPadding)
        self.assertIsInstance(b.fields['bar'], Bit)
        self.assertIsInstance(b.fields['overflow'], Bit)
        self.assertEqual(repr(b), "MyBitfields(foo[0:0], _PAD_[1:3], bar[4:6], overflow[7:10])")

    def test_partial_build(self):
        class MyBitfields(BitFieldStruct):
            foo = Bit(1)
            _ = BitPadding(3)
            bar = Bit(3)
            overflow = Bit(4)

        b = MyBitfields()
        built_full = b.build({'foo': 0, 'bar': 0b101, 'overflow': 0b1111})
        built_partial = b.build({'bar': 0b101, 'overflow': 0b1111})
        self.assertEqual(built_full, built_partial)

    def test_parse_insufficient_data(self):
        class MyBitfields(BitFieldStruct):
            foo = Bit(1)
            _ = BitPadding(3)
            bar = Bit(3)
            overflow = Bit(4)

        b = MyBitfields()
        with self.assertRaisesRegex(ParsingError,
                                    "Insufficient data length for parsing BitFieldStruct! Expected 2 got 1."):
            b.parse(b'\xff')

    def test_build_packing_error(self):
        class MyBitfields(BitFieldStruct):
            foo = Bit(1)
            _ = BitPadding(3)
            bar = Bit(3)
            overflow = Bit(4)

        b = MyBitfields()
        with self.assertRaisesRegex(BuildingError, "Cannot pack 3 into 1 bits!"):
            b.build({'foo': 3})

    def test_embedded_bitfield_struct(self):
        class MyBitfields(BitFieldStruct):
            foo = Bit(1)
            _ = BitPadding(3)
            bar = Bit(3)
            overflow = Bit(4)

        class MyContainerStruct(Struct):
            something = Integer(2)
            bitfields = MyBitfields(embedded=True)

        x = MyContainerStruct()
        self.assertEqual(x.sizeof(), 4)
        self.assertEqual(repr(MyBitfields(embedded=True)),
                         "MyBitfields(embedded=True, foo[0:0], _PAD_[1:3], bar[4:6], overflow[7:10])")


class TestContextual(unittest.TestCase):
    def test_initialization(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        self.assertRegex(repr(c), r"^Contextual\(Integer, <function .+ ")

    def test_build_stream(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        stream = BytesIO()
        c._build_stream(1, stream, context=Context({'length': 1}))
        self.assertEqual(stream.getvalue(), b'\x01')

        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        stream = BytesIO()
        c._build_stream(1, stream, context=Context({'length': 2}))
        self.assertEqual(stream.getvalue(), b'\x00\x01')

    def test_build_stream_error(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        stream = BytesIO()
        with self.assertRaisesRegex(ContextualError, "length"):
            c._build_stream(1, stream, context=Context({}))

    def test_parse_stream(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        self.assertEqual(c._parse_stream(BytesIO(b'\x01'), context=Context({'length': 1})), 1)

        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))

        self.assertEqual(c._parse_stream(BytesIO(b'\x00\x01'), context=Context({'length': 2})), 1)

    def test_parse_stream_error(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        with self.assertRaisesRegex(ValueError, "length must be 1, 2, 4, or 8, got [0-9]+"):
            c._parse_stream(BytesIO(b'\x01'), context=Context({'length': 0}))
        with self.assertRaisesRegex(ContextualError, "length"):
            c._parse_stream(BytesIO(b'\x01'), context=Context())

    def test_sizeof(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        self.assertEqual(c._sizeof(context=Context({'length': 4})), 4)

    def test_sizeof_error(self):
        c = Contextual(Integer, lambda ctx: (ctx['length'], 'big'))
        with self.assertRaisesRegex(ContextualError, "'length'"):
            c._sizeof(Context({}))


class TestComputed(unittest.TestCase):
    def test_computed_constant(self):
        c = Computed(b'foo')
        self.assertEqual(c._parse_stream(BytesIO(b''), {}), b'foo')
        self.assertEqual(c._build_stream(b'foo', BytesIO(b''), {}), b'foo')
        self.assertEqual(c._sizeof({}), 0)

    def test_computed_function(self):
        class Example(Struct):
            x = Integer(1)
            y = Integer(1)
            x_plus_y = Computed(lambda ctx: ctx['x'] + ctx['y'])
            z = Contextual(Bytes, lambda ctx: ctx['x_plus_y'])

        example = Example()
        self.assertEqual(example.parse(b'\x01\x02foo'), {'x': 1, 'y': 2, 'z': b'foo', 'x_plus_y': 3})

        # Test build (requires a slight modification, as Computed doesn't build)
        built_data = example.build({'x': 1, 'y': 2, 'x_plus_y': 3, 'z': b'foo'})
        # This will be b'\x01\x02foo' since Computed doesn't write
        # Check that other fields are built correctly
        self.assertEqual(len(built_data), 5)

    def test_computed_function_key_error(self):
        c = Computed(lambda ctx: ctx['missing'])
        with self.assertRaisesRegex(ValidationError, "KeyError in Computed field"):
            c._parse_stream(BytesIO(b''), {})

    def test_computed_function_exception(self):
        c = Computed(lambda ctx: 1 / 0)
        with self.assertRaisesRegex(ValidationError,
                                    "Error computing Computed field value: division by zero"):
            c._parse_stream(BytesIO(b''), {})

    def test_computed_function_no_context(self):
        c = Computed(lambda ctx: ctx.get('x', 0) + 1)
        self.assertEqual(c._parse_stream(BytesIO(b''), {'x': 2}), 3)
        self.assertEqual(c._parse_stream(BytesIO(b''), {}), 1)


class TestBitFields(unittest.TestCase):

    def setUp(self):
        """Setup method to create common BitFields instances."""
        self.basic_bitfields = BitFields('version:4, header_length:4')
        self.spanning_bitfields = BitFields('foo:12,bar:5')
        self.padded_bitfields = BitFields('padding:7, flag:1')

    def test_basic_build_parse(self):
        self.assertEqual(self.basic_bitfields.build({'version': 4, 'header_length': 0}), b'@')
        self.assertEqual(self.basic_bitfields.parse(b'\x00'), {'version': 0, 'header_length': 0})
        self.assertEqual(self.basic_bitfields.sizeof(), 1)

    def test_spanning_bytes_build_parse(self):
        self.assertEqual(self.spanning_bitfields.sizeof(), 3)
        self.assertEqual(self.spanning_bitfields.build({'foo': 4095, 'bar': 31}), b'\xff\xff\x80')
        self.assertEqual(self.spanning_bitfields.parse(b'\x09\x11\x00'), {'foo': 145, 'bar': 2})

    def test_padding_build_parse(self):
        self.assertEqual(self.padded_bitfields.parse(b'\x01'), {'padding': 0, 'flag': 1})
        self.assertEqual(self.padded_bitfields.build({'flag': 0}), b'\x00')

    def test_building_error(self):
        with self.assertRaises(BuildingError):
            self.padded_bitfields.build({'flag': 10})

    def test_negative_length(self):
        with self.assertRaises(ValueError):
            BitFields('foo:-5')

    def test_embedded_in_struct(self):
        class Entry(Struct):
            header = BitFields('foo:2,bar:2,length:4', embedded=True)
            payload = Contextual(Bytes, lambda ctx: ctx['length'])

        entry = Entry()
        self.assertEqual(entry.build({'foo': 2, 'bar': 0, 'length': 3, 'payload': b'baz'}), b'\x83baz')
        self.assertEqual(entry.parse(b'\x33xxx'), {'foo': 0, 'bar': 3, 'length': 3, 'payload': b'xxx'})


class TestConst(unittest.TestCase):
    def test_basic_bool(self):
        c = Const(Flag(), True)
        self.assertEqual(c.build(True), b'\x01')
        self.assertEqual(c.build(None), b'\x01')
        with self.assertRaisesRegex(BuildingError, "provided value must be None or True, got False"):
            c.build(False)
        self.assertEqual(c.parse(b'\x01'), True)
        with self.assertRaisesRegex(ParsingError, "parsed value must be True, got False"):
            c.parse(b'\x00')

    def test_basic_bytes(self):
        c = Const(b'SIGNATURE')
        self.assertEqual(c.build(None), b'SIGNATURE')
        self.assertEqual(c.parse(b'SIGNATURE'), b'SIGNATURE')
        self.assertEqual(repr(c), "Const(Bytes(9), value=b'SIGNATURE')")

    def test_custom_construct(self):
        c = Const(Bytes(4), b'test')
        self.assertEqual(c.build(None), b'test')
        self.assertEqual(c.parse(b'test'), b'test')
        with self.assertRaises(BuildingError):
            c.build(b'fail')
        with self.assertRaises(ParsingError):
            c.parse(b'fail')
        self.assertEqual(c.sizeof(), 4)

    def test_none_value(self):
        c = Const(Bytes(0), b'')
        self.assertEqual(c.build(None), b'')
        self.assertEqual(c.parse(b''), b'')
        self.assertEqual(c.sizeof(), 0)


class TestRaise(unittest.TestCase):
    def test_raise_building(self):
        r = Raise("A building error occurred")
        stream = BytesIO()
        with self.assertRaisesRegex(BuildingError, "A building error occurred"):
            r._build_stream(None, stream, None)

    def test_raise_parsing(self):
        r = Raise("A parsing error occurred")
        stream = BytesIO(b"some data")
        with self.assertRaisesRegex(ParsingError, "A parsing error occurred"):
            r._parse_stream(stream, None)

    def test_raise_sizeof(self):
        r = Raise("A sizeof error occurred")
        with self.assertRaisesRegex(SizeofError, "A sizeof error occurred"):
            r._sizeof(None)

    def test_repr(self):
        r = Raise("A test message")
        self.assertEqual(repr(r), "Raise(message='A test message')")


class TestIf(unittest.TestCase):
    def test_initialization(self):
        i = If(lambda ctx: ctx['flag'], Const(b'True'), Const(b'False'))
        self.assertIsNotNone(i.predicate)
        self.assertIsNotNone(i.then_construct)
        self.assertIsNotNone(i.else_construct)
        i = If(lambda ctx: ctx['flag'], Const(b'True'))
        self.assertIsNotNone(i.predicate)
        self.assertIsNotNone(i.then_construct)
        self.assertIsInstance(i.else_construct, Pass)

    def test_build_stream(self):
        i = If(lambda ctx: ctx['flag'], Const(b'True'), Const(b'False'))
        stream = BytesIO()
        i._build_stream(None, stream, {'flag': True})
        self.assertEqual(stream.getvalue(), b'True')

        stream = BytesIO()
        i._build_stream(None, stream, {'flag': False})
        self.assertEqual(stream.getvalue(), b'False')

    def test_parse_stream(self):
        i = If(lambda ctx: ctx['flag'], Const(b'True'), Const(b'False'))
        stream = BytesIO(b'True')
        parsed = i._parse_stream(stream, {'flag': True})
        self.assertEqual(parsed, b'True')

        stream = BytesIO(b'False')
        parsed = i._parse_stream(stream, {'flag': False})
        self.assertEqual(parsed, b'False')

    def test_sizeof(self):
        i = If(lambda ctx: ctx['flag'], Const(b'True'), Const(b'False'))
        self.assertEqual(i._sizeof({'flag': True}), 4)
        self.assertEqual(i._sizeof({'flag': False}), 5)

        i = If(lambda ctx: ctx['flag'], Const(b'True'))
        self.assertEqual(i._sizeof({'flag': True}), 4)
        self.assertEqual(i._sizeof({'flag': False}), 0)

    def test_repr(self):
        i = If(lambda ctx: ctx['flag'], Const(b'True'), Const(b'False'))
        self.assertRegex(
            repr(i),
            r"If\(<function TestIf.test_repr.<locals>.<lambda> at 0x[0-9a-fA-F]+>, then_construct=Const\(Bytes\(\d+\), value=b'True'\), else_construct=Const\(Bytes\(\d+\), value=b'False'\)\)",
        )

        i = If(lambda ctx: ctx['flag'], Const(b'True'))
        self.assertRegex(
            repr(i),
            r"If\(<function TestIf.test_repr.<locals>.<lambda> at 0x[0-9a-fA-F]+>, Const\(Bytes\(\d+\), value=b'True'\)\)",
        )

        i = If(lambda ctx: ctx['flag'], Const(b'True'))
        self.assertRegex(
            repr(i),
            r"If\(<function TestIf.test_repr.<locals>.<lambda> at 0x[0-9a-fA-F]+>, Const\(Bytes\(\d+\), value=b'True'\)\)",
        )


class TestSwitch(unittest.TestCase):
    def test_initialization(self):
        s = Switch(lambda ctx: ctx['foo'], cases={1: Integer(1), 2: Bytes(3)})
        self.assertIsNotNone(s.key)
        self.assertIsNotNone(s.cases)
        self.assertIsInstance(s.default, Raise)

        s = Switch(lambda ctx: None, cases={}, default=Pass())
        self.assertIsNotNone(s.key)
        self.assertIsNotNone(s.cases)
        self.assertIsInstance(s.default, Pass)

    def test_build_stream(self):
        s = Switch(lambda ctx: ctx['foo'], cases={1: Integer(1), 2: Bytes(3)})
        stream = BytesIO()
        s._build_stream(5, stream, context={'foo': 1})
        self.assertEqual(stream.getvalue(), b'\x05')

        stream = BytesIO()
        s._build_stream(b'bar', stream, context={'foo': 2})
        self.assertEqual(stream.getvalue(), b'bar')

        with self.assertRaisesRegex(BuildingError, "no default case specified"):
            s._build_stream(b'baz', BytesIO(), context={'foo': 3})

        s = Switch(lambda ctx: None, cases={}, default=Pass())
        stream = BytesIO()
        s._build_stream(None, stream, None)
        self.assertEqual(stream.getvalue(), b'')

    def test_parse_stream(self):
        s = Switch(lambda ctx: ctx['foo'], cases={1: Integer(1), 2: Bytes(3)})
        stream = BytesIO(b'\x05')
        parsed_data = s._parse_stream(stream, context={'foo': 1})
        self.assertEqual(parsed_data, 5)

        stream = BytesIO(b'baz')
        parsed_data = s._parse_stream(stream, context={'foo': 2})
        self.assertEqual(parsed_data, b'baz')

        with self.assertRaisesRegex(ParsingError, "no default case specified"):
            s._parse_stream(BytesIO(b'baz'), context={'foo': 3})

        s = Switch(lambda ctx: None, cases={}, default=Pass())
        parsed_data = s._parse_stream(BytesIO(b''), None)
        self.assertIsNone(parsed_data)

    def test_sizeof(self):
        s = Switch(lambda ctx: ctx['foo'], cases={1: Integer(1), 2: Bytes(3)})
        self.assertEqual(s._sizeof(context={'foo': 1}), 1)
        self.assertEqual(s._sizeof(context={'foo': 2}), 3)

        with self.assertRaisesRegex(SizeofError, "no default case specified"):
            s._sizeof(context={'foo': 3})

        s = Switch(lambda ctx: None, cases={}, default=Pass())
        self.assertEqual(s._sizeof(None), 0)

    def test_repr(self):
        s = Switch(lambda ctx: ctx['foo'], cases={1: Integer(1), 2: Bytes(3)})
        self.assertRegex(repr(s),
                         r"Switch\(<function TestSwitch.test_repr.<locals>.<lambda> at 0x[0-9a-fA-F]+>, cases={1: Integer\(1, byteorder='big', signed=False\), 2: Bytes\(3\)}\)")

        s = Switch(lambda ctx: None, cases={}, default=Pass())
        self.assertRegex(repr(s),
                         r"Switch\(<function TestSwitch.test_repr.<locals>.<lambda> at 0x[0-9a-fA-F]+>, cases={}, default=Pass\(\)\)")


class TestEnum(unittest.TestCase):
    def test_initialization(self):
        e = Enum(Flag(), cases={'yes': True, 'no': False})
        self.assertIsNotNone(e.construct)
        self.assertIsNotNone(e.cases)
        self.assertIsNotNone(e.build_cases)
        self.assertIsNotNone(e.parse_cases)
        self.assertIsInstance(e.default, Raise)

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'}, default=Pass())
        self.assertIsNotNone(e.construct)
        self.assertIsNotNone(e.cases)
        self.assertIsNotNone(e.build_cases)
        self.assertIsNotNone(e.parse_cases)
        self.assertIsInstance(e.default, Pass)

    def test_build_stream(self):
        e = Enum(Flag(), cases={'yes': True, 'no': False})
        stream = BytesIO()
        built = e._build_stream('yes', stream, None)
        self.assertEqual(stream.getvalue(), b'\x01')
        self.assertEqual(built, 'yes')

        stream = BytesIO()
        built = e._build_stream('no', stream, None)
        self.assertEqual(stream.getvalue(), b'\x00')
        self.assertEqual(built, 'no')

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'})
        with self.assertRaisesRegex(BuildingError, "no default case specified"):
            e._build_stream('z', BytesIO(), None)

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'}, default=Pass())
        stream = BytesIO()
        built = e._build_stream('z', stream, None)
        self.assertEqual(stream.getvalue(), b'')
        self.assertIsNone(built)

    def test_parse_stream(self):
        e = Enum(Flag(), cases={'yes': True, 'no': False})
        stream = BytesIO(b'\x00')
        parsed = e._parse_stream(stream, None)
        self.assertEqual(parsed, 'no')

        stream = BytesIO(b'\x01')
        parsed = e._parse_stream(stream, None)
        self.assertEqual(parsed, 'yes')

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'})
        with self.assertRaisesRegex(ParsingError, "no default case specified"):
            e._parse_stream(BytesIO(b'zzz'), None)

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'}, default=Pass())
        stream = BytesIO(b'z')
        parsed = e._parse_stream(stream, None)
        self.assertIsNone(parsed)

    def test_sizeof(self):
        e = Enum(Flag(), cases={'yes': True, 'no': False})
        self.assertEqual(e._sizeof(None), 1)

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'})
        self.assertEqual(e._sizeof(None), 3)

    def test_repr(self):
        e = Enum(Flag(), cases={'yes': True, 'no': False})
        self.assertEqual(repr(e), "Enum(Flag(), cases={'yes': True, 'no': False})")

        e = Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'}, default=Pass())
        self.assertEqual(repr(e), "Enum(Bytes(3), cases={'x': b'xxx', 'y': b'yyy'}, default=Pass())")

    def test_enum_in_struct(self):
        class Entry(Struct):
            foo = Enum(Flag(), cases={'yes': True, 'no': False})
            bar = Computed(lambda ctx: print('In context:', ctx['foo']))

        captured_output = StringIO()

        with contextlib.redirect_stdout(captured_output):
            stream = BytesIO()
            Entry()._build_stream(Context({'foo': True}), stream, Context())
        self.assertEqual(stream.getvalue(), b'\x01')
        self.assertEqual(captured_output.getvalue().strip(), 'In context: yes')

        captured_output = StringIO()
        with contextlib.redirect_stdout(captured_output):
            stream = BytesIO()
            Entry()._build_stream(Context({'foo': False}), stream, Context())
        self.assertEqual(stream.getvalue(), b'\x00')
        self.assertEqual(captured_output.getvalue().strip(), 'In context: no')

        captured_output = StringIO()
        with contextlib.redirect_stdout(captured_output):
            stream = BytesIO(b'\x01')
            parsed_stream = Entry()._parse_stream(stream, Context())
        self.assertEqual(parsed_stream, {'foo': 'yes', 'bar': None})
        self.assertEqual(captured_output.getvalue().strip(), 'In context: yes')

        captured_output = StringIO()
        with contextlib.redirect_stdout(captured_output):
            stream = BytesIO(b'\x00')
            parsed_stream = Entry()._parse_stream(stream, Context())
        self.assertEqual(parsed_stream, {'foo': 'no', 'bar': None})
        self.assertEqual(captured_output.getvalue().strip(), 'In context: no')


class TestOffset(unittest.TestCase):
    def test_initialization(self):
        offset = Offset(Bytes(1), 4)
        self.assertEqual(offset.offset, 4)
        with self.assertRaises(ValueError):
            Offset(Bytes(1), -2)

    def test_build_stream(self):
        offset = Offset(Bytes(1), 4)
        stream = BytesIO()
        built = offset._build_stream(b"Z", stream, None)
        self.assertEqual(stream.getvalue(), b"\x00\x00\x00\x00Z")
        self.assertEqual(built, b"Z")

    def test_parse_stream(self):
        offset = Offset(Bytes(1), 4)
        stream = BytesIO(b"abcdef")
        parsed = offset._parse_stream(stream, None)
        self.assertEqual(parsed, b"e")

    def test_sizeof(self):
        offset = Offset(Bytes(1), 4)
        self.assertEqual(offset._sizeof(None), 1)

    def test_repr(self):
        offset = Offset(Bytes(1), 4)
        self.assertEqual(repr(offset), "Offset(Bytes(1), offset=4)")


class TestTell(unittest.TestCase):
    def test_tell_initialization(self):
        t = Tell()
        # Since Tell doesn't have initialization logic, we just check that it exists.
        self.assertIsInstance(t, Tell)

    def test_tell_build_stream(self):
        t = Tell()
        stream = BytesIO()
        self.assertEqual(t._build_stream(None, stream, None), 0)
        stream.write(b'test')
        self.assertEqual(t._build_stream(None, stream, None), 4)

    def test_tell_parse_stream(self):
        t = Tell()
        stream = BytesIO(b'foobar')
        stream.seek(3)
        self.assertEqual(t._parse_stream(stream, None), 3)

    def test_tell_sizeof(self):
        t = Tell()
        self.assertEqual(t._sizeof(None), 0)

    def test_tell_repr(self):
        t = Tell()
        self.assertEqual(repr(t), 'Tell()')

    def test_tell_example_struct(self):
        class Example(Struct):
            key = Bytes(3)
            pos1 = Tell()
            value = Bytes(3)
            pos2 = Tell()

        example = Example()
        self.assertEqual(example.parse(b'foobar'), {
            'key': b'foo', 'pos1': 3, 'value': b'bar', 'pos2': 6
        })

        example = Example()
        self.assertEqual(example.parse(b'foobar'), {
            'key': b'foo', 'pos1': 3, 'value': b'bar', 'pos2': 6
        })


class TestChecksum(unittest.TestCase):

    def test_initialization(self):
        data_func = lambda ctx: ctx['data']
        checksum = Checksum(Bytes(32), hashlib.sha256, data_func)
        self.assertEqual(checksum.hash_func, hashlib.sha256)
        self.assertEqual(checksum.data_func, data_func)

    def test_build_stream(self):
        data_func = lambda ctx: ctx['data']
        checksum = Checksum(Bytes(32), hashlib.sha256, data_func)
        stream = BytesIO()
        context = {'data': b'foo'}
        result = checksum._build_stream(None, stream, context)
        expected_digest = hashlib.sha256(b'foo').digest()
        self.assertEqual(result, expected_digest)
        self.assertEqual(stream.getvalue(), expected_digest)

        stream = BytesIO()
        context = {'data': b'bar'}
        custom_digest = hashlib.sha256(b"bar").digest()
        result = checksum._build_stream(custom_digest, stream, context)
        self.assertEqual(result, custom_digest)
        self.assertEqual(stream.getvalue(), custom_digest)

        stream = BytesIO()
        context = {'data': b'test'}
        expected_digest = hashlib.sha256(b'test').digest()
        with self.assertRaisesRegex(BuildingError,
                                    fr"wrong checksum, provided b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' but expected {hexlify(expected_digest)!r}"):
            checksum._build_stream(bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
                                   stream, context)

    def test_parse_stream(self):
        data_func = lambda ctx: ctx['data']
        checksum = Checksum(Bytes(32), hashlib.sha256, data_func)
        context = {'data': b'foo'}
        digest = hashlib.sha256(b'foo').digest()
        stream = BytesIO(digest)
        result = checksum._parse_stream(stream, context)
        self.assertEqual(result, digest)

        context = {'data': b'bar'}
        digest = hashlib.sha256(b'bar').digest()
        stream = BytesIO(digest)
        result = checksum._parse_stream(stream, context)
        self.assertEqual(result, digest)

        context = {'data': b'test'}
        wrong_digest = hashlib.sha256(b"wrong").digest()
        expected_digest = hashlib.sha256(b"test").digest()
        stream = BytesIO(wrong_digest)

        with self.assertRaisesRegex(ParsingError,
                                    fr"wrong checksum, parsed {hexlify(wrong_digest)!r} but expected {hexlify(expected_digest)!r}"):
            checksum._parse_stream(stream, context)

    def test_sizeof(self):
        data_func = lambda ctx: ctx['data']
        checksum = Checksum(Bytes(32), hashlib.sha256, data_func)
        self.assertEqual(checksum._sizeof(None), 32)

    def test_repr(self):
        data_func = lambda ctx: ctx['data']
        checksum = Checksum(Bytes(32), hashlib.sha256, data_func)
        self.assertRegex(repr(checksum),
                         f"Checksum\(Bytes\(32\), hash_func={repr(hashlib.sha256)}, data_func=<function TestChecksum.test_repr.<locals>.<lambda> at 0x[0-9a-fA-F]+>\)")


class TestVarint(unittest.TestCase):
    def test_initialization(self):
        varint = Varint()
        self.assertIsInstance(varint, Varint)

    def test_build_stream(self):
        varint = Varint()
        stream = BytesIO()
        varint._build_stream(0, stream, None)
        self.assertEqual(stream.getvalue(), b'\x00')

        stream = BytesIO()
        varint._build_stream(127, stream, None)
        self.assertEqual(stream.getvalue(), b'\x7f')

        stream = BytesIO()
        varint._build_stream(128, stream, None)
        self.assertEqual(stream.getvalue(), b'\x80\x01')

        stream = BytesIO()
        varint._build_stream(300, stream, None)
        self.assertEqual(stream.getvalue(), b'\xac\x02')

        stream = BytesIO()
        varint._build_stream(16383, stream, None)
        self.assertEqual(stream.getvalue(), b'\xff\x7f')

        stream = BytesIO()
        varint._build_stream(16384, stream, None)
        self.assertEqual(stream.getvalue(), b'\x80\x80\x01')

        stream = BytesIO()
        varint._build_stream(1024, stream, None)
        self.assertEqual(stream.getvalue(), b'\x80\x08')

    def test_parse_stream(self):
        varint = Varint()
        stream = BytesIO(b'\x00')
        self.assertEqual(varint._parse_stream(stream, None), 0)

        stream = BytesIO(b'\x7f')
        self.assertEqual(varint._parse_stream(stream, None), 127)

        stream = BytesIO(b'\x80\x01')
        self.assertEqual(varint._parse_stream(stream, None), 128)

        stream = BytesIO(b'\xac\x02')
        self.assertEqual(varint._parse_stream(stream, None), 300)

        stream = BytesIO(b'\xff\x7f')
        self.assertEqual(varint._parse_stream(stream, None), 16383)

        stream = BytesIO(b'\x80\x80\x01')
        self.assertEqual(varint._parse_stream(stream, None), 16384)

        stream = BytesIO(b'\x80\x08')
        self.assertEqual(varint._parse_stream(stream, None), 1024)

        with self.assertRaisesRegex(ParsingError, "Unexpected EOF while reading bytes"):
            varint._parse_stream(BytesIO(b''), None)

    def test_sizeof(self):
        varint = Varint()
        with self.assertRaisesRegex(NotImplementedError, "Varint has no fixed size"):
            varint._sizeof(None)

    def test_repr(self):
        varint = Varint()
        self.assertEqual(repr(varint), "Varint()")


if __name__ == '__main__':
    unittest.main()
