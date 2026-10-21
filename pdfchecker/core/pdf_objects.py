"""Read serialized PDF objects without confusing string content with PDF names."""
import re

from .utils import XrefObjectCache, build_xref_object_cache


class Name(str):
    pass


class Ref(int):
    pass


class PDFString(bytes):
    def text(self, stream=False):
        if self.startswith((b'\xfe\xff', b'\xff\xfe')):
            return self.decode('utf-16', errors='replace')
        if self.startswith(b'\xef\xbb\xbf'):
            return self.decode('utf-8-sig', errors='replace')
        if stream:
            try:
                return self.decode('utf-8')
            except UnicodeDecodeError:
                pass
        # PDFDocEncoding differs from Latin-1 in these positions.
        special = dict(enumerate('˘ˇˆ˙˝˛˚˜', 0x18))
        special.update(enumerate('•†‡…—–ƒ⁄‹›−‰„“”‘’‚™ﬁﬂŁŒŠŸŽıłœšž', 0x80))
        special[0xa0] = '€'
        return ''.join(special.get(byte, chr(byte)) for byte in self)


_TOKEN = re.compile(r'\s+|%[^\r\n]*|<<|>>|[\[\]()]|/[^\s<>\[\]()/%]*|[^\s<>\[\]()/%]+')
_NAME_ESCAPE = re.compile(r'#([0-9A-Fa-f]{2})')


def decode_name(text):
    """Expand the #xx escapes of a PDF name given without its leading slash."""
    return _NAME_ESCAPE.sub(lambda match: chr(int(match[1], 16)), text)


def parse_object(text):
    position = 0

    def skip():
        nonlocal position
        while position < len(text):
            if text[position].isspace():
                position += 1
            elif text[position] == '%':
                while position < len(text) and text[position] not in '\r\n':
                    position += 1
            else:
                break

    def read(depth=0):
        nonlocal position
        if depth > 100:
            raise ValueError('PDF object nesting limit exceeded')
        skip()
        if position >= len(text):
            raise ValueError('Incomplete PDF object')
        if text.startswith('<<', position):
            position += 2
            result = {}
            while True:
                skip()
                if text.startswith('>>', position):
                    position += 2
                    return result
                key = read(depth + 1)
                if not isinstance(key, Name):
                    raise ValueError('Invalid PDF dictionary key')
                result[str(key)] = read(depth + 1)
        if text[position] == '[':
            position += 1
            result = []
            while True:
                skip()
                if position < len(text) and text[position] == ']':
                    position += 1
                    return result
                result.append(read(depth + 1))
        if text[position] == '(':
            position += 1
            data = bytearray()
            nesting = 1
            while position < len(text):
                char = text[position]
                position += 1
                if char == '\\':
                    if position >= len(text):
                        break
                    char = text[position]
                    position += 1
                    if char in '\r\n':
                        if char == '\r' and text[position:position+1] == '\n':
                            position += 1
                        continue
                    if char in '01234567':
                        digits = char
                        while len(digits) < 3 and text[position:position+1] and text[position] in '01234567':
                            digits += text[position]
                            position += 1
                        data.append(int(digits, 8) & 255)
                        continue
                    char = {'n':'\n', 'r':'\r', 't':'\t', 'b':'\b', 'f':'\f'}.get(char, char)
                elif char == '(':
                    nesting += 1
                elif char == ')':
                    nesting -= 1
                    if not nesting:
                        return PDFString(data)
                data.extend(char.encode('latin-1') if ord(char) <= 255 else char.encode('utf-8'))
            raise ValueError('Unterminated PDF string')
        if text[position] == '<':
            end = text.find('>', position)
            if end < 0:
                raise ValueError('Unterminated PDF hex string')
            value = ''.join(text[position+1:end].split())
            position = end + 1
            return PDFString(bytes.fromhex(value + ('0' if len(value) % 2 else '')))
        match = _TOKEN.match(text, position)
        if not match:
            raise ValueError('Invalid PDF token')
        token = match.group()
        position = match.end()
        if token.startswith('/'):
            return Name(decode_name(token[1:]))
        if re.fullmatch(r'\d+', token):
            reference = re.match(r'\s+\d+\s+R\b', text[position:])
            if reference:
                position += reference.end()
                return Ref(token)
        return token

    return read()


def object_map(doc, cache=None):
    """Parse every object of the document. The result (or the parse failure)
    is kept in an XrefObjectCache, so analyzers sharing one parse it once."""
    if cache is None:
        cache = build_xref_object_cache(doc)
    parsed = getattr(cache, 'objects', None)
    if parsed is None:
        try:
            parsed = _parse_objects(cache)
        except Exception as exc:
            parsed = exc
        if isinstance(cache, XrefObjectCache):
            cache.objects = parsed
    if isinstance(parsed, Exception):
        raise parsed
    return parsed


def _parse_objects(cache):
    objects = {}
    for xref, (text, error) in cache.items():
        if error:
            raise ValueError(f'XRef {xref}: {error}')
        objects[xref] = parse_object(text) if text else None
    return objects


def walk(value):
    """Walk direct children only; references are resolved explicitly by callers."""
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def open_action_nodes(doc, objects):
    catalog = objects.get(doc.pdf_catalog(), {})
    pending = [catalog.get('OpenAction')] if isinstance(catalog, dict) else []
    visited = set()
    nodes = set()
    while pending:
        value = pending.pop()
        if isinstance(value, Ref):
            if value in visited:
                continue
            visited.add(value)
            pending.append(objects.get(value))
        elif isinstance(value, dict):
            nodes.add(id(value))
            if 'Next' in value:
                pending.append(value['Next'])
        elif isinstance(value, list):
            pending.extend(value)
    return nodes


def script_text(doc, objects, value):
    """Text of a /JS entry, which may be a string or a (possibly indirect)
    string or stream; None when it cannot be read."""
    visited = set()
    while isinstance(value, Ref) and value not in visited:
        visited.add(value)
        if doc.xref_is_stream(value):
            return PDFString(doc.xref_stream(value)).text(stream=True)
        value = objects.get(value)
    return value.text() if isinstance(value, PDFString) else None


def javascript_entries(doc, objects):
    """Yield (xref, action dictionary, runs automatically, script) for every
    /JS entry, where xref is the object that contains the dictionary."""
    auto = open_action_nodes(doc, objects)
    for xref, obj in objects.items():
        for node in walk(obj):
            if not isinstance(node, dict) or 'JS' not in node:
                continue
            text = script_text(doc, objects, node['JS'])
            if text is None:
                raise ValueError(f'Unable to read JavaScript at XRef {xref}')
            yield xref, node, id(node) in auto, text


def resolve(value, objects):
    visited = set()
    while isinstance(value, Ref) and value not in visited:
        visited.add(value)
        value = objects.get(value)
    return value


def filespec_streams(spec, objects):
    spec = resolve(spec, objects)
    if not isinstance(spec, dict):
        return set()
    ef = resolve(spec.get('EF'), objects)
    return {int(value) for value in ef.values() if isinstance(value, Ref)} if isinstance(ef, dict) else set()


def listed_attachment_streams(doc, objects):
    catalog = objects.get(doc.pdf_catalog(), {})
    names = resolve(catalog.get('Names'), objects)
    pending = [names.get('EmbeddedFiles')] if isinstance(names, dict) else []
    visited = set()
    streams = set()
    while pending:
        tree = resolve(pending.pop(), objects)
        if not isinstance(tree, dict) or id(tree) in visited:
            continue
        visited.add(id(tree))
        entries = resolve(tree.get('Names'), objects)
        if isinstance(entries, list):
            for spec in entries[1::2]:
                streams.update(filespec_streams(spec, objects))
        kids = resolve(tree.get('Kids'), objects)
        if isinstance(kids, list):
            pending.extend(kids)
    for page in doc:
        annotations = resolve(objects.get(page.xref, {}).get('Annots'), objects)
        if isinstance(annotations, list):
            for annotation in annotations:
                annotation = resolve(annotation, objects)
                if isinstance(annotation, dict) and annotation.get('Subtype') == Name('FileAttachment'):
                    streams.update(filespec_streams(annotation.get('FS'), objects))
    return streams
