"""Bounded, credential-free extraction. All storage is supplied by the runtime."""
import base64
import hashlib
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

VERSION = 'c-extractor-1'


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode('utf-8')).hexdigest()


class Limit(Exception):
    pass


class HTMLViews(HTMLParser):
    # Raw HTML remains a view: attributes, comments and unsupported CSS cannot disappear.
    def __init__(self, raw):
        super().__init__(convert_charrefs=False)
        self.raw = raw
        self.stack = []
        self.parts = {'visible': [], 'hidden': []}
        self.lengths = {'visible': 0, 'hidden': 0}
        self.maps = {'visible': [], 'hidden': []}
        self.offsets = [0]
        self.offsets.extend(match.end() for match in re.finditer('\n', raw))
        self.malformed = False

    def position(self):
        row, col = self.getpos()
        return self.offsets[row - 1] + col

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        style = re.sub(r'\s', '', attrs.get('style') or '').lower()
        hidden = (tag in {'script', 'style', 'template', 'head'} or 'hidden' in attrs
                  or attrs.get('aria-hidden') == 'true' or 'display:none' in style
                  or 'visibility:hidden' in style or 'opacity:0' in style)
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.stack.append((tag, hidden))

    def handle_startendtag(self, tag, attrs):
        before = len(self.stack)
        self.handle_starttag(tag, attrs)
        del self.stack[before:]

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()
        else:
            self.malformed = True

    def append(self, value, length):
        key = 'hidden' if any(h for _, h in self.stack) else 'visible'
        start = self.lengths[key]
        self.lengths[key] += len(value)
        self.parts[key].append(value)
        self.maps[key].append({'span': [start, start + len(value)],
                               'source_span': [self.position(), self.position() + length]})

    def handle_data(self, data):
        self.append(data, len(data))

    def handle_entityref(self, name):
        import html
        token = '&' + name
        if self.raw[self.position() + len(token):].startswith(';'):
            token += ';'
        self.append(html.unescape(token), len(token))

    def handle_charref(self, name):
        import html
        token = '&#' + name
        if self.raw[self.position() + len(token):].startswith(';'):
            token += ';'
        self.append(html.unescape(token), len(token))


def extract(assignment, restricted_io):
    """read_resource(id)->bytes; write_artifact(mapping)->opaque evidence ID.

    Per-resource media_type and original_hash originate with A, never source text.
    Source maps point to exact parent views; raw views map codepoints to byte spans.
    """
    result = {'contract_version': 'v1', 'extractor_version': VERSION,
              'extraction_status': 'COMPLETE', 'resources': [], 'reason_codes': []}
    try:
        limits = assignment['limits']
        max_bytes = min(limits['max_bytes'], 2_000_000)
        max_chars = min(limits['max_chars'], 500_000)
        max_views = min(limits['max_views'], 128)
        max_parts = min(limits['max_parts'], 128)
        depth = min(limits['max_decode_depth'], 3)
        if any(type(x) is not int or x < 0 for x in (max_bytes, max_chars, max_views, max_parts, depth)):
            raise ValueError('limits')
        if not isinstance(assignment['resources'], list) or not assignment['resources']:
            raise ValueError('resources')
        seen = set()
        total_bytes = total_chars = total_views = 0
        for resource in assignment['resources']:
            if resource['resource_id'] in seen:
                raise ValueError('duplicate resource')
            seen.add(resource['resource_id'])
            raw = restricted_io.read_resource(resource['resource_id'])
            total_bytes += len(raw)
            if total_bytes > max_bytes:
                raise Limit()
            if digest(raw) != resource['original_hash']:
                raise ValueError('hash')
            item = {'resource_id': resource['resource_id'], 'original_hash': digest(raw),
                    'views': [], 'unsupported_parts': []}
            result['resources'].append(item)

            def add(text, kind, parent=None, mapping=None):
                nonlocal total_chars, total_views
                total_chars += len(text)
                total_views += 1
                if total_chars > max_chars or total_views > max_views:
                    raise Limit()
                view = {'view_id': f"{resource['resource_id']}:{len(item['views'])}",
                        'view_hash': digest(text), 'kind': kind, 'text': text,
                        'source_map': mapping or [], 'parent_view_id': parent}
                view['evidence_id'] = restricted_io.write_artifact(view.copy())
                if not isinstance(view['evidence_id'], str) or not view['evidence_id']:
                    raise ValueError('artifact')
                item['views'].append(view)
                return view

            def body(payload, charset, html=False):
                # Strict decoding: invalid bytes are never replaced with reassuring text.
                text = payload.decode(charset or 'utf-8', errors='strict')
                if total_chars + len(text) > max_chars:
                    raise Limit()
                cursor = 0
                mapping = []
                # UTF-8 exact byte provenance; other charsets retain whole-part mapping.
                if (charset or 'utf-8').lower().replace('_', '-') in {'utf-8', 'ascii', 'us-ascii'}:
                    for i, char in enumerate(text):
                        size = len(char.encode(charset or 'utf-8'))
                        mapping.append({'span': [i, i + 1], 'source_span': [cursor, cursor + size]})
                        cursor += size
                else:
                    mapping = [{'span': [0, len(text)], 'source_span': [0, len(payload)]}]
                root = add(text, 'html_raw' if html else 'text', mapping=mapping)
                if html:
                    parser = HTMLViews(text)
                    parser.feed(text)
                    parser.close()
                    if parser.malformed or parser.stack:
                        result['extraction_status'] = 'INCOMPLETE'
                        result['reason_codes'].append('MALFORMED_HTML')
                    for key in ('visible', 'hidden'):
                        add(''.join(parser.parts[key]), 'html_' + key, root['view_id'], parser.maps[key])
                queue = [(view, 0) for view in item['views'] if view['view_id'] == root['view_id'] or view['parent_view_id'] == root['view_id']]
                while queue:
                    view, layer = queue.pop(0)
                    text = view['text']
                    positions = [i for i, c in enumerate(text) if unicodedata.category(c) == 'Cf']
                    if positions:
                        invisible = set(positions)
                        kept = [i for i in range(len(text)) if i not in invisible]
                        normalized = add(''.join(text[i] for i in kept), 'unicode_visible', view['view_id'],
                                         [{'span': [j, j + 1], 'source_span': [i, i + 1]} for j, i in enumerate(kept)])
                        queue.append((normalized, layer))
                        # Retain the original invisible characters in the parent view.
                    for match in re.finditer(r'(?i)base64:([A-Za-z0-9+/=]+)', text):
                        if layer >= depth:
                            result['extraction_status'] = 'INCOMPLETE'
                            result['reason_codes'].append('DECODE_DEPTH')
                            continue
                        decoded = base64.b64decode(match[1], validate=True).decode('utf-8', errors='strict')
                        child = add(decoded, 'decoded_base64', view['view_id'],
                                    [{'span': [0, len(decoded)], 'source_span': list(match.span(1))}])
                        queue.append((child, layer + 1))

            media = resource['media_type']
            if media in {'text/plain', 'text/html'}:
                body(raw, resource.get('charset', 'utf-8'), media == 'text/html')
            elif media == 'message/rfc822':
                message = BytesParser(policy=policy.default).parsebytes(raw)
                # Headers and MIME structure are independently inspectable exact content.
                mime_root = add(raw.decode('ascii', errors='backslashreplace'), 'mime_raw', mapping=[
                    {'span': [0, len(raw.decode('ascii', errors='backslashreplace'))], 'source_span': [0, len(raw)]}])
                for n, part in enumerate(message.walk()):
                    if n >= max_parts:
                        raise Limit()
                    if part.defects:
                        raise ValueError('mime')
                    typ = part.get_content_type()
                    if part.is_multipart():
                        if part.get_content_disposition() == 'attachment' or part.get_filename() or typ == 'message/rfc822':
                            item['unsupported_parts'].append({'part_id': str(n), 'media_type': typ, 'task_relevance': 'UNKNOWN'})
                            result['extraction_status'] = 'INCOMPLETE'
                        continue
                    if part.get_content_disposition() == 'attachment' or part.get_filename() or typ not in {'text/plain', 'text/html'}:
                        item['unsupported_parts'].append({'part_id': str(n), 'media_type': typ, 'task_relevance': 'UNKNOWN'})
                        result['extraction_status'] = 'INCOMPLETE'
                    else:
                        payload = part.get_payload(decode=True)
                        if part.defects or payload is None:
                            raise ValueError('mime')
                        before = len(item['views'])
                        body(payload, part.get_content_charset(), typ == 'text/html')
                        for view in item['views'][before:]:
                            view['part_id'] = str(n)
                            if view['parent_view_id'] is None:
                                view['parent_view_id'] = mime_root['view_id']
                                view['source_map'] = [{'span': [0, len(view['text'])], 'source_span': [0, len(mime_root['text'])]}]
                                view['mapping_precision'] = 'WHOLE_MESSAGE'
                            # Persist finalized provenance, not the preliminary view.
                            view['evidence_id'] = restricted_io.write_artifact(view.copy())
                if not message.is_multipart() and message.get_content_type() not in {'text/plain', 'text/html'}:
                    result['extraction_status'] = 'INCOMPLETE'
            else:
                item['unsupported_parts'].append({'media_type': media, 'task_relevance': 'UNKNOWN'})
                result['extraction_status'] = 'INCOMPLETE'
    except Limit:
        result['extraction_status'] = 'INCOMPLETE'
        result['reason_codes'].append('RESOURCE_LIMIT')
    except Exception:
        result['extraction_status'] = 'ERROR'
        result['reason_codes'].append('EXTRACTION_FAILED')
    return result
