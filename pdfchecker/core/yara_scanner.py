"""Optional local YARA matching with one compiled rule bundle per invocation."""
import io
import math
import time
from pathlib import Path

MAX_TARGET_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_TARGETS = 1000
TIME_BUDGET = 30


def compile_rules(paths):
    try:
        import yara
    except ImportError:
        raise ValueError("YARA support is not installed: pip install 'pdfchecker[yara]'") from None
    rules = yara.compile(filepaths={f'rules{i+1}': str(Path(path).resolve()) for i, path in enumerate(paths)})
    output = io.BytesIO()
    rules.save(file=output)
    return output.getvalue()


def scan_yara(path, analysis, compiled):
    import yara
    rules = yara.load(file=io.BytesIO(compiled))
    result = {'matches': [], 'errors': [], 'limits': [], 'targets_scanned': 0}
    deadline = time.monotonic() + TIME_BUDGET
    total_bytes = 0

    def targets():
        # The original encrypted file is scanned as stored; recovered content
        # below is decrypted in memory by MuPDF.
        yield 'pdf', str(path), None
        for source in (analysis.javascript or {}).get('javascript_sources', []):
            yield 'javascript', source['location'], source.get('full_content', '').encode('utf-8')
        for source in (analysis.embedded or {}).get('embedded_files', []):
            yield 'attachment', source['filename'], source.get('data')
        for source in (analysis.embedded or {}).get('hidden_streams', []):
            yield 'hidden-stream', f"XRef {source['xref']}", source.get('data')

    for kind, location, data in targets():
        if result['targets_scanned'] >= MAX_TARGETS or time.monotonic() >= deadline:
            result['limits'].append('YARA target count or total time limit reached')
            break
        size = Path(path).stat().st_size if kind == 'pdf' else len(data or b'')
        if size > MAX_TARGET_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
            result['limits'].append(f'{kind} {location}: YARA byte limit reached')
            continue
        if data is None and kind != 'pdf':
            result['errors'].append(f'{kind} {location}: content unavailable')
            continue
        total_bytes += size
        options = {'filepath': str(path)} if kind == 'pdf' else {'data': data}
        try:
            warnings = []
            matches = rules.match(**options, timeout=max(1, math.ceil(deadline-time.monotonic())),
                                  console_callback=lambda message: None,
                                  warnings_callback=lambda *args: warnings.append('YARA match limit reached') or yara.CALLBACK_CONTINUE)
            result['limits'].extend(warnings)
            result['targets_scanned'] += 1
            for match in matches:
                result['matches'].append({'rule': match.rule, 'namespace': match.namespace,
                                          'tags': list(match.tags), 'source': kind, 'location': location})
        except yara.TimeoutError:
            result['limits'].append(f'{kind} {location}: YARA timed out')
            break
        except yara.Error as exc:
            result['errors'].append(f'{kind} {location}: {exc}')
    return result
