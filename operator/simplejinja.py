import copy
import re
from base64 import b64decode

import jinja2
import jmespath
from str2bool import str2bool

def error_if_undefined(result):
    if isinstance(result, jinja2.Undefined):
        result._fail_with_undefined_error()
    else:
        return result

j2env = jinja2.Environment(
    finalize = error_if_undefined,
    undefined = jinja2.ChainableUndefined,
)
j2env.filters['bool'] = lambda x: bool(str2bool(x)) if isinstance(x, str) else bool(x)
j2env.filters['b64decode'] = lambda x: b64decode(x.encode('utf-8') + b'==').decode('utf-8')
j2env.filters['json_query'] = lambda x, query: jmespath.search(query, x)

j2template_cache = {}

# Adapted from ANsible plugins/filter/core.py
def regex_replace(value='', pattern='', replacement='', ignorecase=False, multiline=False):
    ''' Perform a `re.sub` returning a string '''
    flags = 0
    if ignorecase:
        flags |= re.I
    if multiline:
        flags |= re.M
    _re = re.compile(pattern, flags=flags)
    return _re.sub(replacement, value)

j2env.filters['regex_replace'] = regex_replace

def check_condition(condition, variables=None):
    return str2bool(
        jinja2process("{{("+condition+")|bool}}", variables=variables)
    )

def jinja2process(template, variables=None):
    variables = copy.copy(variables) if variables is not None else {}
    j2template = j2template_cache.get(template)
    if not j2template:
        j2template = j2env.from_string(template)
        j2template_cache[template] = j2template
    template_out = j2template.render(variables)
    return template_out
