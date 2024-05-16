from base64 import b64decode
from distutils.util import strtobool

import copy
import jinja2
import jmespath
import re

def error_if_undefined(result):
    if isinstance(result, jinja2.Undefined):
        result._fail_with_undefined_error()
    else:
        return result

j2env = jinja2.Environment(
    finalize = error_if_undefined,
    undefined = jinja2.ChainableUndefined,
)
j2env.filters['bool'] = lambda x: bool(strtobool(x)) if isinstance(x, str) else bool(x)
j2env.filters['b64decode'] = lambda x: b64decode(x.encode('utf-8') + b'==').decode('utf-8')
j2env.filters['json_query'] = lambda x, query: jmespath.search(query, x)

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

def jinja2process(template, omit=None, template_style='jinja2', variables={}):
    variables = copy.copy(variables)
    j2template = j2env.from_string(template)
    template_out = j2template.render(variables)
    return template_out
