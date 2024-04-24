from distutils.util import strtobool

import copy
import jinja2

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
j2env.filters['json_query'] = lambda x, query: jmespath.search(query, x)

def jinja2process(template, omit=None, template_style='jinja2', variables={}):
    variables = copy.copy(variables)
    j2template = j2env.from_string(template)
    template_out = j2template.render(variables)
    return template_out
