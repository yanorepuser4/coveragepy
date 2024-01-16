# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""Run sys.monitoring on a file of Python code."""

import functools
import sys

from types import CodeType, FrameType

from coverage.debug import short_filename, short_stack

print(sys.version)
the_program = sys.argv[1]

code = open(the_program).read()

my_id = sys.monitoring.COVERAGE_ID
sys.monitoring.use_tool_id(my_id, "run_sysmon.py")
register = functools.partial(sys.monitoring.register_callback, my_id)
events = sys.monitoring.events


def bytes_to_lines(code):
    """Make a dict mapping byte code offsets to line numbers."""
    b2l = {}
    cur_line = 0
    for bstart, bend, lineno in code.co_lines():
        for boffset in range(bstart, bend, 2):
            b2l[boffset] = lineno
    return b2l


def arg_repr(arg):
    """Make a customized repr for logged values."""
    if isinstance(arg, CodeType):
        return (
            f"<code @{id(arg):#x}"
            + f" name={arg.co_name},"
            + f" file={short_filename(arg.co_filename)!r}#{arg.co_firstlineno}>"
        )
    return repr(arg)


def handler(*names):
    def _decorator(func):
        @functools.wraps(func)
        def _wrapped(*args):
            args_reprs = []
            code = None
            for name, arg in zip(names, args):
                if name:
                    if name == "code":
                        code = arg
                    args_reprs.append(f"{name}={arg_repr(arg)}")
                    if name.endswith("@") and code is not None:
                        line = bytes_to_lines(code)[arg]
                        args_reprs[-1] += f"#{line}"
            name = func.__name__.removeprefix("sysmon_")
            print(f"{name}({', '.join(args_reprs)})")
            return func(*args)
        return _wrapped
    return _decorator


@handler("code", "@")
def sysmon_py_start(code, instruction_offset):
    sys.monitoring.set_local_events(
        my_id,
        code,
        events.PY_RETURN | events.PY_RESUME | events.LINE | events.BRANCH | events.JUMP,
    )


@handler("code", "@")
def sysmon_py_resume(code, instruction_offset):
    ...

@handler("code", "@", None)
def sysmon_py_return(code, instruction_offset, retval):
    return sys.monitoring.DISABLE


@handler("code", "#")
def sysmon_line(code, line_number):
    return sys.monitoring.DISABLE


@handler("code", "src@", "dst@")
def sysmon_branch(code, instruction_offset, destination_offset):
    ... #return sys.monitoring.DISABLE


@handler("code", "src@", "dst@")
def sysmon_jump(code, instruction_offset, destination_offset):
    return sys.monitoring.DISABLE


sys.monitoring.set_events(
    my_id,
    events.PY_START | events.PY_UNWIND,
)
register(events.PY_START, sysmon_py_start)
register(events.PY_RESUME, sysmon_py_resume)
register(events.PY_RETURN, sysmon_py_return)
# register(events.PY_UNWIND, sysmon_py_unwind_arcs)
register(events.LINE, sysmon_line)
register(events.BRANCH, sysmon_branch)
register(events.JUMP, sysmon_jump)

exec(code)
