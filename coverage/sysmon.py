# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""Callback functions and support for sys.monitoring data collection."""

from __future__ import annotations

import collections
import functools
import inspect
import itertools
import os
import sys
import traceback

from dataclasses import dataclass
from types import CodeType, FrameType
from typing import (
    Any,
    Callable,
    Set,
    TYPE_CHECKING,
    cast,
)

from coverage.debug import log, short_filename, short_stack
from coverage.types import (
    AnyCallable,
    TArc,
    TFileDisposition,
    TLineNo,
    TTraceData,
    TTraceFileData,
    TracerCore,
    TWarnFn,
)

# pylint: disable=unused-argument

# $set_env.py: COVERAGE_LOG_SYSMON - Trace sys.monitoring calls
LOG = bool(int(os.getenv("COVERAGE_LOG_SYSMON", "0")))

# This module will be imported in all versions of Python, but only used in 3.12+
# It will be type-checked for 3.12, but not for earlier versions.
sys_monitoring = getattr(sys, "monitoring", None)

if TYPE_CHECKING:
    assert sys_monitoring is not None
    # I want to say this but it's not allowed:
    #   MonitorReturn = Literal[sys.monitoring.DISABLE] | None
    MonitorReturn = Any


if LOG:  # pragma: debugging

    class LoggingWrapper:
        """Wrap a namespace to log all its functions."""

        def __init__(self, wrapped: Any, namespace: str) -> None:
            self.wrapped = wrapped
            self.namespace = namespace

        def __getattr__(self, name: str) -> Callable[..., Any]:
            def _wrapped(*args: Any, **kwargs: Any) -> Any:
                self_prefix = ""
                caller_self = inspect.stack()[1][0].f_locals.get("self")
                if caller_self is not None:
                    self_prefix = f"{id(caller_self):#x}: "
                log(f"{self_prefix}{self.namespace}.{name}{args}{kwargs}")
                return getattr(self.wrapped, name)(*args, **kwargs)

            return _wrapped

    sys_monitoring = LoggingWrapper(sys_monitoring, "sys.monitoring")
    assert sys_monitoring is not None

    short_stack = functools.partial(
        short_stack,
        full=True,
        short_filenames=True,
        frame_ids=True,
    )

    def arg_repr(arg: Any) -> str:
        """Make a customized repr for logged values."""
        if isinstance(arg, CodeType):
            return (
                f"<code @{id(arg):#x}"
                + f" name={arg.co_name},"
                + f" file={short_filename(arg.co_filename)!r}#{arg.co_firstlineno}>"
            )
        return repr(arg)

    def panopticon(*names: str | None) -> AnyCallable:
        """Decorate a function to log its calls."""

        def _decorator(method: AnyCallable) -> AnyCallable:
            @functools.wraps(method)
            def _wrapped(self: Any, *args: Any) -> Any:
                try:
                    # log(f"{method.__name__}() stack:\n{short_stack()}")
                    args_reprs = []
                    code = None
                    for name, arg in zip(names, args):
                        if name is None:
                            continue
                        if name == "code":
                            code = arg
                        args_reprs.append(f"{name}={arg_repr(arg)}")
                        if name.endswith("@") and code is not None:
                            try:
                                line = bytes_to_lines(code)[arg]
                            except LookupError:
                                pass
                            else:
                                args_reprs[-1] += f"#{line}"
                    log(f"{id(self):#x}:{method.__name__}({', '.join(args_reprs)})")
                    ret = method(self, *args)
                    # log(f" end {id(self):#x}:{method.__name__}({', '.join(args_reprs)})")
                    return ret
                except Exception as exc:
                    log(f"!!{exc.__class__.__name__}: {exc}")
                    # fmt: off
                    log("".join(traceback.format_exception(exc)))  # pylint: disable=[no-value-for-parameter]
                    # fmt: on
                    try:
                        assert sys_monitoring is not None
                        sys_monitoring.set_events(sys.monitoring.COVERAGE_ID, 0)
                    except ValueError:
                        # We might have already shut off monitoring.
                        log("oops, shutting off events with disabled tool id")
                    raise

            return _wrapped

        return _decorator

else:

    def log(  # pylint: disable=function-redefined
        msg: str, stack: bool = False
    ) -> None:
        """Write a message to our detailed debugging log(s), but not really."""

    def panopticon(*names: str | None) -> AnyCallable:
        """Decorate a function to log its calls, but not really."""

        def _decorator(meth: AnyCallable) -> AnyCallable:
            return meth

        return _decorator


@dataclass
class CodeInfo:
    """The information we want about each code object."""

    tracing: bool
    file_data: TTraceFileData
    byte_to_line: dict[int, int]
    branch_dests: dict[int, set[int]]


def bytes_to_lines(code: CodeType) -> dict[int, int]:
    """Make a dict mapping byte code offsets to line numbers."""
    b2l = {}
    for bstart, bend, lineno in code.co_lines():
        if lineno is not None:
            for boffset in range(bstart, bend, 2):
                b2l[boffset] = lineno
    return b2l


class SysMonitor(TracerCore):
    """Python implementation of the raw data tracer for PEP669 implementations."""

    serial = itertools.count()

    # One of these will be used across threads. Be careful.

    def __init__(self, tool_id: int) -> None:
        self.number = next(self.serial)
        log(f"SysMonitor() #{self.number}: {id(self):#x}")

        # Attributes set from the collector:
        self.data: TTraceData
        self.trace_arcs = False
        self.should_trace: Callable[[str, FrameType], TFileDisposition]
        self.should_trace_cache: dict[str, TFileDisposition | None]
        # TODO: should_start_context and switch_context are unused!
        # Change tests/testenv.py:DYN_CONTEXTS when this is updated.
        self.should_start_context: Callable[[FrameType], str | None] | None = None
        self.switch_context: Callable[[str | None], None] | None = None
        # TODO: warn is unused.
        self.warn: TWarnFn

        self.myid = tool_id

        # Map id(code_object) -> CodeInfo
        self.code_infos: dict[int, CodeInfo] = {}
        # A list of code_objects, just to keep them alive so that id's are
        # useful as identity.
        self.code_objects: list[CodeType] = []
        self.last_lines: dict[FrameType, int] = {}
        # Map id(code_object) -> code_object
        self.local_event_codes: dict[int, CodeType] = {}
        self.sysmon_on = False

        self.stopped = False
        self._activity = False

    def __repr__(self) -> str:
        points = sum(len(v) for v in self.data.values())
        files = len(self.data)
        return (
            f"<SysMonitor #{self.number} at {id(self):#x}: "
            + f"{points} data points in {files} files>"
        )

    @panopticon()
    def start(self) -> None:
        """Start this Tracer."""
        self.stopped = False

        assert sys_monitoring is not None
        sys_monitoring.use_tool_id(self.myid, "coverage.py")
        register = functools.partial(sys_monitoring.register_callback, self.myid)
        events = sys.monitoring.events
        if self.trace_arcs:
            sys_monitoring.set_events(
                self.myid,
                events.PY_START
                | events.PY_UNWIND
                | events.EXCEPTION_HANDLED
                | events.RAISE
                | events.RERAISE
                | events.PY_THROW,
            )
            register(events.BRANCH, self.sysmon_branch)
            register(events.EXCEPTION_HANDLED, self.sysmon_exception_handled)
            register(events.JUMP, self.sysmon_jump)
            register(events.LINE, self.sysmon_line_arcs)
            register(events.PY_RESUME, self.sysmon_py_resume)
            register(events.PY_RETURN, self.sysmon_py_return)
            register(events.PY_START, self.sysmon_py_start)
            register(events.PY_THROW, self.sysmon_py_throw)
            register(events.PY_UNWIND, self.sysmon_py_unwind)
            register(events.RAISE, self.sysmon_raise)
            register(events.RERAISE, self.sysmon_reraise)
        else:
            sys_monitoring.set_events(self.myid, events.PY_START)
            register(events.PY_START, self.sysmon_py_start)
            register(events.LINE, self.sysmon_line_lines)
        sys_monitoring.restart_events()
        self.sysmon_on = True

    @panopticon()
    def stop(self) -> None:
        """Stop this Tracer."""
        if not self.sysmon_on:
            # In forking situations, we might try to stop when we are not
            # started.  Do nothing in that case.
            return
        assert sys_monitoring is not None
        sys_monitoring.set_events(self.myid, 0)
        self.sysmon_on = False
        for code in self.local_event_codes.values():
            sys_monitoring.set_local_events(self.myid, code, 0)
        self.local_event_codes = {}

        sys_monitoring.free_tool_id(self.myid)

    @panopticon()
    def post_fork(self) -> None:
        """The process has forked, clean up as needed."""
        self.stop()

    def activity(self) -> bool:
        """Has there been any activity?"""
        return self._activity

    def reset_activity(self) -> None:
        """Reset the activity() flag."""
        self._activity = False

    def get_stats(self) -> dict[str, int] | None:
        """Return a dictionary of statistics, or None."""
        return None

    # The number of frames in callers_frame takes @panopticon into account.
    if LOG:

        def callers_frame(self) -> FrameType:
            """Get the frame of the Python code we're monitoring."""
            return (
                inspect.currentframe().f_back.f_back.f_back  # type: ignore[union-attr,return-value]
            )

    else:

        def callers_frame(self) -> FrameType:
            """Get the frame of the Python code we're monitoring."""
            return inspect.currentframe().f_back.f_back  # type: ignore[union-attr,return-value]

    @panopticon("code", "@")
    def sysmon_py_start(self, code: CodeType, instruction_offset: int) -> MonitorReturn:
        """Handle sys.monitoring.events.PY_START events."""
        # Entering a new frame.  Decide if we should trace in this file.
        self._activity = True

        code_info = self.code_infos.get(id(code))
        tracing_code: bool | None = None
        file_data: TTraceFileData | None = None
        if code_info is not None:
            tracing_code = code_info.tracing
            file_data = code_info.file_data

        if tracing_code is None:
            filename = code.co_filename
            disp = self.should_trace_cache.get(filename)
            if disp is None:
                frame = inspect.currentframe().f_back  # type: ignore[union-attr]
                if LOG:
                    # @panopticon adds a frame.
                    frame = frame.f_back  # type: ignore[union-attr]
                disp = self.should_trace(filename, frame)  # type: ignore[arg-type]
                self.should_trace_cache[filename] = disp

            tracing_code = disp.trace
            if tracing_code:
                tracename = disp.source_filename
                assert tracename is not None
                if tracename not in self.data:
                    self.data[tracename] = set()
                file_data = self.data[tracename]
                b2l = bytes_to_lines(code)
            else:
                # These won't be used, but empties simplify the type checking.
                file_data = set()
                b2l = {}

            self.code_infos[id(code)] = CodeInfo(
                tracing=tracing_code,
                file_data=file_data,
                byte_to_line=b2l,
                branch_dests=collections.defaultdict(set),
            )
            self.code_objects.append(code)

            if tracing_code:
                events = sys.monitoring.events
                if self.sysmon_on:
                    assert sys_monitoring is not None
                    my_events = events.PY_RETURN | events.PY_RESUME | events.LINE
                    if self.trace_arcs:
                        my_events |= events.BRANCH | events.JUMP
                    sys_monitoring.set_local_events(self.myid, code, my_events)
                    self.local_event_codes[id(code)] = code

        if tracing_code and self.trace_arcs:
            frame = self.callers_frame()
            self.last_lines[frame] = -code.co_firstlineno
            return None
        else:
            return sys.monitoring.DISABLE

    @panopticon("code", "@")
    def sysmon_py_resume(
        self,
        code: CodeType,
        instruction_offset: int,
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.PY_RESUME events for branch coverage."""
        frame = self.callers_frame()
        self.last_lines[frame] = frame.f_lineno

    @panopticon("code", "@", None)
    def sysmon_py_return(
        self,
        code: CodeType,
        instruction_offset: int,
        retval: object,
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.PY_RETURN events for branch coverage."""
        frame = self.callers_frame()
        code_info = self.code_infos.get(id(code))
        if code_info is not None and code_info.file_data is not None:
            last_line = self.last_lines.get(frame)
            if last_line is not None:
                arc = (last_line, -code.co_firstlineno)
                log(f"adding {arc=}")
                cast(Set[TArc], code_info.file_data).add(arc)

        # Leaving this function, no need for the frame any more.
        self.last_lines.pop(frame, None)

    @panopticon("code", "@", "exc")
    def sysmon_py_unwind(
        self,
        code: CodeType,
        instruction_offset: int,
        exception: BaseException,
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.PY_UNWIND events for branch coverage."""
        frame = self.callers_frame()
        # Leaving this function.
        last_line = self.last_lines.pop(frame, None)
        if isinstance(exception, GeneratorExit):
            # We don't want to count generator exits as arcs.
            return
        code_info = self.code_infos.get(id(code))
        if code_info is not None and code_info.file_data is not None:
            if last_line is not None:
                arc = (last_line, -code.co_firstlineno)
                log(f"adding {arc=}")
                cast(Set[TArc], code_info.file_data).add(arc)

    @panopticon("code", "line")
    def sysmon_line_lines(self, code: CodeType, line_number: int) -> MonitorReturn:
        """Handle sys.monitoring.events.LINE events for line coverage."""
        code_info = self.code_infos[id(code)]
        if code_info.file_data is not None:
            log(f"adding {line_number=}")
            cast(Set[TLineNo], code_info.file_data).add(line_number)
        return sys.monitoring.DISABLE

    @panopticon("code", "line")
    def sysmon_line_arcs(self, code: CodeType, line_number: int) -> MonitorReturn:
        """Handle sys.monitoring.events.LINE events for branch coverage."""
        code_info = self.code_infos[id(code)]
        if code_info.file_data is not None:
            frame = self.callers_frame()
            last_line = self.last_lines.get(frame)
            if last_line is not None and last_line != line_number:
                arc = (last_line, line_number)
                log(f"adding {arc=}")
                cast(Set[TArc], code_info.file_data).add(arc)
            self.last_lines[frame] = line_number
        return sys.monitoring.DISABLE

    @panopticon("code", "src@", "dst@")
    def sysmon_jump(
        self, code: CodeType, instruction_offset: int, destination_offset: int
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.JUMP events."""
        code_info = self.code_infos[id(code)]
        assert code_info.file_data is not None
        src_line = code_info.byte_to_line[instruction_offset]
        dst_line = code_info.byte_to_line[destination_offset]
        if src_line != dst_line:
            arc = (src_line, dst_line)
            log(f"adding {arc=}")
            cast(Set[TArc], code_info.file_data).add(arc)
            self.last_lines[self.callers_frame()] = dst_line
        return sys.monitoring.DISABLE

    @panopticon("code", "src@", "dst@")
    def sysmon_branch(
        self, code: CodeType, instruction_offset: int, destination_offset: int
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.BRANCH events."""
        code_info = self.code_infos[id(code)]
        assert code_info.file_data is not None
        dests = code_info.branch_dests[instruction_offset]
        if destination_offset not in dests:
            src_line = code_info.byte_to_line[instruction_offset]
            dst_line = code_info.byte_to_line[destination_offset]
            if src_line != dst_line:
                arc = (src_line, dst_line)
                log(f"adding {arc=}")
                cast(Set[TArc], code_info.file_data).add(arc)
            dests.add(destination_offset)
            self.last_lines[self.callers_frame()] = dst_line
        # A BRANCH event can only have two possible destinations. Once we've
        # seen both, we can disable the event.
        if len(dests) == 2:
            return sys.monitoring.DISABLE
        else:
            return None

    @panopticon("code", "@", "exc")
    def sysmon_exception_handled(
        self, code: CodeType, instruction_offset: int, exception: BaseException
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.EXCEPTION_HANDLED events."""

    @panopticon("code", "@", "exc")
    def sysmon_raise(
        self, code: CodeType, instruction_offset: int, exception: BaseException
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.RAISE events."""
        frame = self.callers_frame()
        self.last_lines[frame] = frame.f_lineno

    @panopticon("code", "@", "exc")
    def sysmon_reraise(
        self, code: CodeType, instruction_offset: int, exception: BaseException
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.RERAISE events."""

    @panopticon("code", "@", "exc")
    def sysmon_py_throw(
        self, code: CodeType, instruction_offset: int, exception: BaseException
    ) -> MonitorReturn:
        """Handle sys.monitoring.events.PY_THROW events."""
