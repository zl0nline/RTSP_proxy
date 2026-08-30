from __future__ import annotations

import asyncio
import re
import socket
from collections.abc import Awaitable, Callable
from typing import Protocol, cast

from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import MessageType
from dbus_next.message import Message
from dbus_next.signature import Variant

from rtsp_proxy.probe_systemd import (
    ProbeSystemdCall,
    ProbeSystemdReply,
    ProbeSystemdSignature,
    ProbeSystemdStartRejected,
    ProbeSystemdStartRejectedInterruption,
    ProbeSystemdTransport,
    ProbeSystemdValue,
)

_SYSTEM_BUS_ADDRESS = "unix:path=/run/dbus/system_bus_socket"


class _AsyncMessageBus(Protocol):
    async def connect(self) -> _AsyncMessageBus: ...

    async def call(self, message: Message) -> Message | None: ...

    def disconnect(self) -> None: ...

    async def wait_for_disconnect(self) -> None: ...


type _BusFactory = Callable[[float], Awaitable[_AsyncMessageBus]]

_DISCONNECT_RESERVE_SECONDS = 2.0
_NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
_UNIT_EXISTS = "org.freedesktop.systemd1.UnitExists"
_PROBE_UNIT_PATTERN = re.compile(r"rtsp-probe-[0-9a-f]{32}\.service")


class DbusNextSystemdTransport(ProbeSystemdTransport):
    """Direct low-level D-Bus adapter for the fixed system-manager call."""

    def __init__(self, *, bus_factory: _BusFactory | None = None) -> None:
        self._bus_factory = bus_factory or _system_bus

    def call(
        self,
        request: ProbeSystemdCall,
        *,
        timeout_seconds: float,
    ) -> ProbeSystemdReply:
        return asyncio.run(self._start(request, timeout_seconds=timeout_seconds))

    def recover(self, unit_name: str, *, timeout_seconds: float) -> None:
        if _PROBE_UNIT_PATTERN.fullmatch(unit_name) is None:
            raise RuntimeError("probe systemd unit name invalid")
        asyncio.run(self._recover(unit_name, timeout_seconds=timeout_seconds))

    async def _start(
        self,
        request: ProbeSystemdCall,
        *,
        timeout_seconds: float,
    ) -> ProbeSystemdReply:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        async def operation(bus: _AsyncMessageBus) -> ProbeSystemdReply:
            message = _message_for(request)
            reply = await _await_until(bus.call(message), deadline=deadline)
            return _reply_from(reply)

        return await self._with_bus(operation, deadline=deadline)

    async def _recover(self, unit_name: str, *, timeout_seconds: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds

        async def operation(bus: _AsyncMessageBus) -> None:
            stop_reply = await _await_until(
                bus.call(_manager_message("StopUnit", "ss", [unit_name, "replace"])),
                deadline=deadline,
            )
            if _is_no_such_unit(stop_reply):
                return
            _object_path_reply(stop_reply)
            while True:
                get_reply = await _await_until(
                    bus.call(_manager_message("GetUnit", "s", [unit_name])),
                    deadline=deadline,
                )
                if _is_no_such_unit(get_reply):
                    return
                _object_path_reply(get_reply)
                await _sleep_until_next_readback(deadline=deadline)

        await self._with_bus(operation, deadline=deadline)

    async def _with_bus[T](
        self,
        operation: Callable[[_AsyncMessageBus], Awaitable[T]],
        *,
        deadline: float,
    ) -> T:
        bus: _AsyncMessageBus | None = None
        primary_error: BaseException | None = None
        try:
            bus = await _await_until(self._bus_factory(deadline), deadline=deadline)
            await _await_until(bus.connect(), deadline=deadline)
            return await operation(bus)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if bus is not None:
                try:
                    await _disconnect(bus)
                except BaseException as cleanup_error:
                    if primary_error is not None:
                        if isinstance(primary_error, ProbeSystemdStartRejected):
                            if not isinstance(cleanup_error, Exception):
                                raise ProbeSystemdStartRejectedInterruption(
                                    cleanup_error
                                ) from None
                            raise primary_error from None
                        raise BaseExceptionGroup(
                            "system bus operation and disconnect failed",
                            [primary_error, cleanup_error],
                        ) from None
                    raise


class _PreconnectedMessageBus(MessageBus):
    def __init__(self, connected_socket: socket.socket) -> None:
        self._connected_socket = connected_socket
        super().__init__(
            bus_address=_SYSTEM_BUS_ADDRESS,
            negotiate_unix_fd=True,
        )

    def _setup_socket(self) -> None:
        self._sock = self._connected_socket
        self._stream = self._sock.makefile("rwb")
        self._fd = self._sock.fileno()


async def _system_bus(deadline: float) -> _AsyncMessageBus:
    connected_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connected_socket.setblocking(False)
    try:
        await _await_until(
            asyncio.get_running_loop().sock_connect(
                connected_socket,
                "/run/dbus/system_bus_socket",
            ),
            deadline=deadline,
        )
        return cast(_AsyncMessageBus, _PreconnectedMessageBus(connected_socket))
    except BaseException:
        connected_socket.close()
        raise


async def _disconnect(bus: _AsyncMessageBus) -> None:
    deadline = asyncio.get_running_loop().time() + _DISCONNECT_RESERVE_SECONDS
    disconnect_error: BaseException | None = None
    try:
        bus.disconnect()
    except BaseException as error:
        disconnect_error = error
    try:
        await _await_until(bus.wait_for_disconnect(), deadline=deadline)
    except BaseException as wait_error:
        if disconnect_error is not None:
            raise BaseExceptionGroup(
                "system bus disconnect and finalization wait failed",
                [disconnect_error, wait_error],
            ) from None
        raise
    if disconnect_error is not None:
        raise disconnect_error from None


async def _await_until[T](awaitable: Awaitable[T], *, deadline: float) -> T:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("probe system bus deadline expired")
    return await asyncio.wait_for(awaitable, timeout=remaining)


def _message_for(request: ProbeSystemdCall) -> Message:
    unit_name, start_mode, properties, auxiliary_units = request.body
    body_properties = [
        [name, Variant(signature, _dbus_value(signature, value))]
        for name, signature, value in properties
    ]
    return Message(
        destination=request.destination,
        path=request.object_path,
        interface=request.interface,
        member=request.member,
        signature=request.signature,
        body=[unit_name, start_mode, body_properties, list(auxiliary_units)],
        unix_fds=list(request.unix_fds),
    )


def _manager_message(member: str, signature: str, body: list[object]) -> Message:
    return Message(
        destination="org.freedesktop.systemd1",
        path="/org/freedesktop/systemd1",
        interface="org.freedesktop.systemd1.Manager",
        member=member,
        signature=signature,
        body=body,
    )


def _is_no_such_unit(reply: Message | None) -> bool:
    return (
        reply is not None
        and reply.message_type is MessageType.ERROR
        and reply.error_name == _NO_SUCH_UNIT
    )


def _object_path_reply(reply: Message | None) -> str:
    if (
        reply is None
        or reply.message_type is not MessageType.METHOD_RETURN
        or reply.signature != "o"
        or len(reply.body) != 1
        or not isinstance(reply.body[0], str)
    ):
        raise RuntimeError("probe systemd response invalid")
    return reply.body[0]


async def _sleep_until_next_readback(*, deadline: float) -> None:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError("probe system bus deadline expired")
    await asyncio.sleep(min(0.02, remaining))


def _dbus_value(
    signature: ProbeSystemdSignature,
    value: ProbeSystemdValue,
) -> object:
    if signature in {"s", "b", "t", "u", "h"}:
        return value
    if signature == "a(sasb)":
        commands = cast(tuple[tuple[str, tuple[str, ...], bool], ...], value)
        return [[path, list(argv), ignore_failure] for path, argv, ignore_failure in commands]
    if signature == "(bas)":
        allow_list, values = cast(tuple[bool, tuple[str, ...]], value)
        return [allow_list, list(values)]
    if signature == "a(hs)":
        descriptors = cast(tuple[tuple[int, str], ...], value)
        return [[descriptor, name] for descriptor, name in descriptors]
    if signature == "a(iayu)":
        prefixes = cast(tuple[tuple[int, bytes, int], ...], value)
        return [[family, address, prefix_length] for family, address, prefix_length in prefixes]
    if signature == "a(iiqq)":
        filters = cast(tuple[tuple[int, int, int, int], ...], value)
        return [list(filter_) for filter_ in filters]
    raise TypeError("probe systemd property signature unsupported")


def _reply_from(reply: Message | None) -> ProbeSystemdReply:
    if (
        reply is not None
        and reply.message_type is MessageType.ERROR
        and reply.error_name == _UNIT_EXISTS
    ):
        raise ProbeSystemdStartRejected("probe_transient_start_rejected") from None
    return ProbeSystemdReply(job_path=_object_path_reply(reply))
