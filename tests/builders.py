"""Builders for tiny synthetic .tlog and ArduPilot .BIN files used by the tests.

Nothing here is real flight data: packets are generated with pymavlink's encoder.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from pymavlink.dialects.v20 import ardupilotmega as mav

T0 = 1_700_000_000.0  # fixed epoch so tests are deterministic
GCS_SYS, VEH_SYS = 255, 1
ARMED_CUSTOM = 128 | 1  # MAV_MODE_FLAG_SAFETY_ARMED | CUSTOM_MODE_ENABLED
DISARMED_CUSTOM = 1
MODE_GUIDED = 4


class _Sink:
    def write(self, data: bytes) -> None:  # MAVLink wants a file-like object
        pass


class TlogBuilder:
    """Collects ``(timestamp, packet)`` pairs and writes a .tlog file."""

    def __init__(self) -> None:
        self._gcs = mav.MAVLink(_Sink(), srcSystem=GCS_SYS, srcComponent=190)
        self._veh = mav.MAVLink(_Sink(), srcSystem=VEH_SYS, srcComponent=1)
        self.records: list[tuple[float, bytes]] = []

    def _add(self, ts: float, link: Any, message: Any, twice: bool) -> None:
        packet = message.pack(link)
        self.records.append((ts, packet))
        if twice:  # a second link delivers every packet again
            self.records.append((ts + 0.0005, packet))

    def vehicle(self, ts: float, message: Any, twice: bool = False) -> TlogBuilder:
        self._add(ts, self._veh, message, twice)
        return self

    def gcs(self, ts: float, message: Any, twice: bool = False) -> TlogBuilder:
        self._add(ts, self._gcs, message, twice)
        return self

    def heartbeat(self, ts: float, armed: bool = False, mode: int = MODE_GUIDED,
                  twice: bool = False) -> TlogBuilder:
        base = ARMED_CUSTOM if armed else DISARMED_CUSTOM
        return self.vehicle(ts, mav.MAVLink_heartbeat_message(2, 3, base, mode, 4, 3), twice)

    def gcs_heartbeat(self, ts: float) -> TlogBuilder:
        return self.gcs(ts, mav.MAVLink_heartbeat_message(6, 8, 0, 0, 4, 3))

    def status(self, ts: float, severity: int, text: str, msg_id: int = 0, chunk: int = 0,
               twice: bool = False) -> TlogBuilder:
        return self.vehicle(ts, mav.MAVLink_statustext_message(
            severity, text.encode(), msg_id, chunk), twice)

    def write(self, path: Path) -> Path:
        with path.open("wb") as out:
            for ts, packet in sorted(self.records, key=lambda r: r[0]):  # real logs are in time order
                out.write(struct.pack(">Q", int(ts * 1e6)) + packet)
        return path


def mission_count(count: int, kind: int = 0) -> Any:
    return mav.MAVLink_mission_count_message(1, 1, count, kind)


def mission_request(seq: int, kind: int = 0) -> Any:
    return mav.MAVLink_mission_request_int_message(255, 190, seq, kind)


def mission_item(seq: int, kind: int = 0) -> Any:
    return mav.MAVLink_mission_item_int_message(
        1, 1, seq, 3, 16, 0, 1, 0, 0, 0, 0, 0, 0, 10.0, kind)


def mission_request_list(kind: int = 0) -> Any:
    return mav.MAVLink_mission_request_list_message(1, 1, kind)


def mission_ack(result: int, kind: int = 0) -> Any:
    return mav.MAVLink_mission_ack_message(255, 190, result, kind)


def command_ack(command: int, result: int) -> Any:
    return mav.MAVLink_command_ack_message(command, result, 0, 0, 255, 190)


# ---------------------------------------------------------------- dataflash (.BIN)

_FMT_TYPE = 128
_FORMATS = {  # type -> (name, format, labels)
    128: ("FMT", "BBnNZ", "Type,Length,Name,Format,Columns"),
    129: ("MSG", "QZ", "TimeUS,Message"),
    130: ("ERR", "QBB", "TimeUS,Subsys,ECode"),
    131: ("EV", "QB", "TimeUS,Id"),
    132: ("MODE", "QMBB", "TimeUS,Mode,ModeNum,Rsn"),
}
_SIZES = {"Q": 8, "B": 1, "M": 1, "Z": 64, "n": 4, "N": 16}


def _length(fmt: str) -> int:
    return 3 + sum(_SIZES[c] for c in fmt)


class DataflashBuilder:
    """Writes a minimal ArduPilot .BIN (FMT table + MSG/ERR/EV/MODE records)."""

    def __init__(self) -> None:
        self._out = bytearray()
        for ftype, (name, fmt, labels) in _FORMATS.items():
            self._record(_FMT_TYPE, struct.pack(
                "<BB4s16s64s", ftype, _length(fmt), name.encode(), fmt.encode(), labels.encode()))

    def _record(self, rtype: int, payload: bytes) -> None:
        self._out += b"\xa3\x95" + bytes([rtype]) + payload

    def msg(self, us: int, text: str) -> DataflashBuilder:
        self._record(129, struct.pack("<Q64s", us, text.encode()))
        return self

    def err(self, us: int, subsys: int, code: int) -> DataflashBuilder:
        self._record(130, struct.pack("<QBB", us, subsys, code))
        return self

    def ev(self, us: int, event_id: int) -> DataflashBuilder:
        self._record(131, struct.pack("<QB", us, event_id))
        return self

    def mode(self, us: int, mode: int) -> DataflashBuilder:
        self._record(132, struct.pack("<QBBB", us, mode, mode, 0))
        return self

    def write(self, path: Path) -> Path:
        path.write_bytes(bytes(self._out))
        return path
