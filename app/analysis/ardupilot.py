"""ArduPilot dataflash code tables.

Values are copied from ``libraries/AP_Logger/AP_Logger.h`` (LogErrorSubsystem,
LogErrorCode, LogEvent). Unknown values are reported as numbers, never guessed.
"""

from __future__ import annotations

SUBSYSTEMS: dict[int, str] = {
    1: "MAIN", 2: "RADIO", 3: "COMPASS", 4: "OPTFLOW", 5: "FAILSAFE_RADIO",
    6: "FAILSAFE_BATT", 7: "FAILSAFE_GPS", 8: "FAILSAFE_GCS", 9: "FAILSAFE_FENCE",
    10: "FLIGHT_MODE", 11: "GPS", 12: "CRASH_CHECK", 13: "FLIP", 14: "AUTOTUNE",
    15: "PARACHUTES", 16: "EKFCHECK", 17: "FAILSAFE_EKFINAV", 18: "BARO", 19: "CPU",
    20: "FAILSAFE_ADSB", 21: "TERRAIN", 22: "NAVIGATION", 23: "FAILSAFE_TERRAIN",
    24: "EKF_PRIMARY", 25: "THRUST_LOSS_CHECK", 26: "FAILSAFE_SENSORS",
    27: "FAILSAFE_LEAK", 28: "PILOT_INPUT", 29: "FAILSAFE_VIBE", 30: "INTERNAL_ERROR",
    31: "FAILSAFE_DEADRECKON", 32: "FAILSAFE_COMPANION",
}

_CRASH_CHECK = 12
_GENERIC_CODES = {0: "resolved", 1: "failed to initialise / occurred", 4: "unhealthy"}
_SPECIFIC_CODES: dict[str, dict[int, str]] = {
    "RADIO": {2: "late frame"},
    "MAIN": {1: "INS delay"},
    "CRASH_CHECK": {1: "crash detected", 2: "loss of control"},
    "FLIP": {2: "flip abandoned"},
    "TERRAIN": {2: "missing terrain data"},
    "NAVIGATION": {2: "failed to set destination", 3: "restarted RTL",
                   4: "failed circle init", 5: "destination outside fence",
                   6: "RTL missing rangefinder"},
    "INTERNAL_ERROR": {1: "internal errors detected"},
    "PARACHUTES": {2: "too low to deploy", 3: "landed"},
    "EKFCHECK": {2: "bad variance", 0: "variance cleared"},
    "BARO": {2: "glitch", 3: "bad depth"},
    "GPS": {2: "glitch"},
}

EVENTS: dict[int, str] = {
    10: "Armed", 11: "Disarmed", 15: "Auto-armed", 17: "Land complete (maybe)",
    18: "Land complete", 28: "Not landed", 19: "Lost GPS", 25: "Home set",
    41: "Fence enabled", 42: "Fence disabled", 49: "Parachute disabled",
    50: "Parachute enabled", 51: "Parachute released",
}
#: Events worth a WARNING level (everything else is INFO).
WARNING_EVENTS = frozenset({19, 51})


def subsystem_name(code: int) -> str:
    return SUBSYSTEMS.get(code, f"subsystem {code}")


def error_description(subsystem: int, code: int) -> str:
    """Human description of an ERR record's (subsystem, code) pair."""
    name = SUBSYSTEMS.get(subsystem, "")
    if name.startswith("FAILSAFE_") and code in (0, 1):
        return "failsafe resolved" if code == 0 else "failsafe occurred"
    specific = _SPECIFIC_CODES.get(name, {})
    if code in specific:
        return specific[code]
    return _GENERIC_CODES.get(code, f"code {code}")


def is_crash_error(subsystem: int, code: int) -> bool:
    """CRASH_CHECK with crash / loss of control."""
    return subsystem == _CRASH_CHECK and code in (1, 2)
