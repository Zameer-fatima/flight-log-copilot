"""Regenerate the synthetic demo samples in ``sample_data/`` (run from the project root).

    python tools/make_demo_samples.py

Everything here is invented (fake vehicle, fake program ``demo-gcs``, fake paths); no real
flight, customer or machine data is used. The samples are what the public demo shows.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.builders import (  # noqa: E402
    DataflashBuilder,
    TlogBuilder,
    command_ack,
    mission_ack,
    mission_count,
    mission_item,
    mission_request,
)

OUT = ROOT / "sample_data"
T0 = 1_741_947_300.0  # 2025-03-14 10:15:00 UTC
STABILIZE, AUTO, GUIDED, RTL, LAND = 0, 3, 4, 6, 9
INVALID_SEQUENCE, MAV_RESULT_FAILED, GET_HOME_POSITION = 13, 4, 410


def make_tlog() -> Path:
    """A ~75 s sortie: a failed mission upload, a good one, a link gap and a low battery."""
    b = TlogBuilder()
    mode, armed = STABILIZE, False
    changes = {25: (GUIDED, False), 27: (GUIDED, True), 30: (AUTO, True),
               61: (RTL, True), 66: (LAND, True), 72: (LAND, False)}
    for t in range(0, 76):
        if t in changes:
            mode, armed = changes[t]
        if 38 <= t < 50:  # the link drops for 12 seconds
            continue
        b.heartbeat(T0 + t, armed=armed, mode=mode)
    b.status(T0 + 0.5, 6, "ArduCopter V4.5.2 (demo)").status(T0 + 0.6, 6, "Frame: QUAD/PLUS")
    b.status(T0 + 2, 4, "PreArm: Compass not calibrated")
    b.status(T0 + 20, 6, "EKF3 IMU0 is using GPS")
    b.vehicle(T0 + 1, command_ack(GET_HOME_POSITION, MAV_RESULT_FAILED))
    b.vehicle(T0 + 6, command_ack(GET_HOME_POSITION, MAV_RESULT_FAILED))
    # upload #1: the vehicle keeps asking for item 3, then rejects the mission
    b.gcs(T0 + 8, mission_count(6))
    for seq, t in ((0, 8.1), (1, 8.4), (2, 8.7)):
        b.vehicle(T0 + t, mission_request(seq)).gcs(T0 + t + 0.1, mission_item(seq))
    b.vehicle(T0 + 9.0, mission_request(3))
    b.vehicle(T0 + 10.5, mission_request(3))
    b.vehicle(T0 + 12.0, mission_request(3))
    b.vehicle(T0 + 13.0, mission_ack(INVALID_SEQUENCE))
    # upload #2: clean
    b.gcs(T0 + 16, mission_count(6))
    for seq in range(6):
        b.vehicle(T0 + 16.1 + 0.2 * seq, mission_request(seq))
        b.gcs(T0 + 16.2 + 0.2 * seq, mission_item(seq))
    b.vehicle(T0 + 17.5, mission_ack(0))
    b.status(T0 + 27.5, 6, "Arming motors")
    b.status(T0 + 55, 4, "Battery 1 is low 21.3V used 1850 mAh")
    b.status(T0 + 60, 2, "Battery 1 is critical 20.1V used 2310 mAh")
    b.status(T0 + 60.5, 6, "Failsafe: Battery - returning to launch")
    return b.write(OUT / "demo.tlog")


def make_bin() -> Path:
    """A dataflash log with GPS/EKF trouble, a failsafe and a crash-check trip."""
    s = 1_000_000
    b = DataflashBuilder()
    b.msg(1 * s, "ArduCopter V4.5.2 (demo)").msg(1 * s, "Frame: QUAD/PLUS")
    b.mode(2 * s, 4).ev(5 * s, 10).mode(8 * s, 3)
    b.err(40 * s, 16, 2).err(41 * s, 11, 2).ev(42 * s, 19)
    b.msg(42 * s, "EKF3 IMU0 lost GPS")
    b.err(43 * s, 17, 1).mode(44 * s, 6)
    b.err(70 * s, 6, 1)
    b.err(94 * s, 12, 1).msg(94 * s, "Crash: Disarming").ev(95 * s, 11)
    return b.write(OUT / "demo.BIN")


def _block(pid: int, sig: str, ts: str, frames: list[str]) -> str:
    body = "\n".join(f"                {f}" for f in frames)
    return f"""           PID: {pid} (demo-gcs)
           UID: 1000 (demo)
        Signal: {sig}
     Timestamp: {ts} UTC (2 weeks ago)
  Command Line: /opt/demo-gcs/bin/demo-gcs
    Executable: /opt/demo-gcs/bin/demo-gcs
       Storage: /var/lib/systemd/coredump/core.demo-gcs.{pid} (missing)
       Message: Process {pid} (demo-gcs) of user 1000 dumped core.

                Stack trace of thread {pid}:
{body}

"""


def make_crash() -> Path:
    qt = "/opt/qt/6.6.3/lib/libQt6Core.so.6.6.3"
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
    segv = [f"#0  0x00007f3a1c2b2845 QObject::property(char const*) const ({qt} + 0x1b2845)",
            "#1  0x0000000101000014 n/a (n/a + 0x0)"]
    abrt = [f"#0  0x00007f3a1b0969fc __pthread_kill_implementation ({libc} + 0x969fc)",
            f"#1  0x00007f3a1b042476 raise ({libc} + 0x42476)",
            f"#2  0x00007f3a1b0287f3 abort ({libc} + 0x287f3)",
            f"#3  0x00007f3a1b089637 __libc_message ({libc} + 0x89637)",
            f"#4  0x00007f3a1b0a0cbc malloc_printerr ({libc} + 0xa0cbc)",
            f"#5  0x00007f3a1b0a2a14 _int_free ({libc} + 0xa2a14)",
            f"#6  0x00007f3a1b0a5413 free ({libc} + 0xa5413)",
            f"#7  0x00007f3a1c2cd1f0 QVariant::~QVariant() ({qt} + 0x1cd1f0)"]
    text = "".join(_block(4000 + i, "11 (SEGV)", f"Tue 2025-03-{4 + i:02d} 1{i}:2{i}:10", segv)
                   for i in range(5))
    text += _block(4100, "6 (ABRT)", "Fri 2025-03-07 16:40:02", abrt)
    path = OUT / "demo_crash.txt"
    path.write_text(text, encoding="utf-8")
    return path


if __name__ == "__main__":
    for made in (make_tlog(), make_bin(), make_crash()):
        print(f"wrote {made.relative_to(ROOT)} ({made.stat().st_size} bytes)")
