#!/usr/bin/env python3
"""Serialized (one-at-a-time, no overlap) standby watch using the real
AVR1710Client. Polls get_power() every POLL_INTERVAL seconds and logs
reachability + reported power state, so we can see (a) when/if power
actually flips to off after the power-off commands already sent, and
(b) whether the control port ever goes genuinely dark afterward.
"""
import asyncio
import sys
import time

sys.path.insert(0, "/Users/allisonbulner/ha-avr1710-integration/custom_components/avr1710")
import api as avr_api  # noqa: E402

HOST = "192.168.0.65"
POLL_INTERVAL = 20
DURATION_S = 600
LOG = "/tmp/avr_clean_watch.log"


def log(msg: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


async def check_once() -> None:
    client = avr_api.AVR1710Client(HOST)
    t0 = time.time()
    try:
        power = await client.get_power()
        source = await client.get_source()
        log(f"REACHABLE power_on={power} source={source!r} ({time.time()-t0:.1f}s)")
    except Exception as e:
        log(f"UNREACHABLE {type(e).__name__}: {e} ({time.time()-t0:.1f}s)")
    finally:
        await client.close()


async def main() -> None:
    open(LOG, "w").close()
    log("=== clean serialized watch start ===")
    end = time.time() + DURATION_S
    while time.time() < end:
        await check_once()
        await asyncio.sleep(POLL_INTERVAL)
    log("=== watch complete ===")


asyncio.run(main())
