import asyncio
import statistics
import time
import websockets

URL = "ws://127.0.0.1:8765"
NUM_CLIENTS = 100
SLEEP_SEC = 6.5

async def run_benchmark():
    print(f"[BENCH] Connecting {NUM_CLIENTS} concurrent WebSockets to {URL}...")
    t_conn0 = time.perf_counter()
    clients = await asyncio.gather(*[
        websockets.connect(URL, ping_interval=None, open_timeout=10)
        for _ in range(NUM_CLIENTS)
    ])
    t_conn = (time.perf_counter() - t_conn0) * 1000.0
    print(f"[BENCH] {len(clients)}/{NUM_CLIENTS} sockets OPEN in {t_conn:.1f} ms")

    async def send_recv(idx, ws, tag):
        t0 = time.perf_counter()
        await ws.send(f"{tag}-client-{idx}")
        resp = await ws.recv()
        dt = (time.perf_counter() - t0) * 1000.0
        return dt, resp

    # Phase 1: Warm active burst
    res_warm = await asyncio.gather(*[send_recv(i, ws, "WARM") for i, ws in enumerate(clients)])
    lat_warm = sorted(r[0] for r in res_warm)
    print(f"[WARM ] 100/100 ACKs OK | p50={statistics.median(lat_warm):.2f} ms | p95={lat_warm[94]:.2f} ms | max={lat_warm[-1]:.2f} ms")

    # Phase 2: Idle sleep with ALL 100 open WebSocket connections
    print(f"[IDLE ] Holding all {NUM_CLIENTS} TCP/WS sockets open for {SLEEP_SEC}s (waiting for eBPF freeze + Zstd RAM evict)...")
    await asyncio.sleep(SLEEP_SEC)

    # Phase 3: Thundering-herd wake-up across all 100 sockets simultaneously
    print(f"[WAKE ] Firing {NUM_CLIENTS} simultaneous messages onto FROZEN process...")
    t_burst0 = time.perf_counter()
    res_wake = await asyncio.gather(*[send_recv(i, ws, "WAKE") for i, ws in enumerate(clients)], return_exceptions=True)
    t_burst = (time.perf_counter() - t_burst0) * 1000.0

    errors = [r for r in res_wake if isinstance(r, Exception)]
    ok = [r for r in res_wake if not isinstance(r, Exception)]
    lat_wake = sorted(r[0] for r in ok)

    print(f"[WAKE ] Survived: {len(ok)}/{NUM_CLIENTS} sockets (Dropped: {len(errors)}) | Total burst: {t_burst:.2f} ms")
    if lat_wake:
        print(f"[WAKE ] Latency: min={lat_wake[0]:.2f} ms | p50={statistics.median(lat_wake):.2f} ms | p95={lat_wake[int(len(lat_wake)*0.95)-1]:.2f} ms | max={lat_wake[-1]:.2f} ms")
        print(f"[WAKE ] Sample ACK: {ok[0][1]}")

    await asyncio.gather(*[ws.close() for ws in clients], return_exceptions=True)

if __name__ == "__main__":
    asyncio.run(run_benchmark())
