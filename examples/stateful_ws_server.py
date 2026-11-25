import asyncio, websockets, time, os, sys

def get_rss_mb():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0

print(f"[AETHER-APP] Reservando 400 MB de estado en memoria RAM...", flush=True)
t0 = time.perf_counter()
mem_heap = bytearray(400 * 1024 * 1024)
mem_heap[::4096] = b"Z" * (len(mem_heap) // 4096)
mem_heap[100_000_000:100_000_022] = b"AETHER_SECRET_100MB_OK"
mem_heap[250_000_000:250_000_022] = b"AETHER_SECRET_250MB_OK"
mem_heap[390_000_000:390_000_022] = b"AETHER_SECRET_390MB_OK"
dt = (time.perf_counter() - t0) * 1000.0
print(f"[AETHER-APP] 400 MB confirmados en DRAM en {dt:.0f} ms | VmRSS = {get_rss_mb():.1f} MB", flush=True)

counter = 0
offsets = [100_000_000, 250_000_000, 390_000_000]

async def handler(ws):
    global counter
    print("\n[AETHER-APP] Cliente conectado. WebSocket activo.", flush=True)
    try:
        async for msg in ws:
            counter += 1
            t = time.strftime("%H:%M:%S")
            off = offsets[(counter - 1) % len(offsets)]
            secret = bytes(mem_heap[off:off + 22]).decode("ascii")
            rss_now = get_rss_mb()
            print(f"[AETHER-APP][{t}] '{msg}' | counter={counter} | @{off // 1_000_000}MB='{secret}' | VmRSS={rss_now:.1f} MB", flush=True)
            await ws.send(f"ACK #{counter} ({t}) | @{off // 1_000_000}MB='{secret}' | RAM fisica: {rss_now:.1f} MB / 400 MB")
    except Exception:
        pass

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    host = "0.0.0.0" if port == 8765 else "127.0.0.1"
    async with websockets.serve(handler, host, port):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
