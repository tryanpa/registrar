"""A tiny WHOIS server (RFC 3912): the client sends one line, we answer and close.

Run:  python3 -m registrar.whois_server
Students query it with:  whois -h registrar.sandbar.lab mysite.lab
"""
import asyncio
import logging

from . import db as dbm
from .config import from_env
from .whois_fmt import whois_text

log = logging.getLogger("registrar.whois")
MAX_QUERY_BYTES = 256
MAX_CONNECTIONS = 50


def answer(cfg, query):
    conn = dbm.connect(cfg.db_path, query_only=True)
    try:
        return whois_text(cfg, conn, query)
    finally:
        conn.close()


async def handle(reader, writer, cfg, limit):
    peer = (writer.get_extra_info("peername") or ("?",))[0]
    try:
        async with limit:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
            except (asyncio.TimeoutError, ValueError, asyncio.LimitOverrunError):
                return
            query = line[:MAX_QUERY_BYTES].decode("utf-8", "replace").strip()
            log.info("%s asked about %r", peer, query[:80])
            text = await asyncio.get_running_loop().run_in_executor(None, answer, cfg, query)
            writer.write(text.replace("\n", "\r\n").encode())
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    except Exception:
        log.exception("error handling query from %s", peer)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve(cfg):
    limit = asyncio.Semaphore(MAX_CONNECTIONS)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, cfg, limit),
        cfg.whois_bind, cfg.whois_port, limit=1024,
    )
    log.info("WHOIS listening on %s:%s", cfg.whois_bind, cfg.whois_port)
    async with server:
        await server.serve_forever()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(serve(from_env()))


if __name__ == "__main__":
    main()
