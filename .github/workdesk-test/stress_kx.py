"""WorkDesk hbbs: стресс- и краш-тест TCP 21116 с обменом ключами (правило: перед каждой публикацией).

Нагрузка: 300 обычных и 300 шифрованных запросов волнами по 100 одновременно.
Краш: обрыв после KeyExchange, полкадра и обрыв, битый ответ на обмен, 200 молчащих соединений разом.
"""
import asyncio
import base64
import time

from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import VerifyKey
from nacl.utils import random as nrandom

import rendezvous_pb2 as pb

# Подставляет ws_register_test.py перед вызовом stress_check(): ключ сервера и кодек кадров
KEY = frame = msg = read_frame = None

UNKNOWN = "111222333"


async def one_plain():
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    try:
        w.write(frame(msg(punch_hole_request=pb.PunchHoleRequest(id=UNKNOWN, licence_key=KEY))))
        await w.drain()
        m = pb.RendezvousMessage()
        m.ParseFromString(await read_frame(r, timeout=10))
        assert m.WhichOneof("union") == "punch_hole_response", m
    finally:
        w.close()


async def one_secure():
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    try:
        m = pb.RendezvousMessage()
        m.ParseFromString(await read_frame(r, timeout=10))
        server_pk = VerifyKey(base64.b64decode(KEY)).verify(m.key_exchange.keys[0])
        ours = PrivateKey.generate()
        sym = nrandom(SecretBox.KEY_SIZE)
        ke = pb.RendezvousMessage()
        ke.key_exchange.keys.extend([bytes(ours.public_key), Box(ours, PublicKey(server_pk)).encrypt(sym, bytes(24)).ciphertext])
        w.write(frame(ke.SerializeToString()))
        box = SecretBox(sym)
        nonce = (1).to_bytes(8, "little") + bytes(16)
        req = msg(punch_hole_request=pb.PunchHoleRequest(id=UNKNOWN, licence_key=KEY))
        w.write(frame(box.encrypt(req, nonce).ciphertext))
        await w.drain()
        m = pb.RendezvousMessage()
        m.ParseFromString(box.decrypt(await read_frame(r, timeout=10), nonce))
        assert m.WhichOneof("union") == "punch_hole_response", m
    finally:
        w.close()


async def stress_check():
    times = {"обычные": [], "шифрованные": []}
    errors = []

    async def timed(kind, fn):
        t = time.perf_counter()
        try:
            await fn()
            times[kind].append(time.perf_counter() - t)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{kind}: {e!r}")

    for _ in range(3):
        await asyncio.gather(*[timed("обычные", one_plain) for _ in range(100)],
                             *[timed("шифрованные", one_secure) for _ in range(100)])
    for kind, t in times.items():
        t.sort()
        p95 = t[max(0, int(len(t) * 0.95) - 1)] if t else 0
        print(f"OK  нагрузка, {kind}: {len(t)} успешно, p50 {t[len(t) // 2] * 1000:.0f} мс, p95 {p95 * 1000:.0f} мс")
    assert not errors, errors[:5]

    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    await read_frame(r, timeout=5)
    w.close()  # ушёл сразу после KeyExchange
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    w.write(bytes([0x81]))
    await w.drain()
    w.close()  # полкадра и обрыв
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    await read_frame(r, timeout=5)
    w.write(frame(bytes([0x0A, 0x00])))
    await w.drain()
    w.close()  # битый ответ на обмен
    many = [await asyncio.open_connection("127.0.0.1", 21116) for _ in range(200)]
    await asyncio.sleep(1.5)  # все получили KeyExchange и молчат
    for _, w in many:
        w.close()
    await one_plain()
    await one_secure()
    print("OK  краш-сценарии: обрывы, полкадра, битый обмен, 200 молчащих — сервер отвечает дальше")
