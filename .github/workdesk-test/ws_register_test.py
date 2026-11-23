"""WorkDesk hbbs: регистрация через WebSocket и доставка запросов в этот поток.

B регистрируется через ws://127.0.0.1:21118 (как клиент с закрытым UDP 21116), A просит подключиться к B,
B получает PunchHole в свой поток, отвечает RelayResponse, A получает ответ. Плюс проверка связи (heartbeat).
"""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import websockets
import rendezvous_pb2 as pb

WS = "ws://127.0.0.1:21118"
PEER_ID = "987654321"
KEY = open(os.environ.get("HBBS_KEY_FILE", "id_ed25519.pub")).read().strip()


def msg(**kw):
    m = pb.RendezvousMessage()
    for k, v in kw.items():
        getattr(m, k).CopyFrom(v)
    return m.SerializeToString()


async def recv_msg(ws, timeout=5, skip_empty=True):
    while True:
        data = await asyncio.wait_for(ws.recv(), timeout)
        if isinstance(data, str):
            raise AssertionError("ожидались бинарные сообщения")
        if not data and skip_empty:
            continue
        m = pb.RendezvousMessage()
        m.ParseFromString(data)
        return m, data


async def udp_check():
    """Обычный клиент по UDP: регистрация и доставка запроса работают как раньше."""
    import socket
    loop = asyncio.get_running_loop()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.setblocking(False); u.bind(("127.0.0.1", 0))
    srv = ("127.0.0.1", 21116)

    async def udp_recv(timeout=5):
        data = await asyncio.wait_for(loop.sock_recv(u, 65535), timeout)
        m = pb.RendezvousMessage(); m.ParseFromString(data); return m

    u.sendto(msg(register_peer=pb.RegisterPeer(id="123123123", serial=0)), srv)
    m = await udp_recv(); assert m.WhichOneof("union") == "register_peer_response", m
    u.sendto(msg(register_pk=pb.RegisterPk(id="123123123", uuid=b"uuid-u", pk=b"U" * 32)), srv)
    m = await udp_recv(); assert m.WhichOneof("union") == "register_pk_response" and m.register_pk_response.result == pb.RegisterPkResponse.OK, m
    u.sendto(msg(register_peer=pb.RegisterPeer(id="123123123", serial=0)), srv)
    m = await udp_recv(); assert m.WhichOneof("union") == "register_peer_response", m
    print("OK  UDP: регистрация как раньше")
    async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.7"}) as a:
        await a.send(msg(punch_hole_request=pb.PunchHoleRequest(id="123123123", licence_key=KEY)))
        m = await udp_recv(); assert m.WhichOneof("union") in ("punch_hole", "fetch_local_addr"), m
    print("OK  UDP: запрос на подключение доставлен по UDP")
    u.close()


async def dual_check():
    """Два канала сразу: UDP и WebSocket у одного клиента, запрос приходит по обоим; UDP замолчал — клиент в сети через WebSocket."""
    import socket
    loop = asyncio.get_running_loop()
    PID = "777888999"
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.setblocking(False); u.bind(("127.0.0.1", 0))
    srv = ("127.0.0.1", 21116)

    async def udp_recv(timeout=5):
        while True:
            data = await asyncio.wait_for(loop.sock_recv(u, 65535), timeout)
            m = pb.RendezvousMessage(); m.ParseFromString(data)
            if m.WhichOneof("union") != "register_peer_response":
                return m

    u.sendto(msg(register_peer=pb.RegisterPeer(id=PID, serial=0)), srv)
    u.sendto(msg(register_pk=pb.RegisterPk(id=PID, uuid=b"uuid-d", pk=b"D" * 32)), srv)
    m = await udp_recv(); assert m.WhichOneof("union") == "register_pk_response" and m.register_pk_response.result == pb.RegisterPkResponse.OK, m
    u.sendto(msg(register_peer=pb.RegisterPeer(id=PID, serial=0)), srv)
    async with websockets.connect(WS, extra_headers={"X-Real-IP": "127.0.0.1"}) as b:
        await b.send(msg(register_pk=pb.RegisterPk(id=PID, uuid=b"uuid-d", pk=b"D" * 32)))
        m, _ = await recv_msg(b); assert m.register_pk_response.result == pb.RegisterPkResponse.OK, m
        print("OK  два канала: зарегистрирован и по UDP, и через WebSocket")
        async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.9"}) as a:
            await a.send(msg(punch_hole_request=pb.PunchHoleRequest(id=PID, licence_key=KEY)))
            mu = await udp_recv(); assert mu.WhichOneof("union") in ("punch_hole", "fetch_local_addr"), mu
            mw, _ = await recv_msg(b); assert mw.WhichOneof("union") == mu.WhichOneof("union"), mw
            print("OK  два канала: запрос пришёл и по UDP, и в поток WebSocket")
        # UDP замолчал (клиент больше не шлёт RegisterPeer); поток отвечает на heartbeat 35 с
        end = loop.time() + 35
        while loop.time() < end:
            try:
                data = await asyncio.wait_for(b.recv(), max(0.1, end - loop.time()))
            except asyncio.TimeoutError:
                break
            if data == b"":
                await b.send(b"")
        async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.10"}) as a:
            await a.send(msg(punch_hole_request=pb.PunchHoleRequest(id=PID, licence_key=KEY)))
            mw, _ = await recv_msg(b, timeout=10)
            assert mw.WhichOneof("union") in ("punch_hole", "fetch_local_addr"), mw
            print("OK  два канала: UDP молчит 35 с, клиент в сети, запрос дошёл через WebSocket")
    u.close()


def frame(data):
    """Кадр hbb_common BytesCodec: длина << 2 в 1–4 байтах, младшие 2 бита — длина заголовка - 1."""
    n = len(data)
    if n <= 0x3F:
        head = (n << 2).to_bytes(1, "little")
    elif n <= 0x3FFF:
        head = ((n << 2) | 1).to_bytes(2, "little")
    elif n <= 0x3FFFFF:
        head = ((n << 2) | 2).to_bytes(3, "little")
    else:
        head = ((n << 2) | 3).to_bytes(4, "little")
    return head + data


async def read_frame(reader, timeout=5):
    b0 = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
    hl = (b0 & 3) + 1
    rest = await asyncio.wait_for(reader.readexactly(hl - 1), timeout) if hl > 1 else b""
    n = int.from_bytes(bytes([b0]) + rest, "little") >> 2
    return await asyncio.wait_for(reader.readexactly(n), timeout) if n else b""


async def kx_check():
    """Клиент, вошедший в консоль (secure_tcp): молчит, получает KeyExchange, дальше всё зашифровано.
    Клиент без входа шлёт запрос сразу и обмена не видит."""
    import base64
    from nacl.signing import VerifyKey
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.secret import SecretBox
    from nacl.utils import random as nrandom

    # без входа: запрос сразу, ответ открытым текстом, KeyExchange не приходит
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    w.write(frame(msg(punch_hole_request=pb.PunchHoleRequest(id="111222333", licence_key=KEY)))); await w.drain()
    m = pb.RendezvousMessage(); m.ParseFromString(await read_frame(r))
    assert m.WhichOneof("union") == "punch_hole_response", m
    assert m.punch_hole_response.failure == pb.PunchHoleResponse.ID_NOT_EXIST, m
    w.close()
    print("OK  TCP без входа: ответ сразу, без обмена ключами")

    # со входом: молчим, сервер присылает подписанный ключ
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    m = pb.RendezvousMessage(); m.ParseFromString(await read_frame(r, timeout=5))
    assert m.WhichOneof("union") == "key_exchange", m
    assert len(m.key_exchange.keys) == 1, m
    server_pk = VerifyKey(base64.b64decode(KEY)).verify(m.key_exchange.keys[0])
    assert len(server_pk) == 32 and server_pk[31] & 0x80 == 0, "ключ сервера без старшего бита"
    ours = PrivateKey.generate()
    sym = nrandom(SecretBox.KEY_SIZE)
    sealed = Box(ours, PublicKey(server_pk)).encrypt(sym, bytes(24)).ciphertext
    ke = pb.RendezvousMessage(); ke.key_exchange.keys.extend([bytes(ours.public_key), sealed])
    w.write(frame(ke.SerializeToString())); await w.drain()
    box = SecretBox(sym)
    nonce = lambda seq: seq.to_bytes(8, "little") + bytes(16)
    req = msg(punch_hole_request=pb.PunchHoleRequest(id="111222333", licence_key=KEY))
    w.write(frame(box.encrypt(req, nonce(1)).ciphertext)); await w.drain()
    data = await read_frame(r)
    m = pb.RendezvousMessage(); m.ParseFromString(box.decrypt(data, nonce(1)))
    assert m.WhichOneof("union") == "punch_hole_response", m
    assert m.punch_hole_response.failure == pb.PunchHoleResponse.ID_NOT_EXIST, m
    # второй запрос — со следующим номером, ответ тоже
    w.write(frame(box.encrypt(req, nonce(2)).ciphertext)); await w.drain()
    m = pb.RendezvousMessage(); m.ParseFromString(box.decrypt(await read_frame(r), nonce(2)))
    assert m.WhichOneof("union") == "punch_hole_response", m
    w.close()
    print("OK  TCP со входом: KeyExchange, запросы и ответы зашифрованы")

    # мусор вместо ответа на обмен: сервер не падает и обслуживает дальше
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    await read_frame(r, timeout=5)
    w.write(frame(b"garbage")); await w.drain(); w.close()
    r, w = await asyncio.open_connection("127.0.0.1", 21116)
    w.write(frame(msg(punch_hole_request=pb.PunchHoleRequest(id="111222333", licence_key=KEY)))); await w.drain()
    m = pb.RendezvousMessage(); m.ParseFromString(await read_frame(r))
    assert m.WhichOneof("union") == "punch_hole_response", m
    w.close()
    print("OK  мусор в обмене ключами не ломает сервер")


async def main():
    hb = {"seen": False}
    async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.2"}) as b:
        await b.send(msg(register_pk=pb.RegisterPk(id=PEER_ID, uuid=b"uuid-b", pk=b"P" * 32)))
        m, _ = await recv_msg(b)
        assert m.WhichOneof("union") == "register_pk_response", m
        assert m.register_pk_response.result == pb.RegisterPkResponse.OK, m
        print("OK  регистрация через WebSocket")

        async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.3"}) as a:
            await a.send(msg(punch_hole_request=pb.PunchHoleRequest(id=PEER_ID, licence_key=KEY)))
            m, _ = await recv_msg(b)
            kind = m.WhichOneof("union")
            assert kind in ("punch_hole", "fetch_local_addr"), m
            req = getattr(m, kind)
            print(f"OK  запрос на подключение доставлен в поток B ({kind})")
            await b.send(msg(relay_response=pb.RelayResponse(
                socket_addr=req.socket_addr, relay_server="relay.test:21117", id=PEER_ID, version="1.5.3")))
            m, _ = await recv_msg(a)
            assert m.WhichOneof("union") == "relay_response", m
            assert m.relay_response.relay_server == "relay.test:21117", m
            print("OK  ответ B доставлен A (RelayResponse)")

        async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.4"}) as c:
            await c.send(msg(punch_hole_request=pb.PunchHoleRequest(id="111222333", licence_key=KEY)))
            m, _ = await recv_msg(c)
            assert m.WhichOneof("union") == "punch_hole_response", m
            assert m.punch_hole_response.failure == pb.PunchHoleResponse.ID_NOT_EXIST, m
            print("OK  неизвестный ID по-прежнему ID_NOT_EXIST")

        data = await asyncio.wait_for(b.recv(), 20)
        assert data == b"", f"ожидался heartbeat, пришло {data!r}"
        await b.send(b"")
        print("OK  heartbeat получен и подтвержден")

        # 35 с, как настоящий клиент: отвечаем на каждый heartbeat (дольше 30 с REG_TIMEOUT)
        loop = asyncio.get_running_loop(); end = loop.time() + 35; beats = 0
        while loop.time() < end:
            try:
                data = await asyncio.wait_for(b.recv(), max(0.1, end - loop.time()))
            except asyncio.TimeoutError:
                break
            assert data == b"", f"неожиданное сообщение {data!r}"
            await b.send(b""); beats += 1
        assert beats >= 2, f"за 35 с пришло {beats} heartbeat"
        print(f"OK  за 35 с {beats} heartbeat, клиент отвечает")
        async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.5"}) as d:
            await d.send(msg(punch_hole_request=pb.PunchHoleRequest(id=PEER_ID, licence_key=KEY)))
            m, _ = await recv_msg(b, timeout=10)
            assert m.WhichOneof("union") in ("punch_hole", "fetch_local_addr"), m
            print("OK  через 35 с клиент онлайн, запросы доходят")

    await asyncio.sleep(1)
    async with websockets.connect(WS, extra_headers={"X-Real-IP": "10.0.0.6"}) as e:
        await e.send(msg(punch_hole_request=pb.PunchHoleRequest(id=PEER_ID, licence_key=KEY)))
        m, _ = await recv_msg(e, timeout=5)
        assert m.WhichOneof("union") == "punch_hole_response", m
        assert m.punch_hole_response.failure == pb.PunchHoleResponse.OFFLINE, m
        print("OK  после закрытия потока B сразу «не в сети» (OFFLINE)")
    await kx_check()
    await udp_check()
    await dual_check()
    print("ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")


asyncio.run(main())
