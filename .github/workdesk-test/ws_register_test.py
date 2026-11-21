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
    await udp_check()
    print("ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")


asyncio.run(main())
