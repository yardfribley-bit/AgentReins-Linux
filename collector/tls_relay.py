#!/usr/bin/env python3
"""Optional opaque TCP relay; preserves end-to-end TLS without reading credentials."""
import os
import socket
import threading


def pump(source, destination):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        for conn in (source, destination):
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()


def handle(client, host, port, idle_timeout):
    try:
        remote = socket.create_connection((host, port), timeout=15)
        # create_connection retains its timeout on the connected socket.
        # Model generation may take longer than connection establishment.
        remote.settimeout(idle_timeout)
        client.settimeout(idle_timeout)
    except OSError:
        client.close()
        return
    threading.Thread(target=pump, args=(client, remote), daemon=True).start()
    threading.Thread(target=pump, args=(remote, client), daemon=True).start()


def main():
    host = os.environ['AGENTREINS_RELAY_UPSTREAM_HOST']
    port = int(os.environ.get('AGENTREINS_RELAY_UPSTREAM_PORT', '443'))
    idle = float(os.environ.get('AGENTREINS_RELAY_IDLE_TIMEOUT', '660'))
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((os.environ.get('AGENTREINS_RELAY_BIND', '127.0.0.1'),
                     int(os.environ.get('AGENTREINS_RELAY_PORT', '18443'))))
        server.listen(128)
        while True:
            client, _ = server.accept()
            threading.Thread(target=handle, args=(client, host, port, idle), daemon=True).start()


if __name__ == '__main__':
    main()
