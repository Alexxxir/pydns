#!/usr/bin/python3

import socket
import argparse
from dns_server import DNSServer
import subprocess
import os
import sys


def _create_parser():
    parser = argparse.ArgumentParser(
        description="Кэширующий DNS сервер.")
    parser.add_argument("asked_server", nargs="?",
                        default="77.88.8.8")
    parser.add_argument("-c", "--clear_cache", action="store_true",
                        help="Отчищает кэш")
    return parser.parse_args()


if __name__ == '__main__':
    parser = _create_parser()
    if os.getuid() != 0:
        try:
            subprocess.call(["sudo", "python3", *sys.argv])
        except PermissionError:
            pass
        finally:
            sys.exit(0)
    if parser.clear_cache:
        DNSServer.clear_cache()
        sys.exit(0)
    try:
        print("Сервер запущен")
        DNSServer("localhost", 53, parser.asked_server).run()
    except KeyboardInterrupt:
        pass
    finally:
        print("Сервер остановлен")
