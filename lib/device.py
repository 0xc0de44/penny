#!/usr/bin/python3

from port import Port
from vulnerability import Vulnerability

class Device:
    def __init__(self, ip, os=None, version=None):
        self.ip = ip
        self.os = os
        self.version = version
        self.ports = {}

    def addPort(self, port):
        self.ports[port.number] = port

    def print(self):
        print(f"Host {self.ip}")
        print(f"OS fingerprint: {self.os} - {self.version}")
        if not len(self.ports):
            print(f"Ports: none")
            return
        print(f"Ports: ")
        for p in self.ports.values():
            p.print()


if __name__ == "__main__":
    print(f"### device.py example ###\n")

    d=Device("127.0.0.1", "Windows 10", "Build 1901")

    p = Port(25, "tcp")
    p.service = "smtp"
    p.software = "postfix"
    p.version = "2.13"
    v = Vulnerability()
    v.software = p.software
    v.version = p.version
    v.type = "RCE"
    v.description = "sample RCE desc"
    v.addExploit("https://cve.truc/exp1")
    v.addExploit("https://cve.truc/exp2")
    p.addVuln(v)

    d.addPort(p)

    d.print()