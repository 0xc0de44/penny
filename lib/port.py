#!/usr/bin/python3

from vulnerability import Vulnerability

from colorama import *


class Port:
    def __init__(self, number, proto=None):
        self.number = number
        self.proto = proto
        self.service=None
        self.software=None
        self.version=None
        self.vulns = []
        init(convert=True)

    def addVuln(self, vuln):
        self.vulns.append(vuln)

    def print(self):
        print(f"{self.number} - {self.proto}")
        if not self.service:
            print(f" * Service: unknown")
            return
        print(f" * Service: {self.service} | {self.software} {self.version}")
        if not self.vulns:
            print(f" * Vulnerabilities: unknown")
            return
        print(f"{Style.BRIGHT}{Fore.RED} * Vulnerabilities: YES{Style.NORMAL}{Fore.RESET}")
        for v in self.vulns:
            print(f" * * [{v.type}] {v.description}")
            if not v.exploits():
                print(f" * * * No exploits")
                continue
            for e in v.exploits():
                print(f" * * * {e}")


if __name__ == "__main__":
    print(f"### port.py example ###\n")
    p=Port(25, "tcp")
    p.service="smtp"
    p.software="postfix"
    p.version="2.13"
    v=Vulnerability()
    v.software=p.software
    v.version = p.version
    v.type = "RCE"
    v.description = "sample RCE desc"
    v.addExploit("https://cve.truc/exp1")
    v.addExploit("https://cve.truc/exp2")
    p.addVuln(v)
    p.print()
