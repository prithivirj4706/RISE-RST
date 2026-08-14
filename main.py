#!/usr/bin/env python3
"""SentinelAudit entrypoint.

    python main.py --target local
    python main.py --target audit@10.0.0.5 --key ~/.ssh/audit_ed25519
    python main.py --target docker://vulnerable-ubuntu
    python main.py --target local --reaudit
"""

import sys

from sentinelaudit.cli import main

if __name__ == "__main__":
    sys.exit(main())
