# -*- coding: utf-8 -*-
"""FamGate launcher. Usage:  python3 run.py"""
import os
import sys

import uvicorn

if __name__ == "__main__":
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=False)
    except Exception:
        pass

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    reload_ = os.environ.get("RELOAD", "0") == "1"
    # Port is bound to 127.0.0.1 only; behind Docker's bridge the peer is the
    # docker host (172.17.0.x), which must be trusted or X-Forwarded-Proto is ignored.
    uvicorn.run("app:app", host=host, port=port, reload=reload_, access_log=True,
                proxy_headers=True, forwarded_allow_ips="*")
