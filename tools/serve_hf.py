#!/usr/bin/env python3
"""Start the fixed HF witness only after operator enrollment is complete."""
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.provider_runtime import load_runtime
from arda_quorum.provider_http import make_server

def main():
    try:
        witness=load_runtime('hf');server=make_server(witness,os.environ.get('ARDA_HF_CLIENT_TOKEN'))
    except Exception:
        print('HF_WITNESS_NOT_ENROLLED_OR_NOT_CONFIGURED',file=sys.stderr);return 1
    try:server.serve_forever()
    finally:server.server_close()
if __name__=='__main__':raise SystemExit(main())
