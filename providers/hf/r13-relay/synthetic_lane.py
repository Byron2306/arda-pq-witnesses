"""Deadline-bounded synthetic transport lane. Never authorizes real ingestion."""
import json
import time

MARKER="arda-r13.synthetic-transport-test.v1"
MAX_WINDOW=900

def deadline(env, *, now=None):
    if now is None: now=int(time.time())
    raw=env.get("ARDA_RELAY_TEST_UNTIL","")
    if not raw: return None
    if env.get("ARDA_RELAY_STANDBY_ONLY")!="1":
        raise RuntimeError("TEST_REQUIRES_STANDBY")
    try: until=int(raw)
    except ValueError: raise RuntimeError("INVALID_TEST_DEADLINE") from None
    if until<=now:
        return None  # expired window boots directly into ordinary standby
    if until>now+MAX_WINDOW:
        raise RuntimeError("TEST_DEADLINE_NOT_BOUNDED")
    return until

def active(until, *, now=None):
    if now is None: now=int(time.time())
    return until is not None and now<until

def synthetic_capture(raw):
    try: item=json.loads(raw)
    except (ValueError,TypeError): return False
    return (type(item) is dict and set(item)=={"schema","issued_challenge","evidence","receipt"}
            and item["schema"]=="arda.r13.capture.v2"
            and item["evidence"]=={}
            and item["receipt"]=={"test_only":MARKER})
