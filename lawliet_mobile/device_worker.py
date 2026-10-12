"""Persistent local JSON-lines bridge; EOF/parent exit stops owned scrcpy."""
import json
import os
import select
import signal
import sys
import time
from .device_interaction import InteractionService


def main():
    service = InteractionService(sys.argv[1])
    def shutdown(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    parent = os.getppid()
    buffer = b''
    next_refresh = 0
    try:
        while os.getppid() == parent:
            if (len(sys.argv)<3 or sys.argv[2]!='ios') and time.monotonic() >= next_refresh:
                service.refresh()
                next_refresh = time.monotonic() + 3
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
            if not ready:
                continue
            chunk = os.read(sys.stdin.fileno(), 4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 65536:
                raise ValueError('Interaction request too large.')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                try:
                    request=json.loads(line)
                    if request.get('action')=='ios-status':
                        from .iphone_connection import discover
                        result=discover(sys.argv[1]);result['audit_path']=str(service.audit.path)
                    elif request.get('action')=='ios-info':
                        from .iphone_connection import describe
                        result=describe(sys.argv[1],request.get('serial'))
                        service.audit.record('iphone.connection_checked',serial=result['serial'],trust=result['trust'])
                        result['audit_path']=str(service.audit.path)
                    elif request.get('action')=='ios-audit':
                        event=request.get('event')
                        if event not in {'screen.start_requested','screen.first_frame','screen.stopped','screen.closed'}:
                            raise ValueError('Unsupported iPhone audit event.')
                        fields={k:request.get(k,'') for k in ('serial','capture_source')}
                        if any(not isinstance(v,str) or len(v)>512 for v in fields.values()):raise ValueError('Invalid iPhone audit fields.')
                        service.audit.record('iphone.'+event,**fields)
                        result={'audit_path':str(service.audit.path)}
                    else:
                        result = service.handle(request)
                    reply = {'ok': True, 'result': result}
                except Exception as exc:
                    service.audit.record('interaction.error', error=str(exc))
                    reply = {'ok': False, 'error': str(exc)}
                print(json.dumps(reply), flush=True)
    finally:
        service.close()


if __name__ == '__main__':
    main()
