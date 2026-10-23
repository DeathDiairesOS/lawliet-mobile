"""Bounded USB iPhone discovery and pairing validation; never pairs or collects."""
import re
import subprocess
import shutil
import os
from pathlib import Path
from .core import UserError
from .tools import command, configuration

def tool_executable(name):
    """Resolve installed libimobiledevice utilities even from a GUI PATH."""
    if name not in {"idevice_id","ideviceinfo","idevicepair"}:return None
    found=shutil.which(name)
    if found:return found
    return next((str(p) for base in ("/opt/homebrew/bin","/usr/local/bin","/usr/bin") if (p:=Path(base)/name).is_file() and os.access(p,os.X_OK)),None)

UDID=re.compile(r'(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})\Z')

USB_TRANSPORT_OVERRIDES = (
    'USBMUXD_SOCKET_ADDRESS', 'PYMOBILEDEVICE3_USBMUX',
    'PYMOBILEDEVICE3_TUNNEL', 'PYMOBILEDEVICE3_USERSPACE',
    'PYMOBILEDEVICE3_NATIVE', 'PYMOBILEDEVICE3_FORCE_TUNNEL',
    'PYMOBILEDEVICE3_DEFAULT_FALLBACK', 'PYMOBILEDEVICE3_RECONNECT_ANY',
)

def require_local_usb_environment():
    """Refuse inherited transport/device-switch overrides, without logging values.

    libusbmuxd accepts a remote socket through USBMUXD_SOCKET_ADDRESS. The pinned
    pymobiledevice3 CLI additionally prioritizes a tunnel over its explicit UDID.
    This route supports the default local USB service only. Never mutate the
    process environment shared with other GUI workers.
    """
    present = [name for name in USB_TRANSPORT_OVERRIDES if os.environ.get(name)]
    if present:
        raise UserError('USB iPhone collection cannot use transport overrides. Unset these variables '
                        'in the environment that launches LAWLIET, then restart it: ' + ', '.join(present))

def run(argv,runner=subprocess.run):
    try:result=runner(argv,capture_output=True,text=True,timeout=5)
    except subprocess.TimeoutExpired:raise UserError('iPhone connection check timed out. Unlock the phone and retry.')
    except OSError:raise UserError('iPhone connection utility could not start.')
    if len(result.stdout)>65536 or len(result.stderr)>65536:raise UserError('iPhone connection response exceeds the review limit.')
    return result

def discover(workspace,runner=subprocess.run):
    require_local_usb_environment()
    try:argv=command(workspace,'idevice_id')
    except UserError:
        if configuration(workspace).get('idevice_id'):raise
        binary=tool_executable('idevice_id')
        if not binary:raise UserError('libimobiledevice USB discovery is unavailable. Configure idevice_id or install libimobiledevice.')
        argv=[binary]
    result=run(argv+['-l'],runner)
    if result.returncode:raise UserError('USB iPhone discovery failed. Check the cable and unlock the phone.')
    ids=list(dict.fromkeys(x.strip() for x in result.stdout.splitlines() if x.strip()))
    if len(ids)>16 or any(not UDID.fullmatch(x) for x in ids):raise UserError('Unexpected USB iPhone identifiers.')
    return {'devices':[{'serial':x,'platform':'ios','status':'connected'} for x in ids]}

def describe(workspace,serial,runner=subprocess.run):
    if not isinstance(serial,str) or not UDID.fullmatch(serial):raise UserError('Select a USB iPhone identifier from discovery.')
    if serial not in [d['serial'] for d in discover(workspace,runner)['devices']]:raise UserError('The selected iPhone is no longer connected.')
    info=tool_executable('ideviceinfo');pair=tool_executable('idevicepair')
    device={'serial':serial,'platform':'ios','status':'connected','model':'','version':'','name':'','trust':'not_checked'}
    if not info:device['error']='ideviceinfo is unavailable; USB detection succeeded.'
    else:
        errors=[]
        for key,field in [('ProductType','model'),('ProductVersion','version'),('DeviceName','name')]:
            value=run([info,'-u',serial,'-k',key],runner)
            if value.returncode:errors.append('Unlock the iPhone and approve Trust on the phone to read device information.')
            else:device[field]=value.stdout.strip()[:256]
        if errors:device['error']=errors[0]
    if pair:
        value=run([pair,'-u',serial,'validate'],runner)
        device['trust']='trusted' if value.returncode==0 else 'trust_required'
    return device
