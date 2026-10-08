#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, platform, shutil, socket, ssl, subprocess, time, urllib.request, uuid
from pathlib import Path

def run(cmd,timeout=20):
    try:
        p=subprocess.run(cmd,shell=isinstance(cmd,str),capture_output=True,text=True,timeout=timeout)
        return p.stdout.strip() if p.returncode==0 else ''
    except Exception: return ''

def osquery(sql):
    binary=os.getenv('OSQUERY_BINARY','osqueryi')
    if not shutil.which(binary): return []
    out=run([binary,'--json',sql],30)
    try: return json.loads(out or '[]')
    except Exception: return []

def machine_id():
    for p in ('/etc/machine-id','/var/lib/dbus/machine-id'):
        try:
            v=Path(p).read_text().strip()
            if v: return v
        except Exception: pass
    serial=run('wmic bios get serialnumber /value') if os.name=='nt' else run('cat /sys/class/dmi/id/product_uuid 2>/dev/null')
    if serial: return hashlib.sha256(serial.encode()).hexdigest()
    return str(uuid.getnode())

def native_packages():
    if os.name=='nt': return []
    out=run("dpkg-query -W 2>/dev/null || rpm -qa 2>/dev/null",30)
    rows=[]
    for line in out.splitlines():
        p=line.split('\t')
        if p and p[0]: rows.append({'name':p[0],'version':p[1] if len(p)>1 else '','format':'native-agent'})
    return rows[:20000]

def collect():
    oq_sys=osquery('select * from system_info;'); oq_os=osquery('select * from os_version;')
    oq_addr=osquery('select * from interface_addresses;'); oq_if=osquery('select * from interface_details;')
    oq_ports=osquery('select * from listening_ports;'); oq_proc=osquery('select pid,name,path,cmdline,uid,state from processes;')
    packages=[]
    for q in ('select * from deb_packages;','select * from rpm_packages;','select * from programs;','select * from homebrew_packages;'):
        packages.extend(osquery(q))
    if not packages: packages=native_packages()
    services=osquery('select * from services;'); users=osquery('select * from users;'); patches=osquery('select * from patches;')
    sys=(oq_sys or [{}])[0]; osv=(oq_os or [{}])[0]
    hostname=sys.get('hostname') or socket.gethostname(); mid=sys.get('uuid') or machine_id(); serial=sys.get('hardware_serial') or ''
    macs=[]; ips=[]
    for x in oq_if:
        m=x.get('mac')
        if m and m not in macs: macs.append(m)
    if not macs:
        n=uuid.getnode(); macs=[':'.join(f'{(n>>i)&0xff:02x}' for i in range(40,-1,-8))]
    for x in oq_addr:
        ip=x.get('address')
        if ip and ip not in ('127.0.0.1','::1') and ip not in ips: ips.append(ip)
    return {'source':'inventory_agent','external_id':str(mid),
      'data':{'collected_by':'inventory_agent','platform':platform.platform()},
      'normalized':{'hostname':hostname,'machine_id':str(mid),'serial':serial,'macs':macs,'ips':ips,
        'os_name':osv.get('name') or platform.system(),'os_version':osv.get('version') or platform.version(),
        'cpu_name':sys.get('cpu_brand') or platform.processor(),'network_status':'reachable','device_status':'Ativo',
        'confidence':0.97,'packages':packages,'processes':oq_proc,'services':services,'users':users,'hotfixes':patches,
        'ports':oq_ports,'inventory':{'netaddr':oq_addr,'netiface':oq_if,'ports':oq_ports,'processes':oq_proc,
                                      'packages':packages,'services':services,'users':users,'hotfixes':patches}}}

def ssl_context():
    ca=os.getenv('INVENTORY_CA_BUNDLE'); ctx=ssl.create_default_context(cafile=ca if ca else None)
    cert=os.getenv('INVENTORY_CLIENT_CERT'); key=os.getenv('INVENTORY_CLIENT_KEY')
    if cert: ctx.load_cert_chain(cert,keyfile=key or None)
    return ctx

def send(payload):
    base=os.environ['INVENTORY_URL'].rstrip('/'); token=os.environ['INVENTORY_TOKEN']
    data=json.dumps(payload,separators=(',',':'),default=str).encode()
    req=urllib.request.Request(base+'/api/v1/assets/observations',data=data,method='POST',
      headers={'Content-Type':'application/json','Authorization':'Bearer '+token,'User-Agent':'inventory-agent/1.0'})
    with urllib.request.urlopen(req,context=ssl_context(),timeout=int(os.getenv('INVENTORY_TIMEOUT','20'))) as r:
        return r.status,json.loads(r.read().decode() or '{}')

def main():
    interval=max(60,int(os.getenv('INVENTORY_INTERVAL','3600'))); once=os.getenv('INVENTORY_ONCE','false').lower() in ('1','true','yes')
    while True:
        try:
            status,body=send(collect()); print(json.dumps({'status':status,'response':body}))
        except Exception as exc: print(json.dumps({'error':str(exc)}))
        if once: break
        time.sleep(interval)
if __name__=='__main__': main()
