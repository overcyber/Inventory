from __future__ import annotations
import json, logging, os, re, shutil, subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from services.asset_core import generic_payload_to_state, ingest_observation, record_source_state, sync_netscope_assets

log=logging.getLogger('inventory.sources')
def env_bool(name,default=False):
    raw=os.getenv(name); return default if raw is None else raw.strip().lower() in {'1','true','yes','on','sim'}
def _json_env(name,default):
    try: return json.loads(os.getenv(name,json.dumps(default)) or json.dumps(default))
    except Exception: return default

@dataclass
class SourceResult:
    source:str; observed:int=0; errors:int=0; skipped:bool=False; detail:dict[str,Any]|None=None

class InventorySource(ABC):
    name='base'
    def enabled(self): return True
    def healthcheck(self): return {'ok':True}
    @abstractmethod
    def collect(self,app): raise NotImplementedError

class WazuhSource(InventorySource):
    name='wazuh'
    def enabled(self):
        host=(os.getenv('WAZUH_HOST') or '').strip()
        return env_bool('WAZUH_ENABLED',bool(host and host.upper() not in {'IP_WAZUH','CHANGEME'}))
    def collect(self,app):
        from utils.collector import _sync_wazuh_only
        r=_sync_wazuh_only(app) or {}
        return SourceResult(self.name,int(r.get('processed',0)),int(r.get('errors',0)),detail=r)

class NetScopeSource(InventorySource):
    name='netscope'
    def enabled(self): return env_bool('NETSCOPE_SOURCE_ENABLED',True)
    def collect(self,app):
        r=sync_netscope_assets(); return SourceResult(self.name,r['observed'],r['errors'],detail=r)

class OsquerySource(InventorySource):
    name='osquery'
    QUERIES={
      'system_info':'select * from system_info;','os_version':'select * from os_version;',
      'interface_addresses':'select * from interface_addresses;','interface_details':'select * from interface_details;',
      'listening_ports':'select * from listening_ports;','processes':'select pid,name,path,cmdline,uid,state from processes;',
      'users':'select * from users;','services':'select * from services;','deb_packages':'select * from deb_packages;',
      'rpm_packages':'select * from rpm_packages;','homebrew_packages':'select * from homebrew_packages;',
      'programs':'select * from programs;','patches':'select * from patches;',
      'chrome_extensions':'select * from chrome_extensions;','firefox_addons':'select * from firefox_addons;'}
    def enabled(self): return env_bool('OSQUERY_ENABLED',False)
    @staticmethod
    def _query(sql):
        binary=os.getenv('OSQUERY_BINARY','osqueryi')
        if not shutil.which(binary): raise RuntimeError(f'{binary} não encontrado')
        p=subprocess.run([binary,'--json',sql],capture_output=True,text=True,timeout=int(os.getenv('OSQUERY_TIMEOUT','45')))
        if p.returncode: raise RuntimeError(p.stderr.strip() or f'osquery rc={p.returncode}')
        return json.loads(p.stdout or '[]')
    def collect(self,app):
        raw={}; table_errors={}
        for name,sql in self.QUERIES.items():
            try: raw[name]=self._query(sql)
            except Exception as exc: raw[name]=[]; table_errors[name]=str(exc)
        system=(raw['system_info'] or [{}])[0]; osv=(raw['os_version'] or [{}])[0]
        details={str(x.get('interface')):x for x in raw['interface_details']}
        ips=[]; macs=[]; netaddr=[]; netiface=[]
        for row in raw['interface_addresses']:
            addr=str(row.get('address') or ''); iface=str(row.get('interface') or ''); d=details.get(iface,{})
            if addr and addr not in ('127.0.0.1','::1') and addr not in ips: ips.append(addr)
            mac=str(d.get('mac') or '')
            if mac and mac not in macs: macs.append(mac)
            netaddr.append({'iface':iface,'address':addr,'netmask':row.get('mask') or '',
                            'proto':'ipv6' if ':' in addr else 'ipv4','broadcast':row.get('broadcast') or ''})
        for iface,d in details.items():
            netiface.append({'name':iface,'mac':d.get('mac') or '',
                             'state':'up' if 'UP' in str(d.get('flags') or '') else '',
                             'mtu':d.get('mtu') or '','type':d.get('type') or ''})
        packages=[]
        for table in ('deb_packages','rpm_packages','homebrew_packages','programs'):
            for p in raw[table]:
                name=p.get('name') or p.get('package') or ''
                if name: packages.append({'name':name,'version':p.get('version') or '',
                    'architecture':p.get('arch') or p.get('architecture') or '','format':table.replace('_packages','')})
        extensions=list(raw['chrome_extensions'])+list(raw['firefox_addons'])
        machine_id=str(system.get('uuid') or system.get('hardware_serial') or system.get('hostname') or '')
        mem=str(system.get('physical_memory') or '')
        payload={'hostname':system.get('hostname') or system.get('computer_name') or '','ips':ips,'macs':macs,
          'serial':system.get('hardware_serial') or '','machine_id':machine_id,
          'os_name':osv.get('name') or osv.get('platform') or '','os_version':osv.get('version') or '',
          'cpu_name':system.get('cpu_brand') or '','ram_gb':round(int(mem)/(1024**3),2) if mem.isdigit() else 0,
          'network_status':'reachable','device_status':'Ativo','confidence':0.96,'packages':packages,
          'processes':raw['processes'],'services':raw['services'],'users':raw['users'],'hotfixes':raw['patches'],
          'browser_extensions':extensions,'ports':raw['listening_ports'],
          'inventory':{'netaddr':netaddr,'netiface':netiface,'ports':raw['listening_ports'],'processes':raw['processes'],
                       'packages':packages,'services':raw['services'],'users':raw['users'],'hotfixes':raw['patches'],
                       'browser_extensions':extensions}}
        ingest_observation(self.name,machine_id,{'tables':raw,'errors':table_errors},
                           generic_payload_to_state(payload,self.name,machine_id))
        return SourceResult(self.name,1,len(table_errors),detail={'host':payload['hostname'],'table_errors':table_errors})

def _snmp_auth(target):
    version=str(target.get('version') or '2c')
    if version in ('3','v3'):
        args=['-v3','-l',str(target.get('security_level') or 'authPriv'),'-u',str(target.get('username') or '')]
        if target.get('auth_protocol'): args += ['-a',str(target['auth_protocol'])]
        if target.get('auth_password'): args += ['-A',str(target['auth_password'])]
        if target.get('priv_protocol'): args += ['-x',str(target['priv_protocol'])]
        if target.get('priv_password'): args += ['-X',str(target['priv_password'])]
        return args
    return ['-v2c','-c',str(target.get('community') or 'public')]

class SNMPSource(InventorySource):
    name='snmp'
    OIDS={'sys_name':'1.3.6.1.2.1.1.5.0','sys_descr':'1.3.6.1.2.1.1.1.0','sys_location':'1.3.6.1.2.1.1.6.0',
          'if_descr':'1.3.6.1.2.1.2.2.1.2','if_phys':'1.3.6.1.2.1.2.2.1.6','if_status':'1.3.6.1.2.1.2.2.1.8',
          'dot1q_pvid':'1.3.6.1.2.1.17.7.1.4.5.1.1','fdb_address':'1.3.6.1.2.1.17.4.3.1.1',
          'fdb_port':'1.3.6.1.2.1.17.4.3.1.2',
          'bridge_ifindex':'1.3.6.1.2.1.17.1.4.1.2'}
    def enabled(self): return env_bool('SNMP_ENABLED',False)
    def _walk(self,target,oid):
        binary=os.getenv('SNMPWALK_BINARY','snmpwalk')
        if not shutil.which(binary): raise RuntimeError('snmpwalk não encontrado')
        cmd=[binary]+_snmp_auth(target)+['-On','-t',str(target.get('timeout',2)),'-r',str(target.get('retries',1)),str(target['host']),oid]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=int(target.get('command_timeout',20)))
        if p.returncode: raise RuntimeError(p.stderr.strip() or 'snmpwalk failed')
        out={}
        for line in p.stdout.splitlines():
            m=re.match(r'\.?([\d.]+)\s*=\s*(?:\w+:\s*)?(.*)$',line.strip())
            if m: out[m.group(1)]=m.group(2).strip().strip('"')
        return out
    @staticmethod
    def _mac_value(value):
        compact=re.sub(r'[^0-9A-Fa-f]','',str(value or ''))
        if len(compact)!=12:
            return ''
        return ':'.join(compact[i:i+2] for i in range(0,12,2)).lower()
    def _enrich_netscope(self,host,raw,indexes=None):
        try:
            from services.netscope_core import store, dev_key
            switch=store.find_by_ip(host,include_deleted=False)
            if not switch:
                return 0
            switch_key=dev_key(switch)
            fdb_ports=raw.get('fdb_port') or {}
            ifindexes=raw.get('bridge_ifindex') or {}
            pvids=raw.get('dot1q_pvid') or {}
            changed=0
            for oid,value in (raw.get('fdb_address') or {}).items():
                mac=self._mac_value(value)
                if not mac:
                    continue
                suffix=oid.split('1.3.6.1.2.1.17.4.3.1.1.',1)[-1]
                port_raw=next((v for k,v in fdb_ports.items() if k.endswith('.'+suffix)),None)
                try: bridge_port=int(re.sub(r'[^0-9]','',str(port_raw or '')))
                except ValueError: continue
                ifidx_raw=next((v for k,v in ifindexes.items() if k.endswith('.'+str(bridge_port))),None)
                try: ifidx=int(re.sub(r'[^0-9]','',str(ifidx_raw or bridge_port)))
                except ValueError: ifidx=bridge_port
                iface=(indexes or {}).get(str(ifidx),{})
                pvid_raw=next((v for k,v in pvids.items() if k.endswith('.'+str(bridge_port))), '')
                vlan=re.sub(r'[^0-9]','',str(pvid_raw or ''))
                dev=store.find(mac,include_deleted=False)
                if not dev or dev is switch:
                    continue
                dev['switch_port']={'switch_mac':switch_key,'port':bridge_port,
                                    'label':iface.get('name') or f'port-{bridge_port}',
                                    'vlan':vlan,'speed':'','duplex':''}
                changed+=1
            if changed:
                with store._lock:
                    store._flush()
            return changed
        except Exception:
            return 0
    def collect(self,app):
        observed=errors=0
        for target in _json_env('SNMP_TARGETS_JSON',[]):
            host=str(target.get('host') or '').strip()
            if not host: continue
            try:
                target={**target,'host':host}; raw={k:self._walk(target,oid) for k,oid in self.OIDS.items()}
                idxs={}
                for key,field in (('if_descr','name'),('if_phys','mac'),('if_status','state'),('dot1q_pvid','vlan')):
                    for oid,val in raw[key].items(): idxs.setdefault(oid.rsplit('.',1)[-1],{})[field]=val
                interfaces=[{'name':v.get('name',''),'mac':v.get('mac',''),'state':v.get('state',''),
                             'type':'snmp','vlan':v.get('vlan',''),'ifindex':k} for k,v in idxs.items()]
                payload={'hostname':next(iter(raw['sys_name'].values()),''),'ip':host,'ips':[host],
                         'macs':[x['mac'] for x in interfaces if x.get('mac')],'device_type':'network',
                         'network_status':'reachable','device_status':'Ativo','confidence':0.82,
                         'location':next(iter(raw['sys_location'].values()),''),
                         'inventory':{'netiface':interfaces,'snmp':raw,'fdb':{'address':raw['fdb_address'],'port':raw['fdb_port']}}}
                ingest_observation(self.name,host,raw,generic_payload_to_state(payload,self.name,host))
                self._enrich_netscope(host,raw,indexes=idxs)
                observed+=1
            except Exception as exc: app.logger.warning('[SNMP] %s: %s',host,exc); errors+=1
        return SourceResult(self.name,observed,errors)

def _run_ssh(client,cmd,timeout=20):
    _stdin,stdout,stderr=client.exec_command(cmd,timeout=timeout); rc=stdout.channel.recv_exit_status()
    return stdout.read().decode('utf-8','replace').strip(),rc,stderr.read().decode('utf-8','replace').strip()

class SSHSource(InventorySource):
    name='ssh'
    def enabled(self): return env_bool('SSH_SOURCE_ENABLED',False)
    def collect(self,app):
        import paramiko
        observed=errors=0
        for target in _json_env('SSH_TARGETS_JSON',[]):
            host=str(target.get('host') or '').strip()
            if not host: continue
            c=paramiko.SSHClient()
            if env_bool('SSH_STRICT_HOST_KEY',True): c.load_system_host_keys(); c.set_missing_host_key_policy(paramiko.RejectPolicy())
            else: c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                c.connect(hostname=host,port=int(target.get('port',22)),username=target.get('username'),
                          password=target.get('password'),key_filename=target.get('key_filename'),timeout=8,
                          banner_timeout=8,auth_timeout=8,allow_agent=bool(target.get('allow_agent',True)))
                cmds={'hostname':'hostname -f 2>/dev/null || hostname','machine_id':'cat /etc/machine-id 2>/dev/null || true',
                      'addresses':'ip -j addr 2>/dev/null || true','packages':'dpkg-query -W 2>/dev/null || rpm -qa 2>/dev/null || true',
                      'processes':'ps -eo pid,user,state,comm,args --no-headers 2>/dev/null || true',
                      'services':'systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null || true',
                      'users':'getent passwd 2>/dev/null || true','serial':'cat /sys/class/dmi/id/product_serial 2>/dev/null || true',
                      'ports':'ss -H -lntup 2>/dev/null || true','hotfixes':'(command -v needs-restarting >/dev/null && needs-restarting -r) 2>&1 || true'}
                raw={k:_run_ssh(c,v)[0] for k,v in cmds.items()}
                packages=[]
                for line in raw['packages'].splitlines():
                    p=line.split('\t'); name=p[0].strip() if p else ''
                    if name: packages.append({'name':name,'version':p[1] if len(p)>1 else '','format':'ssh'})
                processes=[]
                for line in raw['processes'].splitlines():
                    p=line.strip().split(None,4)
                    if len(p)>=4: processes.append({'pid':p[0],'euser':p[1],'state':p[2],'name':p[3],'cmd':p[4] if len(p)>4 else ''})
                services=[]
                for line in raw['services'].splitlines():
                    p=line.strip().split(None,4)
                    if p: services.append({'name':p[0],'state':p[2] if len(p)>2 else '','description':p[4] if len(p)>4 else ''})
                users=[{'name':x.split(':',1)[0],'raw':x} for x in raw['users'].splitlines() if x]
                ips=[]; macs=[]; netaddr=[]; netiface=[]
                try:
                    for iface in json.loads(raw['addresses'] or '[]'):
                        name=iface.get('ifname') or ''; mac=iface.get('address') or ''
                        if mac and len(mac)<=20: macs.append(mac)
                        netiface.append({'name':name,'mac':mac,'state':iface.get('operstate') or '','mtu':iface.get('mtu') or '','type':iface.get('link_type') or ''})
                        for ai in iface.get('addr_info') or []:
                            ip=ai.get('local') or ''
                            if ip and ip not in ('127.0.0.1','::1'): ips.append(ip)
                            netaddr.append({'iface':name,'address':ip,'netmask':str(ai.get('prefixlen') or ''),'proto':ai.get('family') or ''})
                except Exception: pass
                payload={'hostname':raw['hostname'],'ip':host,'ips':ips or [host],'macs':macs,'machine_id':raw['machine_id'],
                         'serial':raw['serial'],'network_status':'reachable','device_status':'Ativo','confidence':0.92,
                         'packages':packages,'processes':processes,'services':services,'users':users,
                         'hotfixes':[{'raw':raw['hotfixes']}] if raw['hotfixes'] else [],
                         'inventory':{'netiface':netiface,'netaddr':netaddr,'packages':packages,'processes':processes,
                                      'services':services,'users':users,'ssh_raw':raw}}
                ext=raw['machine_id'] or raw['serial'] or host
                ingest_observation(self.name,ext,raw,generic_payload_to_state(payload,self.name,ext)); observed+=1
            except Exception as exc: app.logger.warning('[SSH] %s: %s',host,exc); errors+=1
            finally: c.close()
        return SourceResult(self.name,observed,errors)

class WinRMSource(InventorySource):
    name='winrm'
    def enabled(self): return env_bool('WINRM_SOURCE_ENABLED',False)
    SCRIPT=r"""$cs=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem;$bios=Get-CimInstance Win32_BIOS;$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;$nic=Get-CimInstance Win32_NetworkAdapterConfiguration|Where-Object {$_.IPEnabled};$proc=Get-CimInstance Win32_Process|Select ProcessId,Name,ExecutablePath,CommandLine;$svc=Get-CimInstance Win32_Service|Select Name,State,StartMode,PathName;$users=Get-LocalUser -ErrorAction SilentlyContinue|Select Name,Enabled,LastLogon;$hot=Get-HotFix -ErrorAction SilentlyContinue|Select HotFixID,InstalledOn,Description;$ports=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Select LocalAddress,LocalPort,OwningProcess,State;$pkg=@();$roots=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*');foreach($r in $roots){$pkg+=Get-ItemProperty $r -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName}|Select DisplayName,DisplayVersion,Publisher,InstallDate};[pscustomobject]@{hostname=$env:COMPUTERNAME;serial=$bios.SerialNumber;machine_id=$cs.Name+'|'+$bios.SerialNumber;os_name=$os.Caption;os_version=$os.Version;architecture=$os.OSArchitecture;cpu_name=$cpu.Name;cpu_cores=$cpu.NumberOfCores;ram=$cs.TotalPhysicalMemory;network=@($nic);processes=@($proc);services=@($svc);users=@($users);hotfixes=@($hot);ports=@($ports);packages=@($pkg)}|ConvertTo-Json -Depth 7 -Compress"""
    def collect(self,app):
        import winrm
        observed=errors=0
        for target in _json_env('WINRM_TARGETS_JSON',[]):
            host=str(target.get('host') or '').strip()
            if not host: continue
            try:
                sess=winrm.Session(host,auth=(target.get('username'),target.get('password')),transport=target.get('transport','ntlm'),server_cert_validation=target.get('server_cert_validation','validate'))
                res=sess.run_ps(self.SCRIPT)
                if res.status_code!=0: raise RuntimeError(res.std_err.decode('utf-8','replace'))
                raw=json.loads(res.std_out.decode('utf-8','replace'))
                network=raw.get('network') or []; network=network if isinstance(network,list) else [network]
                ips=[]; macs=[]; netiface=[]; netaddr=[]
                for n in network:
                    mac=n.get('MACAddress') or ''; desc=n.get('Description') or ''
                    if mac: macs.append(mac)
                    for ip in n.get('IPAddress') or []:
                        if ip not in ('127.0.0.1','::1'): ips.append(ip)
                        netaddr.append({'iface':desc,'address':ip,'proto':'ipv6' if ':' in ip else 'ipv4'})
                    netiface.append({'name':desc,'mac':mac,'state':'up','type':'windows'})
                packages=[{'name':p.get('DisplayName') or '','version':p.get('DisplayVersion') or '','format':'windows-registry','description':p.get('Publisher') or ''} for p in (raw.get('packages') or []) if isinstance(p,dict)]
                processes=[{'pid':p.get('ProcessId'),'name':p.get('Name') or '','cmd':p.get('CommandLine') or p.get('ExecutablePath') or ''} for p in (raw.get('processes') or []) if isinstance(p,dict)]
                services=[{'name':x.get('Name') or '','state':x.get('State') or '','start_type':x.get('StartMode') or ''} for x in (raw.get('services') or []) if isinstance(x,dict)]
                ports=[{'local':{'ip':p.get('LocalAddress') or '','port':p.get('LocalPort')},'pid':p.get('OwningProcess'),'state':p.get('State') or 'Listen','protocol':'tcp'} for p in (raw.get('ports') or []) if isinstance(p,dict)]
                payload={'hostname':raw.get('hostname'),'ips':ips or [host],'macs':macs,'serial':raw.get('serial'),'machine_id':raw.get('machine_id'),
                         'os_name':raw.get('os_name'),'os_version':raw.get('os_version'),'cpu_name':raw.get('cpu_name'),
                         'ram_gb':round(int(raw.get('ram') or 0)/(1024**3),2),'network_status':'reachable','device_status':'Ativo','confidence':0.94,
                         'packages':packages,'processes':processes,'services':services,'users':raw.get('users') or [],
                         'hotfixes':raw.get('hotfixes') or [],'ports':ports,
                         'inventory':{'netiface':netiface,'netaddr':netaddr,'packages':packages,'processes':processes,'services':services,'users':raw.get('users') or [],'hotfixes':raw.get('hotfixes') or [],'ports':ports}}
                ext=str(raw.get('machine_id') or raw.get('serial') or host)
                ingest_observation(self.name,ext,raw,generic_payload_to_state(payload,self.name,ext)); observed+=1
            except Exception as exc: app.logger.warning('[WinRM] %s: %s',host,exc); errors+=1
        return SourceResult(self.name,observed,errors)

class WazuhIndexerSource(InventorySource):
    name='wazuh_indexer'
    def enabled(self): return env_bool('WAZUH_INDEXER_ENABLED',False)
    def collect(self,app):
        import requests
        base=(os.getenv('WAZUH_INDEXER_URL') or '').rstrip('/')
        if not base: raise RuntimeError('WAZUH_INDEXER_URL não configurada')
        sess=requests.Session(); sess.auth=(os.getenv('WAZUH_INDEXER_USER') or '',os.getenv('WAZUH_INDEXER_PASSWORD') or '')
        verify=env_bool('WAZUH_INDEXER_TLS_VERIFY',True); ca=(os.getenv('WAZUH_INDEXER_CA_BUNDLE') or '').strip()
        sess.verify=ca if verify and ca else verify
        size=max(1,min(int(os.getenv('WAZUH_INDEXER_PAGE_SIZE','1000')),5000)); max_docs=max(size,int(os.getenv('WAZUH_INDEXER_MAX_DOCS','500000')))
        resp=sess.post(base+'/wazuh-states-inventory-*/_search?scroll=2m',json={'size':size,'sort':['_doc']},timeout=45); resp.raise_for_status()
        data=resp.json(); scroll_id=data.get('_scroll_id'); hits=data.get('hits',{}).get('hits',[]); all_hits=[]; pages=0
        try:
            while hits and len(all_hits)<max_docs:
                all_hits.extend(hits[:max_docs-len(all_hits)]); pages+=1
                if len(hits)<size or not scroll_id or len(all_hits)>=max_docs: break
                resp=sess.post(base+'/_search/scroll',json={'scroll':'2m','scroll_id':scroll_id},timeout=45); resp.raise_for_status()
                data=resp.json(); scroll_id=data.get('_scroll_id') or scroll_id; hits=data.get('hits',{}).get('hits',[])
        finally:
            if scroll_id:
                try: sess.delete(base+'/_search/scroll',json={'scroll_id':[scroll_id]},timeout=10)
                except Exception: pass
        index_map={
          'hardware':'hardware','system':'os','packages':'packages','ports':'ports',
          'processes':'processes','networks':'netaddr','interfaces':'netiface',
          'protocols':'netproto','services':'services','users':'users','groups':'groups',
          'browser-extensions':'browser_extensions','hotfixes':'hotfixes'}
        cats=tuple(sorted(set(index_map.values())))
        grouped={}
        for hit in all_hits:
            src=hit.get('_source') or {}; agent=src.get('agent') or {}; aid=str(agent.get('id') or src.get('agent_id') or '')
            if not aid: continue
            bucket=grouped.setdefault(aid,{'agent':agent,'inventory':{k:[] for k in cats},'documents':[]})
            bucket['documents'].append({'index':hit.get('_index'),'source':src})
            idx=str(hit.get('_index') or '').lower()
            family=next((k for k in index_map if ('inventory-'+k+'-') in idx or idx.endswith('inventory-'+k)),None)
            if family: bucket['inventory'][index_map[family]].append(src)
        for aid,raw in grouped.items():
            agent=raw.get('agent') or {}; inv=raw['inventory']
            sysdoc=(inv.get('os') or [{}])[0] or {}; hostdoc=sysdoc.get('host') or {}
            hostos=hostdoc.get('os') or {}; agenthost=agent.get('host') or {}
            hostname=hostdoc.get('hostname') or agent.get('name') or ''
            ips=[]; macs=[]; netaddr=[]; netiface=[]
            for doc in inv.get('netaddr') or []:
                network=doc.get('network') or {}; iface=network.get('interface') or {}
                addr=network.get('address') or network.get('ip') or {}
                values=[]
                if isinstance(addr,str): values=[addr]
                elif isinstance(addr,dict):
                    values=[addr.get('ip') or addr.get('address') or '']
                for ip in values:
                    if ip and ip not in ('127.0.0.1','::1'):
                        ips.append(ip); netaddr.append({'iface':iface.get('name') or '',
                            'address':ip,'netmask':addr.get('netmask') if isinstance(addr,dict) else '',
                            'proto':'ipv6' if ':' in ip else 'ipv4'})
            for doc in inv.get('netiface') or []:
                network=doc.get('network') or {}; iface=network.get('interface') or {}
                mac=iface.get('mac') or iface.get('mac_address') or ''
                if mac: macs.append(mac)
                netiface.append({'name':iface.get('name') or '','mac':mac,
                    'state':iface.get('state') or iface.get('status') or '',
                    'mtu':iface.get('mtu') or '','type':iface.get('type') or ''})
            agent_ip=agenthost.get('ip') or agent.get('ip')
            if isinstance(agent_ip,list): ips.extend([x for x in agent_ip if x])
            elif agent_ip and agent_ip not in ips: ips.append(agent_ip)
            packages=[]
            for doc in inv.get('packages') or []:
                p=doc.get('package') or {}
                packages.append({'name':p.get('name') or doc.get('name') or '',
                    'version':p.get('version') or doc.get('version') or '',
                    'architecture':p.get('architecture') or agenthost.get('architecture') or '',
                    'format':p.get('type') or p.get('format') or ''})
            ports=[]
            for doc in inv.get('ports') or []:
                network=doc.get('network') or {}; transport=network.get('transport') or {}
                process=doc.get('process') or {}
                local=network.get('local') or {}
                port=local.get('port') or network.get('port') or doc.get('port')
                ip=local.get('ip') or ''
                ports.append({'local':{'port':port,'ip':ip},'process':process.get('name') or '',
                    'pid':process.get('pid') or '','state':network.get('state') or doc.get('state') or '',
                    'protocol':transport.get('protocol') or network.get('protocol') or ''})
            processes=[]
            for doc in inv.get('processes') or []:
                p=doc.get('process') or {}
                user=p.get('user') or {}
                processes.append({'pid':p.get('pid') or doc.get('pid'),'name':p.get('name') or doc.get('name') or '',
                    'state':p.get('state') or doc.get('state') or '',
                    'euser':user.get('name') if isinstance(user,dict) else user,
                    'cmd':p.get('command_line') or p.get('executable') or ''})
            hardware=(inv.get('hardware') or [{}])[0] or {}; hw=hardware.get('host') or hardware
            cpu=hw.get('cpu') or {}; mem=hw.get('memory') or hw.get('ram') or {}
            legacy_hw={'board_serial':hw.get('serial_number') or hw.get('serial') or '',
                       'cpu':{'name':cpu.get('name') or cpu.get('model') or '',
                              'cores':cpu.get('cores') or cpu.get('core_count') or ''},
                       'ram':{'total':mem.get('total') or 0,'usage':mem.get('usage') or ''}}
            legacy_os={'hostname':hostname,'architecture':hostdoc.get('architecture') or agenthost.get('architecture') or '',
                       'release':((hostos.get('kernel') or {}).get('release') if isinstance(hostos.get('kernel'),dict) else ''),
                       'os':{'name':hostos.get('name') or '','version':hostos.get('version') or '',
                             'codename':hostos.get('codename') or '','platform':hostos.get('platform') or ''}}
            normalized_inv={'hardware':[legacy_hw],'os':[legacy_os],'packages':packages,'ports':ports,
                            'processes':processes,'netaddr':netaddr,'netiface':netiface,
                            'netproto':inv.get('netproto') or [],'services':inv.get('services') or [],
                            'users':inv.get('users') or [],'groups':inv.get('groups') or [],
                            'browser_extensions':inv.get('browser_extensions') or [],
                            'hotfixes':inv.get('hotfixes') or []}
            payload={'hostname':hostname,'ips':list(dict.fromkeys(ips)),'macs':list(dict.fromkeys(macs)),
                     'wazuh_agent_id':aid,'os_name':hostos.get('name') or '',
                     'os_version':hostos.get('version') or '','network_status':'unknown',
                     'agent_status':'unknown','device_status':'Desconhecido',
                     'confidence':0.98,'packages':packages,'processes':processes,'ports':ports,
                     'services':inv.get('services') or [],'users':inv.get('users') or [],
                     'hotfixes':inv.get('hotfixes') or [],
                     'browser_extensions':inv.get('browser_extensions') or [],
                     'inventory':normalized_inv}
            state=generic_payload_to_state(payload,self.name,aid); state['wazuh_agent_id']=aid
            ingest_observation(self.name,aid,raw,state)
        return SourceResult(self.name,len(grouped),0,detail={'hits':len(all_hits),'pages':pages})

SOURCES=[WazuhSource,NetScopeSource,OsquerySource,SNMPSource,SSHSource,WinRMSource,WazuhIndexerSource]
def sync_configured_sources(app):
    summary={}
    for cls in SOURCES:
        src=cls(); enabled=False
        try:
            enabled=src.enabled()
            if not enabled: record_source_state(src.name,enabled=False,status='disabled',success=False); summary[src.name]={'skipped':True}; continue
            result=src.collect(app); payload={'observed':result.observed,'errors':result.errors,'skipped':result.skipped,'detail':result.detail or {}}
            summary[src.name]=payload; record_source_state(src.name,enabled=True,status='ok' if not result.errors else 'partial',metadata=payload,success=True)
        except Exception as exc:
            try: record_source_state(src.name,enabled=enabled,status='error',error=str(exc),success=False)
            except Exception: pass
            app.logger.exception('[Source:%s] %s',src.name,exc); summary[src.name]={'error':str(exc)}
    return summary
