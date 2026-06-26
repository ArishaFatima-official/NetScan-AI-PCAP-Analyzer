#!/usr/bin/env python3
"""
NetScan — PCAP Security Dashboard Generator
Usage: python3 pcap_analyzer_v2.py <your_file.pcap>
Output: pcap_report/dashboard.html  ← open in browser!
"""
import sys, os, warnings, base64
from io import BytesIO
from collections import defaultdict, Counter
from datetime import datetime
warnings.filterwarnings("ignore")

def check_dep(name, install):
    try: __import__(name)
    except ImportError:
        print(f"❌  Missing: {name}\n   Install: pip install {install}"); sys.exit(1)

check_dep("scapy","scapy"); check_dep("matplotlib","matplotlib")
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Ether, DNS
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BG="#060810";BG2="#0c0f1a";BG3="#111627";BORDER="#1e2540"
ACCENT="#00e5ff";GREEN="#00ff9d";YELLOW="#ffcc00";RED="#ff3d5a"
ORANGE="#ff7e36";PURPLE="#a78bfa";TEXT="#dde3f5";TEXT2="#7b87aa";TEXT3="#3d4a6b"
PC={"TCP":ACCENT,"UDP":ORANGE,"ICMP":GREEN,"ARP":RED,"DNS":PURPLE,"Other":TEXT2}
def pc(p): return PC.get(p,TEXT2)

def parse_pcap(path):
    print(f"\n📂  Loading: {path}")
    pkts=rdpcap(path); print(f"    → {len(pkts)} packets"); return pkts

def extract(packets):
    records,t0=[],None
    for i,pkt in enumerate(packets):
        ts=float(pkt.time)
        if t0 is None: t0=ts
        r=dict(num=i+1,ts=round(ts-t0,6),size=len(pkt),proto="Other",
               src="—",dst="—",ttl="—",flags="",src_port=None,dst_port=None,
               icmp_type=-1,icmp_code=-1,info="")
        if pkt.haslayer(ARP):
            a=pkt[ARP]; r["proto"]="ARP"; r["src"]=a.psrc; r["dst"]=a.pdst
            r["info"]=f"who-has {a.pdst}?" if a.op==1 else f"{a.psrc} is-at {a.hwsrc}"
        if pkt.haslayer(IP):
            ip=pkt[IP]; r["src"]=ip.src; r["dst"]=ip.dst; r["ttl"]=ip.ttl
            if pkt.haslayer(ICMP):
                ic=pkt[ICMP]; r["proto"]="ICMP"; r["icmp_type"]=ic.type; r["icmp_code"]=ic.code
                nm={0:"Echo Reply",3:"Dest Unreachable",8:"Echo Request",11:"TTL Exceeded",5:"Redirect"}
                r["info"]=f"{nm.get(ic.type,f'Type {ic.type}')} seq={getattr(ic,'seq',0)}"
            elif pkt.haslayer(TCP):
                t=pkt[TCP]; r["proto"]="TCP"; r["src_port"]=t.sport; r["dst_port"]=t.dport
                fs=[f for f,b in [("SYN",t.flags.S),("ACK",t.flags.A),("FIN",t.flags.F),("RST",t.flags.R),("PSH",t.flags.P)] if b]
                r["flags"]=",".join(fs); r["info"]=f"{t.sport}→{t.dport} [{r['flags'] or '—'}]"
                if pkt.haslayer(DNS): r["proto"]="DNS"
            elif pkt.haslayer(UDP):
                u=pkt[UDP]; r["proto"]="UDP"; r["src_port"]=u.sport; r["dst_port"]=u.dport
                r["info"]=f"{u.sport}→{u.dport} len={u.len}"
                if pkt.haslayer(DNS): r["proto"]="DNS"
        records.append(r)
    return records

def setup_mpl():
    plt.rcParams.update({"figure.facecolor":BG2,"axes.facecolor":BG3,"axes.edgecolor":BORDER,
        "axes.labelcolor":TEXT3,"axes.titlecolor":TEXT,"axes.titlesize":11,"axes.titleweight":"bold",
        "axes.titlepad":12,"axes.grid":True,"grid.color":BORDER,"grid.linewidth":0.5,
        "text.color":TEXT2,"xtick.color":TEXT3,"ytick.color":TEXT3,"xtick.labelsize":8,
        "ytick.labelsize":8,"legend.facecolor":BG3,"legend.edgecolor":BORDER,"legend.labelcolor":TEXT2,
        "legend.fontsize":8,"font.family":"monospace","figure.dpi":120})

def fig_b64(fig):
    buf=BytesIO(); fig.savefig(buf,format="png",bbox_inches="tight",facecolor=fig.get_facecolor(),dpi=130)
    plt.close(fig); return base64.b64encode(buf.getvalue()).decode()

def chart_timeline(records):
    dur=records[-1]["ts"] if len(records)>1 else 1
    bucket=max(0.05,dur/80)
    bins=Counter(round(int(r["ts"]/bucket)*bucket,3) for r in records)
    x=sorted(bins); y=[bins[k] for k in x]
    fig,ax=plt.subplots(figsize=(9,3))
    ax.bar(x,y,width=bucket*0.85,color=ACCENT,alpha=0.7,linewidth=0)
    ax.fill_between(x,y,alpha=0.12,color=ACCENT,step="mid")
    ax.set_title("TRAFFIC TIMELINE — packets per time bucket")
    ax.set_xlabel("Time (seconds)"); ax.set_ylabel("Packets")
    fig.tight_layout(pad=1.5); return fig_b64(fig)

def chart_pie(records):
    cnt=Counter(r["proto"] for r in records)
    labs=list(cnt.keys()); vals=list(cnt.values()); cols=[pc(l) for l in labs]
    fig,ax=plt.subplots(figsize=(4.5,3.5))
    ax.set_facecolor(BG2); fig.set_facecolor(BG2)
    wedges,texts,auto=ax.pie(vals,labels=labs,colors=cols,autopct=lambda p:f"{p:.1f}%" if p>3 else "",
        startangle=140,wedgeprops={"linewidth":2,"edgecolor":BG2},pctdistance=0.8,
        textprops={"color":TEXT2,"fontsize":8})
    for t in auto: t.set_color(TEXT); t.set_fontsize(7)
    ax.set_title("PROTOCOL DISTRIBUTION")
    fig.tight_layout(pad=1); return fig_b64(fig)

def chart_sizes(records):
    groups=defaultdict(lambda:([],[]))
    for r in records: groups[r["proto"]][0].append(r["ts"]); groups[r["proto"]][1].append(r["size"])
    fig,ax=plt.subplots(figsize=(5.5,3.2))
    for proto,(xs,ys) in groups.items(): ax.scatter(xs,ys,c=pc(proto),s=6,alpha=0.6,label=proto,linewidths=0)
    ax.set_title("PACKET SIZES OVER TIME"); ax.set_xlabel("Time (s)"); ax.set_ylabel("Bytes")
    ax.legend(loc="upper right",markerscale=2); fig.tight_layout(pad=1.5); return fig_b64(fig)

def chart_talkers(records):
    cnt=Counter(r["src"] for r in records if r["src"]!="—")
    top=cnt.most_common(8)
    if not top: return None
    ips=[t[0] for t in top][::-1]; vals=[t[1] for t in top][::-1]
    pal=[ACCENT,GREEN,ORANGE,PURPLE,RED,YELLOW,ACCENT,GREEN]
    fig,ax=plt.subplots(figsize=(5.5,3.2))
    bars=ax.barh(ips,vals,color=pal[:len(ips)],height=0.55,linewidth=0)
    for bar,v in zip(bars,vals):
        ax.text(v+max(vals)*0.01,bar.get_y()+bar.get_height()/2,str(v),va="center",color=TEXT2,fontsize=7)
    ax.set_title("TOP TALKERS — packets sent"); ax.set_xlabel("Packets")
    ax.tick_params(axis="y",labelsize=7); fig.tight_layout(pad=1.5); return fig_b64(fig)

def chart_ttl(records):
    ttls=[r["ttl"] for r in records if isinstance(r["ttl"],int)]
    if not ttls: return None
    fig,ax=plt.subplots(figsize=(4.5,3))
    ax.hist(ttls,bins=30,color=PURPLE,alpha=0.8,linewidth=0,edgecolor=BG)
    for v,label in [(64,"Linux/Mac"),(128,"Windows"),(255,"Network HW")]:
        if any(abs(t-v)<5 for t in ttls):
            ax.axvline(v,color=YELLOW,linewidth=1.2,linestyle="--",alpha=0.7)
            ax.text(v+1,ax.get_ylim()[1]*0.85,label,color=YELLOW,fontsize=7)
    ax.set_title("TTL DISTRIBUTION"); ax.set_xlabel("TTL Value"); ax.set_ylabel("Count")
    fig.tight_layout(pad=1.5); return fig_b64(fig)

def chart_topo(records):
    sent=Counter(r["src"] for r in records if r["src"]!="—")
    links=Counter()
    for r in records:
        if r["src"]!="—": links[tuple(sorted([r["src"],r["dst"]]))]+=1
    ips=[ip for ip,_ in sent.most_common(10)]
    if not ips: return None
    n=len(ips); cx,cy,rad=0.5,0.5,0.38
    fig,ax=plt.subplots(figsize=(5,3.8))
    ax.set_xlim(0,1); ax.set_ylim(0,1); ax.axis("off")
    ax.set_facecolor(BG3); fig.set_facecolor(BG2)
    ax.set_title("NETWORK TOPOLOGY MAP",color=TEXT,fontsize=11,fontweight="bold",pad=10)
    pos={}
    for i,ip in enumerate(ips):
        ang=2*np.pi*i/n-np.pi/2; pos[ip]=(cx+rad*np.cos(ang),cy+rad*np.sin(ang))
    max_l=max(links.values()) if links else 1
    for (a,b),cnt in links.items():
        if a in pos and b in pos:
            ax.plot([pos[a][0],pos[b][0]],[pos[a][1],pos[b][1]],
                    color=ACCENT,alpha=0.1+0.6*cnt/max_l,linewidth=0.8+2.5*cnt/max_l,zorder=1)
    max_s=max(sent.values()) if sent else 1
    for ip in ips:
        x,y=pos[ip]; s=sent.get(ip,0); r=0.025+0.045*(s/max_s)
        col=ACCENT if s>max_s*0.5 else GREEN
        ax.add_patch(plt.Circle((x,y),r,color=col,zorder=3,linewidth=0))
        ax.annotate(ip,(x,y-r-0.04),ha="center",fontsize=5.5,color=TEXT2,fontfamily="monospace",zorder=4)
    fig.tight_layout(pad=0.5); return fig_b64(fig)

def analyze(records):
    findings=[]; dur=max(records[-1]["ts"],0.001) if records else 1
    proto_ct=Counter(r["proto"] for r in records)
    sent_ct=Counter(r["src"] for r in records if r["src"]!="—")
    recv_ct=Counter(r["dst"] for r in records if r["dst"]!="—")
    icmp=[r for r in records if r["proto"]=="ICMP"]
    tcp=[r for r in records if r["proto"]=="TCP"]
    udp=[r for r in records if r["proto"]=="UDP"]
    arp=[r for r in records if r["proto"]=="ARP"]
    dns=[r for r in records if r["proto"]=="DNS"]
    icmp_req=[r for r in icmp if r["icmp_type"]==8]
    icmp_rep=[r for r in icmp if r["icmp_type"]==0]
    icmp_unrch=[r for r in icmp if r["icmp_type"]==3]
    icmp_ttlx=[r for r in icmp if r["icmp_type"]==11]
    syn=[r for r in tcp if "SYN" in r["flags"] and "ACK" not in r["flags"]]
    rst=[r for r in tcp if "RST" in r["flags"]]

    if icmp_req and not icmp_rep:
        findings.append({"sev":"HIGH","cat":"Network Problem","icon":"📡","color":RED,
            "title":f"One-Way ICMP — {len(icmp_req)} Requests, Zero Replies",
            "detail":f"{len(icmp_req)} ping Echo Requests captured but zero Echo Replies came back. Destination is offline or firewall is blocking ICMP type 0 (Echo Reply) on return path.",
            "fixes":["Check if destination host is online","Allow ICMP echo-reply in firewall rules",
                     "Test: <code>ping -c 4 &lt;destination-ip&gt;</code> from source",
                     "Linux: <code>iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT</code>",
                     "Check routing: <code>ip route get &lt;src-ip&gt;</code> from destination"]})
    if icmp_unrch:
        findings.append({"sev":"HIGH","cat":"Network Problem","icon":"🚫","color":ORANGE,
            "title":f"Destination Unreachable ({len(icmp_unrch)} ICMP Type 3 Packets)",
            "detail":"ICMP Type 3 messages detected. Target host, port, or network is unreachable. Could be closed port, wrong IP, missing route, or firewall rejection.",
            "fixes":["Verify destination IP address is correct","Check service is running: <code>netstat -tuln | grep &lt;port&gt;</code>",
                     "Check routing: <code>ip route show</code>","Check firewall REJECT vs DROP rules"]})
    if icmp_ttlx:
        findings.append({"sev":"MEDIUM","cat":"Network Problem","icon":"⏱️","color":YELLOW,
            "title":f"TTL Exceeded in Transit ({len(icmp_ttlx)} packets)",
            "detail":"Packets expired mid-route (TTL hit zero). Likely routing loop or TTL set too low for number of network hops.",
            "fixes":["Run: <code>traceroute &lt;destination&gt;</code> — look for repeated router IPs",
                     "Repeated hops = routing loop → fix router configs","Increase TTL if destination is legitimately far"]})
    if icmp and dur>0 and len(icmp)/dur>100:
        rate=len(icmp)/dur
        findings.append({"sev":"CRITICAL","cat":"🚨 DoS Attack","icon":"💥","color":RED,
            "title":f"ICMP Ping Flood — {rate:.0f} packets/sec!",
            "detail":f"{len(icmp)} ICMP packets in {dur:.2f}s = {rate:.0f} pkt/s. Classic Denial of Service ping flood overwhelming the target with requests.",
            "fixes":["<b>Block immediately:</b> <code>iptables -A INPUT -p icmp -j DROP</code>",
                     "Rate-limit: <code>iptables -A INPUT -p icmp -m limit --limit 10/s -j ACCEPT</code>",
                     "Contact ISP for upstream traffic scrubbing","Check if DDoS — multiple source IPs?"]})
    big_icmp=[r for r in icmp if r["size"]>1024]
    if big_icmp:
        findings.append({"sev":"MEDIUM","cat":"Security — Data Exfiltration Risk","icon":"🕵️","color":PURPLE,
            "title":f"Oversized ICMP Packets ({len(big_icmp)} > 1024B, max {max(r['size'] for r in big_icmp)}B)",
            "detail":"Normal pings are 64–128 bytes. Oversized ICMP is used for ICMP tunneling (data exfiltration), covert channels, or Ping of Death attacks.",
            "fixes":["Block oversized ICMP: <code>iptables -A INPUT -p icmp -m length --length 256: -j DROP</code>",
                     "Inspect payloads for base64/encoded data","Use Snort/Zeek rules to detect ICMP tunneling tools"]})
    syn_by_src=defaultdict(set)
    for r in syn:
        if r["dst_port"]: syn_by_src[r["src"]].add(r["dst_port"])
    for ip,ports in syn_by_src.items():
        if len(ports)>10:
            findings.append({"sev":"CRITICAL","cat":"🚨 Port Scan / Reconnaissance","icon":"🔍","color":RED,
                "title":f"Port Scan from {ip} — {len(ports)} ports probed",
                "detail":f"{ip} sent TCP SYN to {len(ports)} different ports. Classic SYN stealth scan (nmap -sS) mapping open services before launching an attack.",
                "fixes":[f"<b>Block attacker:</b> <code>iptables -A INPUT -s {ip} -j DROP</code>",
                         "Install fail2ban for auto-blocking","Audit open ports: <code>ss -tuln</code>",
                         "Enable port-scan detection: portsentry or psad","Alert your security team immediately"]})
    if syn and dur>0 and len(syn)/dur>20:
        findings.append({"sev":"HIGH","cat":"Security — SYN Flood","icon":"🌊","color":ORANGE,
            "title":f"SYN Flood — {len(syn)/dur:.0f} SYN/sec",
            "detail":"High TCP SYN volume without completing 3-way handshakes. Fills server connection queue causing DoS — legitimate connections get refused.",
            "fixes":["Enable SYN cookies: <code>sysctl -w net.ipv4.tcp_syncookies=1</code>",
                     "Reduce retries: <code>sysctl -w net.ipv4.tcp_syn_retries=2</code>",
                     "Rate-limit SYN at firewall","Use CDN/WAF with SYN flood protection"]})
    if len(rst)>30:
        findings.append({"sev":"MEDIUM","cat":"Security — TCP Reset","icon":"⛔","color":ORANGE,
            "title":f"High RST Count ({len(rst)} RST packets)",
            "detail":"Excessive TCP RST packets: TCP RST injection attacks, connection hijacking, or aggressive IDS/firewall resets.",
            "fixes":["Check if RST source is IDS/firewall (ok) or external IP (attack)",
                     "Monitor: <code>tcpdump 'tcp[tcpflags] & tcp-rst != 0'</code>",
                     "Spoofed source IPs in RSTs → RST injection attack"]})
    CLEAR={21:"FTP",23:"Telnet",80:"HTTP",110:"POP3",143:"IMAP",25:"SMTP"}
    seen=set()
    for r in tcp:
        for port in [r["src_port"],r["dst_port"]]:
            if port in CLEAR and port not in seen:
                seen.add(port)
                alt={"FTP":"SFTP/FTPS","Telnet":"SSH","HTTP":"HTTPS","POP3":"POP3S","IMAP":"IMAPS","SMTP":"SMTPS"}
                findings.append({"sev":"HIGH","cat":"Security — Unencrypted Traffic","icon":"🔓","color":ORANGE,
                    "title":f"Cleartext {CLEAR[port]} on Port {port} — Credentials Exposed!",
                    "detail":f"Port {port} ({CLEAR[port]}) is completely unencrypted. Anyone on the network can capture usernames and passwords with a packet sniffer.",
                    "fixes":[f"<b>Replace with {alt[CLEAR[port]]}</b> immediately",
                             "Free TLS certificate: <code>certbot --nginx</code> (Let's Encrypt)",
                             f"Block port {port} at firewall once encrypted alternative is deployed",
                             "Rotate all credentials that may have been transmitted in cleartext"]})
    if len(arp)>50 and dur<60:
        findings.append({"sev":"HIGH","cat":"Security — ARP Scan","icon":"📡","color":ORANGE,
            "title":f"ARP Network Scan ({len(arp)} ARP requests in {dur:.1f}s)",
            "detail":"Rapid ARP scanning (arp-scan, netdiscover, nmap -sn) mapping all live hosts on subnet. Reconnaissance step before an attack.",
            "fixes":["Identify scanning MAC from switch port logs","Enable Dynamic ARP Inspection (DAI) on switches",
                     "Use private VLANs to limit ARP broadcast domain","Install arpwatch for ARP monitoring"]})
    if udp and dur>0 and len(udp)/dur>500:
        findings.append({"sev":"CRITICAL","cat":"🚨 UDP Flood","icon":"💥","color":RED,
            "title":f"UDP Flood — {len(udp)/dur:.0f} UDP packets/sec",
            "detail":"Extreme UDP rate. UDP is connectionless so server must process every packet. Could be UDP DoS, DNS/NTP amplification, or SSDP reflection attack.",
            "fixes":["Rate-limit UDP at edge router/firewall","Block top sources: <code>iptables -A INPUT -p udp -s &lt;ip&gt; -j DROP</code>",
                     "Check for spoofed IPs (amplification attack)","Contact ISP for scrubbing"]})
    if len(dns)>80:
        findings.append({"sev":"MEDIUM","cat":"Security — Suspicious DNS","icon":"🌐","color":PURPLE,
            "title":f"High DNS Query Volume ({len(dns)} DNS packets)",
            "detail":"High DNS traffic may indicate DNS tunneling (data exfiltration), botnet C2 over DNS, or DNS amplification attack.",
            "fixes":["Inspect DNS query names for very long/encoded subdomains",
                     "Force all DNS through internal resolver — block external port 53",
                     "Enable DNS query logging","Use DNS filtering: Pi-hole, Cloudflare Gateway"]})
    send_only=[ip for ip in sent_ct if ip!="—" and ip not in recv_ct]
    if send_only:
        findings.append({"sev":"MEDIUM","cat":"Network Problem","icon":"↗️","color":YELLOW,
            "title":f"{len(send_only)} Host(s) Sending With No Return Traffic",
            "detail":f"Hosts: {', '.join(send_only[:4])}{'...' if len(send_only)>4 else ''}. Packets sent but nothing received back. Asymmetric routing, stateful firewall issue, or black-hole route.",
            "fixes":["Allow established connections: <code>iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT</code>",
                     "Test bidirectional: ping both ways","Check routing: <code>ip route get &lt;destination&gt;</code>"]})
    low_ttl=[r for r in records if isinstance(r["ttl"],int) and r["ttl"]<10]
    if len(low_ttl)>3:
        findings.append({"sev":"LOW","cat":"Network Problem","icon":"⏳","color":TEXT2,
            "title":f"Very Low TTL Values ({len(low_ttl)} packets with TTL < 10)",
            "detail":f"Min TTL: {min(r['ttl'] for r in low_ttl)}. Normal: 64=Linux, 128=Windows, 255=routers. Low TTL = many hops, routing loop, or TTL probing.",
            "fixes":["Run: <code>traceroute &lt;destination&gt;</code>","Repeated hops = routing loop",
                     "Check for traceroute/TTL scanning tools running on network"]})
    if not findings:
        findings.append({"sev":"OK","cat":"Summary","icon":"✅","color":GREEN,
            "title":"No Security Issues Detected — Capture Looks Clean",
            "detail":"No attacks, anomalies, or misconfigurations found. Traffic appears normal and bidirectional.",
            "fixes":["Keep monitoring regularly","Update all software and firmware",
                     "Use HTTPS/TLS everywhere","Enable firewall logging for ongoing visibility"]})
    return findings

def compute_stats(records):
    dur=records[-1]["ts"] if len(records)>1 else 0
    sizes=[r["size"] for r in records]
    proto=Counter(r["proto"] for r in records)
    sent=Counter(r["src"] for r in records if r["src"]!="—")
    recv=Counter(r["dst"] for r in records if r["dst"]!="—")
    ips=set(sent)|set(recv)
    convs=defaultdict(lambda:{"pkts":0,"bytes":0,"protos":set()})
    for r in records:
        if r["src"]!="—":
            k=f"{r['src']} → {r['dst']}"; convs[k]["pkts"]+=1; convs[k]["bytes"]+=r["size"]; convs[k]["protos"].add(r["proto"])
    top_p=proto.most_common(1)[0] if proto else ("—",0)
    total_bytes=sum(sizes)
    return {"count":len(records),"dur":dur,"sizes":sizes,"proto":proto,"sent":sent,"recv":recv,
            "ips":ips,"convs":dict(convs),"top_proto":top_p,"total_bytes":total_bytes,
            "pps":len(records)/dur if dur>0 else 0,"avg_size":int(sum(sizes)/len(sizes)) if sizes else 0,
            "bps":total_bytes/dur if dur>0 else 0}

SEV_ORDER=["CRITICAL","HIGH","MEDIUM","LOW","INFO","OK"]
SEV_CSS={"CRITICAL":f"background:rgba(255,61,90,.18);color:{RED};border:1px solid rgba(255,61,90,.3)",
         "HIGH":f"background:rgba(255,126,54,.15);color:{ORANGE};border:1px solid rgba(255,126,54,.25)",
         "MEDIUM":f"background:rgba(255,204,0,.12);color:{YELLOW};border:1px solid rgba(255,204,0,.2)",
         "LOW":f"background:rgba(0,229,255,.1);color:{ACCENT};border:1px solid rgba(0,229,255,.15)",
         "INFO":f"background:rgba(123,135,170,.1);color:{TEXT2};border:1px solid {BORDER}",
         "OK":f"background:rgba(0,255,157,.1);color:{GREEN};border:1px solid rgba(0,255,157,.2)"}
SEV_BORDER={"CRITICAL":RED,"HIGH":ORANGE,"MEDIUM":YELLOW,"LOW":ACCENT,"INFO":TEXT2,"OK":GREEN}
RGB={"CRITICAL":"255,61,90","HIGH":"255,126,54","MEDIUM":"255,204,0","LOW":"0,229,255","OK":"0,255,157","INFO":"123,135,170"}

def badge_html(sev):
    css = SEV_CSS.get(sev, SEV_CSS.get("INFO",""))
    return '<span style="font-family:Space Mono,monospace;font-size:9px;font-weight:700;letter-spacing:1px;padding:3px 10px;border-radius:2px;' + css + '">' + sev + '</span>' 

def finding_card(f):
    border=SEV_BORDER.get(f["sev"],TEXT2); rgb=RGB.get(f["sev"],"123,135,170")
    fixes="".join(f'<li style="font-size:11px;color:{TEXT2};line-height:2;padding-left:14px;position:relative;list-style:none"><span style="position:absolute;left:0;color:{TEXT3};font-size:10px">→</span>{fix}</li>' for fix in f["fixes"])
    return f'''<div style="background:{BG2};border:1px solid {BORDER};border-left:3px solid {border};border-radius:4px;padding:22px;position:relative;overflow:hidden;">
  <div style="position:absolute;top:0;right:0;width:140px;height:140px;background:radial-gradient(circle at top right,rgba({rgb},0.07),transparent 70%);pointer-events:none"></div>
  <div style="margin-bottom:10px">{badge_html(f["sev"])}</div>
  <div style="font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:{TEXT3};font-family:Space Mono,monospace;margin-bottom:8px">{f["cat"]}</div>
  <div style="font-size:15px;font-weight:700;color:{TEXT};margin-bottom:10px;line-height:1.4">{f["icon"]} {f["title"]}</div>
  <div style="font-size:12px;color:{TEXT2};line-height:1.8;margin-bottom:16px">{f["detail"]}</div>
  <div style="background:{BG3};border:1px solid {BORDER};border-radius:3px;padding:14px 16px;">
    <div style="font-family:Space Mono,monospace;font-size:9px;color:{GREEN};text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px">▶ HOW TO FIX / WHAT TO DO</div>
    <ul style="list-style:none;padding:0;margin:0">{fixes}</ul>
  </div>
</div>'''

def img_tag(b64):
    if not b64: return f'<p style="color:{TEXT3};font-size:12px">No data</p>'
    return f'<img src="data:image/png;base64,{b64}" style="width:100%;border-radius:3px">'

def conv_row_html(pair,d,max_pkts):
    protos=" ".join(f'<span style="font-family:Space Mono,monospace;font-size:8px;padding:2px 7px;border-radius:2px;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.15);color:{ACCENT}">{p}</span>' for p in d["protos"])
    pct=int(d["pkts"]/max_pkts*100)
    return f'''<div style="display:grid;grid-template-columns:1fr auto auto auto;align-items:center;gap:12px;padding:7px 0;border-bottom:1px solid {BORDER}">
  <div style="font-family:Space Mono,monospace;font-size:10px;color:{TEXT};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{pair}</div>
  <div style="display:flex;gap:4px">{protos}</div>
  <div style="height:3px;background:{BG3};border-radius:2px;width:80px"><div style="height:100%;width:{pct}%;background:{ACCENT};border-radius:2px"></div></div>
  <div style="font-family:Space Mono,monospace;font-size:10px;color:{TEXT2};white-space:nowrap">{d["pkts"]} pkts · {d["bytes"]/1024:.1f}KB</div>
</div>'''

def pkt_row_html(r):
    col_map={"TCP":ACCENT,"UDP":ORANGE,"ICMP":GREEN,"ARP":RED,"DNS":PURPLE,"Other":TEXT2}
    col=col_map.get(r["proto"],TEXT2)
    return f'''<tr style="border-bottom:1px solid rgba(30,37,64,.4)">
  <td style="padding:5px 10px;color:{TEXT3}">{r["num"]}</td>
  <td style="padding:5px 10px;font-family:Space Mono,monospace;font-size:10px;color:{TEXT2}">{r["ts"]:.4f}</td>
  <td style="padding:5px 10px"><span style="font-family:Space Mono,monospace;font-size:9px;font-weight:700;padding:2px 8px;border-radius:2px;background:rgba(255,255,255,.04);color:{col};border:1px solid {col}22">{r["proto"]}</span></td>
  <td style="padding:5px 10px;font-family:Space Mono,monospace;font-size:10px;color:{TEXT}">{r["src"]}</td>
  <td style="padding:5px 10px;font-family:Space Mono,monospace;font-size:10px;color:{TEXT}">{r["dst"]}</td>
  <td style="padding:5px 10px;text-align:right;font-family:Space Mono,monospace;font-size:10px;color:{TEXT2}">{r["size"]}</td>
  <td style="padding:5px 10px;text-align:right;font-family:Space Mono,monospace;font-size:10px;color:{TEXT3}">{r["ttl"]}</td>
  <td style="padding:5px 10px;font-family:Space Mono,monospace;font-size:10px;color:{TEXT3};max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{r["info"]}">{r["info"]}</td>
</tr>'''

def build_html(pcap_path,records,S,findings,charts):
    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname=os.path.basename(pcap_path)
    stat_defs=[
        {"l":"TOTAL PACKETS","v":f"{S['count']:,}","s":f"{S['pps']:.1f} pkt/s","c":ACCENT},
        {"l":"DURATION","v":f"{S['dur']:.2f}s","s":f"{S['total_bytes']/1024:.1f} KB total","c":GREEN},
        {"l":"AVG PACKET","v":f"{S['avg_size']}B","s":f"max {max(S['sizes'])}B","c":ORANGE},
        {"l":"UNIQUE IPs","v":str(len(S['ips'])),"s":f"{len(S['proto'])} protocols","c":PURPLE},
        {"l":"TOP PROTOCOL","v":S['top_proto'][0],"s":f"{S['top_proto'][1]} pkts ({round(S['top_proto'][1]/S['count']*100)}%)","c":YELLOW},
        {"l":"THROUGHPUT","v":f"{S['bps']/1024:.1f}","s":"KB/s average","c":RED},
    ]
    stats_html="".join(f'''<div style="background:{BG2};border:1px solid {BORDER};border-top:2px solid {c['c']};border-radius:4px;padding:18px 16px">
  <div style="font-size:9px;text-transform:uppercase;letter-spacing:2px;color:{TEXT3};font-family:Space Mono,monospace;margin-bottom:10px">{c['l']}</div>
  <div style="font-family:'Bebas Neue',cursive,monospace;font-size:38px;color:{TEXT};letter-spacing:1px;line-height:1">{c['v']}</div>
  <div style="font-size:10px;color:{TEXT2};margin-top:6px;font-family:Space Mono,monospace">{c['s']}</div>
</div>''' for c in stat_defs)
    proto_pills="".join(f'<span style="font-family:Space Mono,monospace;font-size:9px;padding:3px 10px;border-radius:2px;background:rgba(255,255,255,.04);border:1px solid {BORDER};display:inline-flex;align-items:center;gap:5px"><span style="width:6px;height:6px;border-radius:50%;background:{pc(p)};display:inline-block"></span>{p} <b style="color:{TEXT}">{cnt}</b></span>' for p,cnt in S["proto"].most_common())
    sorted_convs=sorted(S["convs"].items(),key=lambda x:x[1]["pkts"],reverse=True)[:12]
    max_pkts=sorted_convs[0][1]["pkts"] if sorted_convs else 1
    convs_html="".join(conv_row_html(k,v,max_pkts) for k,v in sorted_convs) or f'<p style="color:{TEXT3};font-size:12px">No IP conversations found</p>'
    table_html="".join(pkt_row_html(r) for r in records[:300])
    sorted_findings=sorted(findings,key=lambda f:SEV_ORDER.index(f["sev"]))
    cnt=Counter(f["sev"] for f in findings)
    findings_html="".join(finding_card(f) for f in sorted_findings)
    th_style=f'style="padding:8px 10px;text-align:left;color:{TEXT3};font-family:Space Mono,monospace;font-size:9px;text-transform:uppercase;letter-spacing:1px;font-weight:400"'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScan — {fname}</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Space+Mono:wght@400;700&family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:{BG};color:{TEXT};font-family:'DM Sans',sans-serif;min-height:100vh}}
body::before{{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.012) 2px,rgba(0,229,255,.012) 4px);pointer-events:none;z-index:9999}}
::-webkit-scrollbar{{width:5px;height:5px}}::-webkit-scrollbar-track{{background:{BG}}}::-webkit-scrollbar-thumb{{background:{BORDER};border-radius:3px}}
.sl{{font-family:Space Mono,monospace;font-size:11px;text-transform:uppercase;letter-spacing:3px;color:{TEXT3};margin-bottom:14px;display:flex;align-items:center;gap:12px}}
.sl::after{{content:'';flex:1;height:1px;background:{BORDER}}}
code{{font-family:Space Mono,monospace;font-size:10px;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.12);padding:1px 6px;border-radius:2px;color:{ACCENT};cursor:pointer}}
code:hover{{background:rgba(0,255,157,.12)}}
.pulse{{width:8px;height:8px;border-radius:50%;background:{GREEN};display:inline-block;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1;box-shadow:0 0 0 0 rgba(0,255,157,.4)}}50%{{opacity:.7;box-shadow:0 0 0 6px rgba(0,255,157,0)}}}}
</style>
</head>
<body>
<div style="background:rgba(6,8,16,.97);border-bottom:1px solid {BORDER};padding:14px 32px;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px);display:flex;align-items:center;gap:16px">
  <div style="font-family:'Bebas Neue',cursive;font-size:26px;letter-spacing:4px;color:{ACCENT};text-shadow:0 0 20px rgba(0,229,255,.4)">NET<span style="color:{TEXT3}">/</span>SCAN</div>
  <span style="font-family:Space Mono,monospace;font-size:10px;color:{TEXT3};border:1px solid {BORDER};padding:3px 10px;border-radius:2px">PCAP SECURITY DASHBOARD</span>
  <span style="font-family:Space Mono,monospace;font-size:10px;color:{TEXT3};border:1px solid {BORDER};padding:3px 10px;border-radius:2px">PYTHON GENERATED · {now}</span>
  <div style="margin-left:auto;display:flex;align-items:center;gap:8px;font-size:12px;font-family:Space Mono,monospace;color:{TEXT2}"><span class="pulse"></span> ANALYSIS COMPLETE</div>
</div>

<div style="max-width:1400px;margin:0 auto;padding:24px 28px">

<div style="background:{BG2};border:1px solid {BORDER};border-left:3px solid {ACCENT};border-radius:4px;padding:16px 24px;margin-bottom:20px;display:flex;align-items:center;gap:16px">
  <div>
    <div style="font-family:'Bebas Neue',cursive;font-size:22px;letter-spacing:2px;color:{ACCENT}">{fname}</div>
    <div style="font-size:11px;color:{TEXT2};margin-top:2px;font-family:Space Mono,monospace">{S['count']:,} packets · {S['dur']:.3f}s · {S['total_bytes']/1024:.1f} KB · analysed {now}</div>
  </div>
</div>

<div style="display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px">{stats_html}</div>

<div class="sl">TRAFFIC ANALYSIS</div>

<div style="display:grid;grid-template-columns:300px 1fr;gap:14px;margin-bottom:14px">
  <div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:12px">● Protocol Mix</div>
    <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px">{proto_pills}</div>
    {img_tag(charts.get('pie'))}
  </div>
  <div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:12px">● Traffic Timeline</div>
    {img_tag(charts.get('timeline'))}
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:14px;margin-bottom:14px">
  <div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:12px">● Packet Sizes</div>
    {img_tag(charts.get('sizes'))}
  </div>
  <div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:12px">● Top Talkers</div>
    {img_tag(charts.get('talkers'))}
  </div>
  <div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:12px">● Network Map</div>
    {img_tag(charts.get('topo'))}
  </div>
  <div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:12px">● TTL Distribution</div>
    {img_tag(charts.get('ttl'))}
  </div>
</div>

<div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px;margin-bottom:14px">
  <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2};margin-bottom:14px">● IP Conversations</div>
  {convs_html}
</div>

<div style="background:{BG2};border:1px solid {BORDER};border-radius:4px;padding:20px;margin-bottom:24px">
  <div style="display:flex;align-items:center;margin-bottom:14px">
    <div style="font-family:Space Mono,monospace;font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{TEXT2}">● Packet List</div>
    <span style="font-family:Space Mono,monospace;font-size:10px;color:{TEXT3};margin-left:auto">First {min(300,S['count'])} of {S['count']} packets</span>
  </div>
  <div style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse;font-size:10px;min-width:640px">
      <thead><tr style="border-bottom:1px solid {BORDER}">
        {''.join(f'<th {th_style}>{h}</th>' for h in ['#','Time (s)','Proto','Source','Destination','Bytes','TTL','Info'])}
      </tr></thead>
      <tbody>{table_html}</tbody>
    </table>
  </div>
</div>

<div class="sl">SECURITY &amp; PROBLEM REPORT</div>

<div style="background:{BG2};border:1px solid {BORDER};border-left:3px solid {RED};border-radius:4px;padding:20px 24px;margin-bottom:16px;display:flex;align-items:center;gap:16px">
  <div style="font-size:36px">🛡️</div>
  <div>
    <div style="font-family:'Bebas Neue',cursive;font-size:28px;letter-spacing:3px;color:{RED}">Security Analysis</div>
    <div style="font-size:12px;color:{TEXT2};margin-top:3px">Rule-based detection · Problems explained · Fix commands included · No API required</div>
  </div>
  <div style="margin-left:auto;display:flex;gap:20px;text-align:center">
    <div><div style="font-family:'Bebas Neue',cursive;font-size:36px;color:{RED};text-shadow:0 0 15px rgba(255,61,90,.4)">{cnt.get('CRITICAL',0)}</div><div style="font-size:9px;color:{TEXT3};font-family:Space Mono,monospace;text-transform:uppercase;letter-spacing:1px">Critical</div></div>
    <div><div style="font-family:'Bebas Neue',cursive;font-size:36px;color:{ORANGE}">{cnt.get('HIGH',0)}</div><div style="font-size:9px;color:{TEXT3};font-family:Space Mono,monospace;text-transform:uppercase;letter-spacing:1px">High</div></div>
    <div><div style="font-family:'Bebas Neue',cursive;font-size:36px;color:{YELLOW}">{cnt.get('MEDIUM',0)}</div><div style="font-size:9px;color:{TEXT3};font-family:Space Mono,monospace;text-transform:uppercase;letter-spacing:1px">Medium</div></div>
    <div><div style="font-family:'Bebas Neue',cursive;font-size:36px;color:{GREEN}">{cnt.get('OK',0)}</div><div style="font-size:9px;color:{TEXT3};font-family:Space Mono,monospace;text-transform:uppercase;letter-spacing:1px">OK</div></div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px">{findings_html}</div>

</div>

<div style="background:{BG2};border-top:1px solid {BORDER};padding:16px 32px;text-align:center;font-family:Space Mono,monospace;font-size:10px;color:{TEXT3}">
  NetScan PCAP Dashboard · Python Generated · {now} · {S['count']:,} packets analysed
</div>

<script>
document.querySelectorAll('code').forEach(el=>{{
  el.title='Click to copy';
  el.addEventListener('click',()=>navigator.clipboard.writeText(el.textContent).then(()=>{{
    const o=el.style.background;el.style.background='rgba(0,255,157,.2)';setTimeout(()=>el.style.background=o,600);
  }}));
}});
</script>
</body></html>"""

def main():
    if len(sys.argv)<2:
        print(__doc__); print(f"\n\033[91mUsage: python3 pcap_analyzer_v2.py <file.pcap>\033[0m\n"); sys.exit(1)
    path=sys.argv[1]
    if not os.path.exists(path):
        print(f"\033[91mError: File not found: {path}\033[0m"); sys.exit(1)
    out_dir=os.path.join(os.path.dirname(os.path.abspath(path)),"pcap_report")
    os.makedirs(out_dir,exist_ok=True)
    setup_mpl()
    print("\n⚙️   Parsing packets…")
    packets=parse_pcap(path); records=extract(packets); S=compute_stats(records)
    print("📊  Generating charts…")
    charts={k:v for k,v in {"timeline":chart_timeline(records),"pie":chart_pie(records),
        "sizes":chart_sizes(records),"talkers":chart_talkers(records),
        "ttl":chart_ttl(records),"topo":chart_topo(records)}.items() if v}
    print("🔍  Running security analysis…")
    findings=analyze(records)
    crit=sum(1 for f in findings if f["sev"]=="CRITICAL"); high=sum(1 for f in findings if f["sev"]=="HIGH")
    print(f"    → {len(findings)} findings ({crit} CRITICAL, {high} HIGH)")
    print("🌐  Building dashboard…")
    html=build_html(path,records,S,findings,charts)
    out=os.path.join(out_dir,"dashboard.html")
    with open(out,"w",encoding="utf-8") as f: f.write(html)
    print(f"\n\033[92m✅  Done! Open this file in your browser:\033[0m")
    print(f"   📂  {out}\n")

if __name__=="__main__":
    main()
