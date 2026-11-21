#!/usr/bin/env python3
"""Carte GRAPHIQUE en direct de l'infrastructure, dans le navigateur du cloud host.

    python3 tools/infra-live.py            puis ouvrir http://127.0.0.1:8099  (make infra-live)

Toutes les 2 s, la page demande /state ; le serveur lit le système réel (libvirt, `ss` sur chaque VM,
`wg show` sur le gateway, journaux nftables) avec les mêmes fonctions que tools/infra-view.py,
et la page dessine : VM (vert = en marche), réseaux, tunnel (âge de la poignée de main), flux actifs
(animés, avec le nombre de connexions), paquets rejetés (flèche rouge éphémère).
N'écoute que sur 127.0.0.1 ; tout ce qui identifie les machines est masqué.
"""
import argparse
import http.server
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("infra_view", HERE / "infra-view.py")
iv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iv)


def state():
    lv = iv.libvirt()
    peers = iv.wg_peers()
    conns = iv.connections()
    drops = iv.drops(15)
    return {
        "time": time.strftime("%H:%M:%S"),
        "vms": {vm: d["state"] for vm, d in lv.items()},
        "peers": [{"name": p["name"], "age": p["age"], "rx": p["rx"], "tx": p["tx"]} for p in peers],
        "conns": [{"src": iv.who(s), "dst": iv.who(d), "port": p, "service": iv.port_name(p)} for s, d, p in conns],
        "drops": [{"t": t, "node": n, "src": iv.who(s), "dst": iv.who(d), "port": dp} for t, n, c, s, d, pr, dp in drops],
    }


class Cache:
    """One reader refreshes the state every `period` s; requests read the last copy."""

    def __init__(self, period):
        self.period, self.data, self.lock = period, {"time": "…", "vms": {}, "peers": [], "conns": [], "drops": []}, threading.Lock()
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                d = state()
                with self.lock:
                    self.data = d
            except Exception as e:  # keep serving the last good state
                print("refresh failed:", type(e).__name__, file=sys.stderr)
            time.sleep(self.period)

    def get(self):
        with self.lock:
            return self.data


PAGE = r"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>ZT Bank — infrastructure en direct</title>
<style>
body{margin:0;background:#0e1618;color:#d6e0dc;font:14px/1.4 system-ui,sans-serif}
header{display:flex;justify-content:space-between;align-items:center;padding:10px 24px;background:#0f3d3e}
h1{font-size:20px;margin:0;color:#fff} #clock{color:#9fd8c8}
svg{display:block;margin:0 auto}
.net rect{fill:#12262a;stroke:#24474c} .net text{fill:#7fa8a0;font-size:13px}
.vm rect{rx:10;stroke-width:2} .vm.up rect{fill:#173a33;stroke:#3ecf8e} .vm.down rect{fill:#3a1a1a;stroke:#e5534b}
.vm text{fill:#fff;font-size:15px;font-weight:600} .vm .sub{fill:#9fb9b3;font-size:12px;font-weight:400}
.ext rect{fill:#1b2427;stroke:#5c6f6b;rx:10} .ext text{fill:#d6e0dc;font-size:14px}
.flow{stroke:#2f4b4f;stroke-width:3;fill:none} .flow.on{stroke:#3ecf8e;stroke-width:5;stroke-dasharray:10 8;animation:run .8s linear infinite}
@keyframes run{to{stroke-dashoffset:-18}}
.lbl{fill:#7fa8a0;font-size:12px} .lbl.on{fill:#3ecf8e;font-weight:600}
.drop{stroke:#e5534b;stroke-width:3;fill:none;stroke-dasharray:4 5;opacity:.9}
.droptxt{fill:#e5534b;font-size:12px}
#wrap{display:flex;gap:16px;padding:12px 16px;align-items:flex-start}
#side{flex:0 0 360px;font-size:12px;background:#111c1f;border:1px solid #24474c;border-radius:10px;padding:10px 12px;margin-top:40px}
#side b{color:#9fd8c8} .bad{color:#e5534b} .ok{color:#3ecf8e}
</style></head><body>
<header><h1>ZT Bank — infrastructure en direct</h1><span id="clock">…</span></header>
<div id="wrap"><svg id="map" width="1200" height="760" viewBox="0 0 1200 760"></svg>
<div id="side"></div></div>
<script>
const NS="http://www.w3.org/2000/svg";
// positions (pixels) — topology from policy.yaml
const NETS=[["wan 192.168.122.0/24 (NAT)",310,40,250,190],["dmz 10.20.0.0/24",590,40,250,190],["app 10.30.0.0/24",590,260,560,180],
            ["data 10.40.0.0/24",590,470,560,150],["mgmt 10.50.0.0/24 (administration, PKI) — le cloud host n'a d'adresse que sur mgmt et wan",40,650,1110,100]];
const VMS={gateway:[370,110,"wg0 10.10.0.1"],frontend:[650,110,"10.20.0.10 :8443 :8444"],"service-a":[650,330,"10.30.0.11 :9443 core"],
           "service-b":[930,330,"10.30.0.12 :9443 ledger"],database:[930,520,"10.40.0.10 :5432"],ca:[930,675,"10.50.0.10 :9000 step-ca"]};
const EXT={rc:[40,70,"poste distant","Firefox · WireGuard"],pf:[40,200,"Internet / Wi-Fi","PayFlow, scanners…"],host:[40,675,"cloud host","10.50.0.1 · bot · client de test"]};
const W=190,H=64;
const FLOWS=[ // id, from, to, port (live count on the destination), label, offset
 ["tun","rc","gateway",null,"WireGuard UDP 51820",1],["web","gateway","frontend","8443","tunnel → :8443",-12],
 ["pay1","pf","gateway","8444","TCP 8444 (DNAT)",0],["pay2","gateway","frontend","8444","partenaire :8444",14],
 ["a","frontend","service-a","9443","mTLS",0],["b","service-a","service-b","9443","mTLS",0],
 ["db","service-b","database","5432","TLS 1.3",0]];
function pos(k){return VMS[k]?[VMS[k][0],VMS[k][1]]:[EXT[k][0],EXT[k][1]]}
function mid(k){const[x,y]=pos(k);return[x+W/2,y+H/2]}
function el(t,a,p){const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);(p||svg).appendChild(e);return e}
const svg=document.getElementById("map");
function edge(a,b,off){off=off||0;const[x1,y1]=mid(a),[x2,y2]=mid(b);const dx=x2-x1,dy=y2-y1;
  const s=Math.abs(dx)/W>Math.abs(dy)/H?(W/2)/Math.abs(dx):(H/2)/Math.abs(dy);const L=Math.hypot(dx,dy)||1;
  const ox=-dy/L*off,oy=dx/L*off;return[x1+dx*s+ox,y1+dy*s+oy,x2-dx*s+ox,y2-dy*s+oy]}
function draw(st){
  svg.innerHTML="";
  el("defs",{}).innerHTML='<marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="#3ecf8e"/></marker><marker id="ad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="#e5534b"/></marker><marker id="ag" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="#2f4b4f"/></marker>';
  for(const[n,x,y,w,h]of NETS){const g=el("g",{class:"net"});el("rect",{x,y,width:w,height:h,rx:14},g);el("text",{x:x+12,y:y+20},g).textContent=n}
  const count=(dst,port)=>st.conns.filter(c=>c.port===port&&c.dst.startsWith(dst)).length;
  const rc=st.peers.find(p=>p.name==="remote-client");const tunOn=rc&&rc.age!==null&&rc.age<180;
  for(const[id,a,b,port,label,off]of FLOWS){
    const n=port?count(port==="8444"&&id==="pay1"?"frontend":b,port):(tunOn?1:0);const on=n>0;const[x1,y1,x2,y2]=edge(a,b,off);
    el("path",{d:`M${x1},${y1}L${x2},${y2}`,class:"flow"+(on?" on":""),"marker-end":on?"url(#ar)":"url(#ag)"});
    const horiz=Math.abs(x2-x1)>Math.abs(y2-y1);
    const t=el("text",horiz?{x:Math.min(x1,x2)+6,y:(y1+y2)/2+(off>0?22:-10),class:"lbl"+(on?" on":"")}
                           :{x:(x1+x2)/2+10,y:(y1+y2)/2,class:"lbl"+(on?" on":"")});
    t.textContent=id==="tun"?(tunOn?`${label} · handshake ${rc.age}s`:`${label} · inactif`):(on?`${label} · ${n} connexion(s)`:label)}
  for(const k in EXT){const[x,y,t,s]=EXT[k];const g=el("g",{class:"ext"});el("rect",{x,y,width:W,height:H},g);
    el("text",{x:x+12,y:y+26},g).textContent=t;const u=el("text",{x:x+12,y:y+46,class:"sub"},g);u.textContent=s;u.style.fill="#9fb9b3";u.style.fontSize="12px"}
  for(const k in VMS){const[x,y,s]=VMS[k];const up=(st.vms[k]||"")==="running";
    const g=el("g",{class:"vm "+(up?"up":"down")});el("rect",{x,y,width:W,height:H},g);
    el("text",{x:x+14,y:y+26},g).textContent=(up?"● ":"○ ")+k;el("text",{x:x+14,y:y+47,class:"sub"},g).textContent=s}
  // recent drops (last 30 s of the list): red dashed arrow from the source's box to the target's box
  const where=n=>{const m=(n||"").split("(")[0];if(VMS[m])return m;if(m==="remote-client")return"rc";if(m==="test-peer"||m==="bot"||m==="cloud-host")return"host";return"pf"};
  const shown=new Set();
  st.drops.slice(-6).forEach((d,i)=>{const a=where(d.src),b=where(d.dst);if(a===b||shown.has(a+b))return;shown.add(a+b);
    const[x1,y1,x2,y2]=edge(a,b);el("path",{d:`M${x1},${y1+6}L${x2},${y2+6}`,class:"drop","marker-end":"url(#ad)"});
    el("text",{x:(x1+x2)/2-40,y:(y1+y2)/2+24,class:"droptxt"}).textContent=`DROP :${d.port} (${d.t})`});
  document.getElementById("clock").textContent="mis à jour "+st.time;
  const side=document.getElementById("side");
  side.innerHTML="<b>Connexions établies</b><br>"+(st.conns.map(c=>`<span class=ok>${c.src} → ${c.dst} :${c.port}</span>`).join("<br>")||"aucune")+
    "<br><br><b>Derniers rejets (nftables)</b><br>"+(st.drops.slice(-5).map(d=>`<span class=bad>${d.t} ${d.node}: ${d.src} → ${d.dst}:${d.port}</span>`).join("<br>")||"aucun");
}
async function tick(){try{const r=await fetch("/state");draw(await r.json())}catch(e){}setTimeout(tick,2000)}
tick();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--period", type=float, default=2)
    a = ap.parse_args()
    cache = Cache(a.period)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/state":
                body, ctype = json.dumps(cache.get()).encode(), "application/json"
            elif self.path in ("/", "/index.html"):
                body, ctype = PAGE.encode(), "text/html; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(f"carte en direct : http://127.0.0.1:{a.port}   (Ctrl-C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
