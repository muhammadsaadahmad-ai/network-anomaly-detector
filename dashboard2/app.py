from flask import Flask, render_template_string, jsonify
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.traffic_models import Session, Alert, TrafficRecord

app = Flask(__name__)

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetWatch — Anomaly Detection</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#03080a;--panel:#050d0f;--border:#0d2e33;--border2:#1a5c63;
  --cyan:#00ffee;--cyan2:#00c8bc;--cyan3:#007a75;--dim:#1a4a47;
  --red:#ff2a2a;--amber:#ffaa00;--blue:#00aaff;--text:#b0fff8;--muted:#3a7a76;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;min-height:100vh;}
body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,238,0.01) 2px,rgba(0,255,238,0.01) 4px);
  pointer-events:none;z-index:0;}
.scan{position:fixed;top:0;left:0;width:100%;height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,255,238,0.3),transparent);
  animation:scan 4s linear infinite;pointer-events:none;z-index:999;}
@keyframes scan{from{top:0}to{top:100vh}}
.wrap{position:relative;z-index:1;padding:20px 24px;max-width:1300px;margin:0 auto;}
.hdr{display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid var(--border2);padding-bottom:14px;margin-bottom:22px;}
.hdr-left{display:flex;align-items:center;gap:18px;}
.logo{width:48px;height:48px;border:1px solid var(--cyan3);display:flex;
  align-items:center;justify-content:center;font-family:'Orbitron',monospace;
  font-weight:900;font-size:16px;color:var(--cyan);position:relative;
  animation:pb 3s ease-in-out infinite;}
.logo::before{content:'';position:absolute;top:-4px;left:-4px;right:-4px;bottom:-4px;
  border:1px solid var(--cyan3);opacity:0.3;}
@keyframes pb{0%,100%{border-color:var(--cyan3)}50%{border-color:var(--cyan2);box-shadow:0 0 14px rgba(0,255,238,0.2)}}
.title h1{font-family:'Orbitron',monospace;font-size:13px;font-weight:700;
  color:var(--cyan);letter-spacing:3px;text-transform:uppercase;}
.title p{font-size:10px;color:var(--muted);letter-spacing:2px;margin-top:3px;}
.live{display:inline-flex;align-items:center;gap:7px;font-size:10px;color:var(--cyan2);letter-spacing:2px;}
.dot{width:7px;height:7px;border-radius:50%;background:var(--cyan);animation:blink 1.2s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.15}}
.ts{font-size:10px;color:var(--muted);margin-top:5px;letter-spacing:1px;}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px;}
.stat{border:1px solid var(--border);background:var(--panel);padding:16px 18px;position:relative;overflow:hidden;}
.stat::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;background:var(--cyan3);}
.stat.sh::before{background:var(--red)}.stat.sm::before{background:var(--amber)}.stat.sl::before{background:var(--blue)}
.sl2{font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;}
.sn{font-family:'Orbitron',monospace;font-size:32px;font-weight:700;color:var(--cyan);line-height:1;}
.stat.sh .sn{color:var(--red)}.stat.sm .sn{color:var(--amber)}.stat.sl .sn{color:var(--blue)}
.ss{font-size:9px;color:var(--dim);margin-top:8px;}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;}
.sec-t{font-family:'Orbitron',monospace;font-size:10px;color:var(--cyan2);letter-spacing:3px;}
.sec-t::before{content:'> ';color:var(--cyan3);}
.tbl-wrap{border:1px solid var(--border);overflow:hidden;}
table{width:100%;border-collapse:collapse;}
thead tr{background:#071a1a;border-bottom:1px solid var(--border2);}
th{padding:11px 14px;font-size:9px;color:var(--cyan3);letter-spacing:2px;text-transform:uppercase;text-align:left;font-weight:400;}
tbody tr{border-bottom:1px solid var(--border);transition:background 0.15s;}
tbody tr:hover{background:#071a18;}
td{padding:11px 14px;font-size:11px;}
.iv{color:#e0fffc;font-family:'Share Tech Mono',monospace;}
.badge{display:inline-block;padding:2px 9px;font-size:9px;letter-spacing:1px;border:1px solid;text-transform:uppercase;}
.bh{color:var(--red);border-color:#6b1212;background:#1a0505;}
.bm{color:var(--amber);border-color:#6b4a00;background:#1a1100;}
.bl{color:var(--blue);border-color:#004a6b;background:#00111a;}
.bps{color:#ff88ff;border-color:#660066;background:#110011;}
.bml{color:var(--cyan);border-color:#006666;background:#001a1a;}
.bs{color:#88ffcc;border-color:#006644;background:#001a11;}
.mc{color:#2a5a5a;font-size:10px;}
.tc{color:#1e4442;font-size:10px;}
.desc{color:#4a6b68;font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.footer{margin-top:18px;padding-top:12px;border-top:1px solid var(--border);
  display:flex;justify-content:space-between;align-items:center;}
.fl{font-size:9px;color:var(--cyan3);letter-spacing:2px;}
.fr{font-size:9px;color:var(--dim);}
.empty td{color:var(--muted);text-align:center;padding:30px;}
</style>
</head>
<body>
<div class="scan"></div>
<div class="wrap">
  <div class="hdr">
    <div class="hdr-left">
      <div class="logo">NW</div>
      <div class="title">
        <h1>NetWatch &mdash; Anomaly Detection</h1>
        <p>NETWORK INTELLIGENCE // PHASE-2 // ML-POWERED</p>
      </div>
    </div>
    <div style="text-align:right">
      <div class="live"><span class="dot"></span>MONITOR ACTIVE</div>
      <div class="ts" id="ts">--:--:-- UTC</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="sl2">Total alerts</div>
      <div class="sn">{{ total }}</div>
      <div class="ss">all detectors</div>
    </div>
    <div class="stat sh">
      <div class="sl2">High severity</div>
      <div class="sn">{{ high }}</div>
      <div class="ss">port scans + floods</div>
    </div>
    <div class="stat sm">
      <div class="sl2">ML anomalies</div>
      <div class="sn">{{ ml_count }}</div>
      <div class="ss">isolation forest</div>
    </div>
    <div class="stat sl">
      <div class="sl2">Packets captured</div>
      <div class="sn">{{ packets }}</div>
      <div class="ss">total traffic records</div>
    </div>
  </div>

  <div class="sec-hdr">
    <div class="sec-t">Alert feed</div>
  </div>

  <div class="tbl-wrap">
    <table>
      <thead>
        <tr><th>Type</th><th>Source IP</th><th>Destination</th><th>Severity</th><th>Description</th><th>Time</th></tr>
      </thead>
      <tbody>
        {% for a in alerts %}
        <tr>
          <td>
            {% if a.alert_type == 'port_scan' %}<span class="badge bps">PORT SCAN</span>
            {% elif a.alert_type == 'anomaly_ml' %}<span class="badge bml">ML ANOMALY</span>
            {% elif a.alert_type == 'anomaly_stat' %}<span class="badge bs">STAT</span>
            {% else %}<span class="badge bl">{{ a.alert_type }}</span>{% endif %}
          </td>
          <td class="iv">{{ a.src_ip }}</td>
          <td class="mc">{{ a.dst_ip }}{% if a.dst_port and a.dst_port > 0 %}:{{ a.dst_port }}{% endif %}</td>
          <td>
            {% if a.severity == 'high' %}<span class="badge bh">HIGH</span>
            {% elif a.severity == 'medium' %}<span class="badge bm">MEDIUM</span>
            {% else %}<span class="badge bl">LOW</span>{% endif %}
          </td>
          <td class="desc">{{ a.description[:80] }}</td>
          <td class="tc">{{ a.timestamp.strftime('%H:%M:%S') }}</td>
        </tr>
        {% else %}
        <tr class="empty"><td colspan="6">[ NO ALERTS — RUN DETECTION FIRST ]</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div class="fl">NETWATCH v1.0 // PHASE-2 // ISOLATION FOREST + Z-SCORE + PORT SCAN</div>
    <div class="fr">PORTFOLIO &mdash; MUHAMMAD SAAD AHMAD</div>
  </div>
</div>
<script>
(function tick(){
  const t=new Date().toUTCString().match(/(\\d{2}:\\d{2}:\\d{2})/);
  if(t) document.getElementById('ts').textContent=t[1]+' UTC';
  setTimeout(tick,1000);
})();
</script>
</body>
</html>"""

@app.route("/")
def index():
    session  = Session()
    alerts   = session.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()
    total    = session.query(Alert).count()
    high     = session.query(Alert).filter_by(severity="high").count()
    ml_count = session.query(Alert).filter_by(alert_type="anomaly_ml").count()
    packets  = session.query(TrafficRecord).count()
    session.close()
    return render_template_string(TEMPLATE, alerts=alerts, total=total,
                                  high=high, ml_count=ml_count, packets=packets)

@app.route("/api/alerts")
def api_alerts():
    session = Session()
    alerts  = session.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
    session.close()
    return jsonify([{
        "type": a.alert_type, "src": a.src_ip, "dst": a.dst_ip,
        "port": a.dst_port, "severity": a.severity,
        "desc": a.description, "time": str(a.timestamp)
    } for a in alerts])

def run_dashboard():
    app.run(host="127.0.0.1", port=5001, debug=False)
