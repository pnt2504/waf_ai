"""Backend demo — đứng sau ML WAF. Nếu WAF đúng thì attack không tới đây."""
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

HTML = """<!DOCTYPE html><html>
<head><title>Backend</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}
h1{color:#58a6ff}.box{background:#161b22;padding:1rem;border-radius:6px;margin:.5rem 0}
.dim{color:#8b949e;font-size:.85em}code{color:#79c0ff}</style></head>
<body>
<h1>✅ Backend — request đã qua WAF</h1>
<div class="box"><div class="dim">Method / Path</div>
<code>{{ method }} {{ path }}</code></div>
<div class="box"><div class="dim">WAF Headers</div>
{% for k,v in waf.items() %}<div><code>{{ k }}: {{ v }}</code></div>{% endfor %}
</div></body></html>"""

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE"])
def catch_all(path):
    waf = {k: v for k, v in request.headers if k.lower().startswith("x-waf")}
    if "application/json" in request.headers.get("Accept", ""):
        return jsonify({"ok": True, "path": f"/{path}", "waf": waf})
    return render_template_string(HTML, method=request.method,
                                  path=f"/{path}", waf=waf)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
