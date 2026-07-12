package report

import "html/template"

// dashboardTemplate is the self-contained single-file dashboard (clean light theme).
var dashboardTemplate = template.Must(template.New("dashboard").Parse(dashboardHTML))

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>adit · {{.Domain}}</title>
<style>
:root{
  --bg:#f5f6f8;--surface:#fff;--surface-2:#fafbfc;--border:#e6e8ec;
  --text:#111827;--muted:#6b7280;--muted-2:#9ca3af;
  --accent:#4f46e5;--accent-soft:#eef2ff;
  --critical:#dc2626;--critical-bg:#fef2f2;--high:#ea580c;--high-bg:#fff5ed;
  --medium:#ca8a04;--medium-bg:#fefce8;--low:#16a34a;--low-bg:#f0fdf4;
  --info:#6b7280;--info-bg:#f3f4f6;
  --radius:12px;--shadow:0 1px 2px rgba(16,24,40,.04),0 1px 3px rgba(16,24,40,.06);
}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.app{display:flex;min-height:100vh}
.sidebar{width:248px;flex:0 0 248px;background:var(--surface);border-right:1px solid var(--border);position:sticky;top:0;height:100vh;overflow-y:auto;padding:20px 12px}
.brand{display:flex;align-items:center;gap:8px;font-weight:650;font-size:15px;padding:0 8px}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--accent)}
.domain{color:var(--muted);font-size:12px;padding:2px 8px 16px;border-bottom:1px solid var(--border);margin-bottom:12px}
nav{display:flex;flex-direction:column;gap:1px}
.nav-link{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 10px;border-radius:8px;color:var(--text);text-decoration:none;font-size:13px;transition:background .12s,color .12s}
.nav-link:hover{background:var(--surface-2)}
.nav-link.active{background:var(--accent-soft);color:var(--accent);font-weight:550}
.nav-link .pill{background:var(--info-bg);color:var(--muted);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-link.active .pill{background:#fff;color:var(--accent)}
.content{flex:1;min-width:0;padding:28px 32px 60px;max-width:1420px}
.topbar{margin-bottom:24px}
h1{font-size:22px;margin:0 0 4px;font-weight:650;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:13px}
.section-title{font-size:15px;font-weight:600;margin:0 0 14px;letter-spacing:-.005em}
.block{margin-bottom:34px;scroll-margin-top:20px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(176px,1fr));gap:14px;margin-bottom:28px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;box-shadow:var(--shadow)}
.stat-value{font-size:26px;font-weight:680;letter-spacing:-.02em}
.stat-label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-top:2px}
.stat-sub{color:var(--accent);font-size:12px;margin-top:6px}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(232px,1fr));gap:14px}
.finding{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--info);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
.finding.lvl-critical{border-left-color:var(--critical)}
.finding.lvl-high{border-left-color:var(--high)}
.finding.lvl-medium{border-left-color:var(--medium)}
.finding.lvl-low{border-left-color:var(--low)}
.finding-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.finding-label{color:var(--muted);font-size:12px;font-weight:550}
.finding-value{font-size:22px;font-weight:680;margin:6px 0 2px;letter-spacing:-.02em}
.finding-detail{color:var(--muted-2);font-size:12px}
.finding .badge{text-transform:uppercase;font-size:10px}
.empty-note{color:var(--muted-2);font-size:12px;margin-top:22px}
.data-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:12px;flex-wrap:wrap}
.data-head .section-title{margin:0}
.count-pill{background:var(--info-bg);color:var(--muted);font-size:12px;font-weight:500;padding:2px 9px;border-radius:20px;margin-left:4px}
.search{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:7px 12px;font-size:13px;width:240px;max-width:100%;outline:none;transition:border .12s,box-shadow .12s}
.search:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:auto;box-shadow:var(--shadow);max-height:648px}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{position:sticky;top:0;background:var(--surface-2);color:var(--muted);text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.03em;padding:10px 14px;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none}
thead th:hover{color:var(--text)}
tbody td{padding:9px 14px;border-bottom:1px solid #f1f2f4;white-space:nowrap;max-width:440px;overflow:hidden;text-overflow:ellipsis}
tbody tr:hover{background:var(--surface-2)}
tbody tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.01em}
.badge.critical{background:var(--critical-bg);color:var(--critical)}
.badge.high{background:var(--high-bg);color:var(--high)}
.badge.medium{background:var(--medium-bg);color:var(--medium)}
.badge.low{background:var(--low-bg);color:var(--low)}
.badge.info{background:var(--info-bg);color:var(--info)}
@media(max-width:820px){.app{flex-direction:column}.sidebar{width:100%;flex-basis:auto;height:auto;position:static;border-right:none;border-bottom:1px solid var(--border)}nav{flex-direction:row;flex-wrap:wrap}.content{padding:20px}}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand"><span class="dot"></span> adit</div>
    <div class="domain">{{.Domain}}</div>
    <nav id="nav">
      <a href="#overview" class="nav-link active">Overview</a>
      {{range .Sections}}<a href="#{{.ID}}" class="nav-link">{{.Name}}<span class="pill">{{.Count}}</span></a>{{end}}
    </nav>
  </aside>
  <main class="content">
    <header class="topbar">
      <h1>Active Directory Report</h1>
      <div class="meta">{{.Domain}} &middot; DC {{.DC}} &middot; generated {{.Generated}}</div>
    </header>

    <section id="overview" class="block">
      <div class="stat-grid">
        {{range .Stats}}<div class="stat"><div class="stat-value">{{.Value}}</div><div class="stat-label">{{.Label}}</div>{{if .Sub}}<div class="stat-sub">{{.Sub}}</div>{{end}}</div>{{end}}
      </div>
      {{if .Findings}}
      <h2 class="section-title">Security Highlights</h2>
      <div class="finding-grid">
        {{range .Findings}}<div class="finding lvl-{{.Level}}"><div class="finding-top"><span class="finding-label">{{.Label}}</span><span class="badge {{.Level}}">{{.Level}}</span></div><div class="finding-value">{{.Value}}</div><div class="finding-detail">{{.Detail}}</div></div>{{end}}
      </div>
      {{end}}
      {{if .Empty}}<div class="empty-note">No records: {{range $i, $e := .Empty}}{{if $i}}, {{end}}{{$e}}{{end}}</div>{{end}}
    </section>

    {{range .Sections}}
    <section id="{{.ID}}" class="block">
      <div class="data-head">
        <h2 class="section-title">{{.Name}}<span class="count-pill">{{.Count}}</span></h2>
        <input class="search" type="search" placeholder="Filter&hellip;" data-target="tbl-{{.ID}}">
      </div>
      <div class="table-wrap">
        <table id="tbl-{{.ID}}">
          <thead><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr></thead>
          <tbody>{{range .Rows}}<tr>{{range .}}<td>{{if .Badge}}<span class="badge {{.Badge}}">{{.Text}}</span>{{else}}{{.Text}}{{end}}</td>{{end}}</tr>{{end}}</tbody>
        </table>
      </div>
    </section>
    {{end}}
  </main>
</div>
<script>
document.querySelectorAll('.search').forEach(function(input){
  input.addEventListener('input', function(){
    var q = input.value.toLowerCase();
    var tbl = document.getElementById(input.dataset.target);
    tbl.querySelectorAll('tbody tr').forEach(function(tr){
      tr.style.display = tr.textContent.toLowerCase().indexOf(q) > -1 ? '' : 'none';
    });
  });
});
document.querySelectorAll('table').forEach(function(tbl){
  tbl.querySelectorAll('thead th').forEach(function(th, idx){
    th.addEventListener('click', function(){
      var asc = th.dataset.asc !== 'true'; th.dataset.asc = asc ? 'true' : 'false';
      var body = tbl.querySelector('tbody');
      var rows = Array.prototype.slice.call(body.querySelectorAll('tr'));
      rows.sort(function(a, b){
        var x = a.children[idx].textContent.trim(), y = b.children[idx].textContent.trim();
        var nx = parseFloat(x), ny = parseFloat(y);
        if (!isNaN(nx) && !isNaN(ny) && x !== '' && y !== '') return asc ? nx - ny : ny - nx;
        return asc ? x.localeCompare(y) : y.localeCompare(x);
      });
      rows.forEach(function(r){ body.appendChild(r); });
    });
  });
});
var links = {};
document.querySelectorAll('.nav-link').forEach(function(a){ links[a.getAttribute('href').slice(1)] = a; });
var obs = new IntersectionObserver(function(entries){
  entries.forEach(function(e){
    if (e.isIntersecting) {
      for (var k in links) links[k].classList.remove('active');
      if (links[e.target.id]) links[e.target.id].classList.add('active');
    }
  });
}, {rootMargin: '-15% 0px -75% 0px'});
document.querySelectorAll('.block').forEach(function(s){ obs.observe(s); });
</script>
</body>
</html>`
