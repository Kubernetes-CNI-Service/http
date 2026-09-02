#!/usr/bin/env python3
"""Convert LLDP-style Graphviz DOT links into an interactive HTML topology."""

from __future__ import annotations

import argparse
import html
import json
import math
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path


EDGE_RE = re.compile(
    r'"((?:\\.|[^"\\])*)"\s*:\s*"((?:\\.|[^"\\])*)"\s*'
    r'--\s*'
    r'"((?:\\.|[^"\\])*)"\s*:\s*"((?:\\.|[^"\\])*)"',
    re.MULTILINE,
)
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
PORT_NUMBER_RE = re.compile(r"^(.*?)(\d+)$")


def dot_unescape(value: str) -> str:
    """Decode the small set of escapes normally used in quoted DOT IDs."""
    return value.replace('\\"', '"').replace('\\\\', '\\')


def natural_key(value: str) -> list[tuple[int, object]]:
    return [(0, int(part)) if part.isdigit() else (1, part.casefold())
            for part in re.split(r"(\d+)", value)]


def simplify_ports(ports: list[str]) -> str:
    """Collapse consecutive numeric ports, e.g. swp1,swp2,swp3 -> swp1-3."""
    unique = sorted(set(ports), key=natural_key)
    grouped: dict[str, list[int]] = defaultdict(list)
    literal: list[str] = []
    for port in unique:
        match = PORT_NUMBER_RE.match(port)
        if match:
            grouped[match.group(1)].append(int(match.group(2)))
        else:
            literal.append(port)

    result: list[str] = []
    for prefix in sorted(grouped, key=natural_key):
        numbers = sorted(set(grouped[prefix]))
        start = previous = numbers[0]
        for number in numbers[1:] + [None]:
            if number is not None and number == previous + 1:
                previous = number
                continue
            if start == previous:
                result.append(f"{prefix}{start}")
            else:
                result.append(f"{prefix}{start}-{previous}")
            if number is not None:
                start = previous = number
    result.extend(literal)
    return ", ".join(sorted(result, key=natural_key))


def parse_dot(path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    text = path.read_text(encoding="utf-8-sig")
    clean = BLOCK_COMMENT_RE.sub("", text)
    clean = re.sub(r"//.*?$|#.*?$", "", clean, flags=re.MULTILINE)

    raw_links: list[tuple[str, str, str, str]] = []
    for match in EDGE_RE.finditer(clean):
        raw_links.append(tuple(dot_unescape(item) for item in match.groups()))
    if not raw_links:
        raise ValueError("no LLDP-style links were found (expected \"device\":\"port\" -- \"device\":\"port\")")

    devices: set[str] = set()
    aggregated: dict[tuple[str, str, str], dict[str, object]] = {}
    for device_a, port_a, device_b, port_b in raw_links:
        if not device_a or not device_b or not port_a or not port_b:
            continue
        devices.update((device_a, device_b))
        if natural_key(device_a) <= natural_key(device_b):
            left, right, left_port, right_port = device_a, device_b, port_a, port_b
        else:
            left, right, left_port, right_port = device_b, device_a, port_b, port_a
        is_eth0 = left_port.casefold() == "eth0" or right_port.casefold() == "eth0"
        is_bmc = "bmc" in left_port.casefold() or "bmc" in right_port.casefold()
        link_kind = "eth0" if is_eth0 else "bmc" if is_bmc else "data"
        key = (left, right, link_kind)
        edge = aggregated.setdefault(key, {
            "source": left,
            "target": right,
            "is_eth0": is_eth0,
            "is_bmc": is_bmc,
            "is_management": is_eth0 or is_bmc,
            "source_ports": [],
            "target_ports": [],
        })
        edge["source_ports"].append(left_port)
        edge["target_ports"].append(right_port)

    nodes = [{"id": device, "label": device} for device in sorted(devices, key=natural_key)]
    edges: list[dict[str, object]] = []
    for index, edge in enumerate(aggregated.values(), 1):
        source_ports = edge.pop("source_ports")
        target_ports = edge.pop("target_ports")
        edge.update({
            "id": f"link-{index}",
            "count": len(source_ports),
            "source_label": simplify_ports(source_ports),
            "target_label": simplify_ports(target_ports),
            "links": [
                {"source_port": source_port, "target_port": target_port}
                for source_port, target_port in zip(source_ports, target_ports)
            ],
        })
        edges.append(edge)
    return nodes, edges


def parse_network_terms(value: str) -> tuple[str, ...]:
    terms = tuple(dict.fromkeys(term.strip().casefold() for term in value.split(",") if term.strip()))
    if not terms:
        raise argparse.ArgumentTypeError("provide at least one comma-separated network name")
    return terms


def filter_topology(
    nodes: list[dict[str, object]],
    edges: list[dict[str, object]],
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    def matches(device: object, terms: tuple[str, ...]) -> bool:
        name = str(device).casefold()
        return any(term in name for term in terms)

    filtered = []
    for edge in edges:
        endpoints = (edge["source"], edge["target"])
        if include and not any(matches(device, include) for device in endpoints):
            continue
        if exclude and any(matches(device, exclude) for device in endpoints):
            continue
        filtered.append(edge)
    if not filtered:
        raise ValueError("network filters removed every connection")
    used = {str(edge[key]) for edge in filtered for key in ("source", "target")}
    return [node for node in nodes if str(node["id"]) in used], filtered


def build_html(dot_path: Path, nodes: list[dict[str, object]], edges: list[dict[str, object]]) -> str:
    payload = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(dot_path.stem)
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - Network Topology</title>
<style>
:root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
* {{ box-sizing: border-box; }}
html, body {{ width: 100%; height: 100%; margin: 0; overflow: hidden; background: #08111f; color: #dbeafe; }}
#toolbar {{ position: fixed; z-index: 5; top: 14px; left: 14px; right: 14px; display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid #29405f; border-radius: 10px; background: rgba(10, 23, 42, .94); box-shadow: 0 8px 30px #0008; }}
#title {{ font-weight: 700; margin-right: auto; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
#stats {{ color: #93c5fd; font-size: 13px; white-space: nowrap; }}
button, input {{ border: 1px solid #36577e; border-radius: 6px; background: #10243e; color: #e5f2ff; padding: 7px 10px; }}
button {{ cursor: pointer; }} button:hover {{ background: #193759; }}
button:disabled {{ opacity: .45; cursor: not-allowed; }}
#save.dirty {{ border-color: #f59e0b; color: #fde68a; }}
#search {{ width: 220px; }}
#searchWrap {{ position: relative; }}
#searchResults {{ position: absolute; z-index: 8; top: calc(100% + 6px); right: 0; width: min(420px, 80vw); max-height: 280px; overflow: auto; border: 1px solid #36577e; border-radius: 8px; background: #0b1b30; box-shadow: 0 12px 30px #000a; display: none; }}
.search-result {{ padding: 8px 10px; cursor: pointer; overflow-wrap: anywhere; }}
.search-result:hover, .search-result.active {{ background: #193759; }}
.search-empty {{ padding: 8px 10px; color: #fca5a5; }}
#canvas {{ width: 100%; height: 100%; cursor: grab; user-select: none; }}
#canvas.panning {{ cursor: grabbing; }}
.link {{ stroke-opacity: .78; }}
.link.tan {{ stroke: #facc15; }}
.link.oob {{ stroke: #22c55e; }}
.link.oobofoob {{ stroke: #000; filter: drop-shadow(0 0 1px #94a3b8); }}
.link.eth0, .link.bmc {{ stroke: #ccc; stroke-opacity: .9; stroke-dasharray: 10 7; }}
.link.dim, .node.dim, .port-label.dim {{ opacity: .1; }}
.link.selected {{ stroke: #fbbf24; stroke-opacity: 1; }}
.node rect {{ stroke: #dbeafe; stroke-width: 1.5; rx: 8; filter: drop-shadow(0 2px 4px #0009); }}
.node text {{ fill: #f3f8ff; font-size: 12px; font-weight: 700; text-anchor: middle; pointer-events: none; }}
.node {{ cursor: move; }} .node.selected circle {{ stroke: #fbbf24; stroke-width: 4; }}
.node.selected rect {{ stroke: #fbbf24; stroke-width: 4; }}
.port-label {{ pointer-events: auto; cursor: pointer; }}
.port-label rect {{ fill: #07111f; fill-opacity: .94; stroke: #47739f; stroke-width: .8; rx: 4; }}
.port-label text {{ fill: #a9ddff; font-size: 10px; font-weight: 650; text-anchor: middle; dominant-baseline: middle; }}
.port-label.selected rect {{ stroke: #fbbf24; stroke-width: 2.5; fill: #3a2b08; }}
.port-label.selected text {{ fill: #fff3bd; }}
.zone-bg {{ stroke: #2e4868; stroke-width: 1.5; rx: 16; cursor: pointer; }}
.zone-bg:hover, .zone-bg.selected {{ stroke: #fbbf24; stroke-width: 4; }}
.zone-title {{ fill: #dbeafe; font-size: 26px; font-weight: 750; text-anchor: middle; cursor: pointer; }}
.zone-title.main {{ font-size: 104px; font-weight: 850; }}
.server-group rect {{ fill: #0b1728; fill-opacity: .2; stroke: #7795b8; stroke-width: 1.5; stroke-dasharray: 12 8; rx: 10; cursor: move; pointer-events: all; }}
.server-group text {{ fill: #d2e7ff; font-size: 33px; font-weight: 800; text-anchor: middle; cursor: move; pointer-events: all; }}
.server-group.selected rect {{ stroke: #fbbf24; stroke-width: 3; }}
.server-group.dim {{ opacity: .1; }}
.hidden-by-zone {{ display: none !important; }}
.layer-line {{ stroke: #38506d; stroke-width: 1; stroke-dasharray: 8 8; }}
.layer-title {{ fill: #82a9d1; font-size: 17px; font-weight: 700; }}
.layer-band {{ pointer-events: none; }}
.layer-band.spine {{ fill: #8b5cf6; fill-opacity: .07; }}
.layer-band.leaf {{ fill: #38bdf8; fill-opacity: .055; }}
#details {{ position: fixed; z-index: 5; right: 14px; bottom: 14px; width: min(440px, calc(100vw - 28px)); max-height: 34vh; overflow: auto; padding: 12px; border: 1px solid #29405f; border-radius: 10px; background: rgba(10, 23, 42, .94); display: none; font-size: 13px; }}
#details b {{ color: #fbbf24; }} #details .pair {{ padding: 5px 0; border-bottom: 1px solid #203855; }}
#legend {{ position: fixed; z-index: 6; left: 14px; bottom: 14px; width: 260px; padding: 12px 14px; border: 1px solid #29405f; border-radius: 10px; background: rgba(10, 23, 42, .96); box-shadow: 0 8px 30px #0008; display: none; font-size: 13px; }}
#legend.open {{ display: block; }}
.legend-row {{ display: flex; align-items: center; gap: 9px; margin-top: 8px; }}
.legend-line {{ width: 38px; height: 0; border-top: 4px solid; }}
.legend-line.tan {{ border-color: #facc15; }} .legend-line.oob {{ border-color: #22c55e; }} .legend-line.oobofoob {{ border-color: #000; filter: drop-shadow(0 0 1px #94a3b8); }}
.legend-line.management {{ border-color: #ccc; border-top-style: dashed; }}
.legend-box {{ width: 38px; height: 18px; border-radius: 4px; }} .legend-box.spine {{ background: #8b5cf633; border: 1px solid #9b72e8; }} .legend-box.leaf {{ background: #38bdf833; border: 1px solid #308ad2; }}
#welcome {{ position: fixed; z-index: 10; inset: 0; display: grid; place-items: center; background: #020817b8; }}
#welcome[hidden] {{ display: none; }}
#welcomeCard {{ width: min(520px, calc(100vw - 36px)); padding: 22px; border: 1px solid #47739f; border-radius: 14px; background: #0b1b30; box-shadow: 0 20px 60px #000c; }}
#welcomeCard h2 {{ margin: 0 0 10px; }} #welcomeCard p {{ color: #b9d4ef; line-height: 1.55; }}
#welcomeCard ul {{ padding-left: 20px; line-height: 1.65; }} #welcomeActions {{ display: flex; justify-content: flex-end; gap: 10px; }}
@media (max-width: 1050px) {{ #stats {{ display:none; }} }}
@media (max-width: 850px) {{ #title, #fitSelected, #actualSize, #legendButton {{ display:none; }} #search {{ width: 140px; }} #toolbar {{ gap: 7px; }} }}
</style>
</head>
<body>
<div id="toolbar">
  <div id="title">{title}</div>
  <div id="stats"></div>
  <div id="searchWrap"><input id="search" type="search" placeholder="Search device..." aria-label="Search device" autocomplete="off"><div id="searchResults" role="listbox"></div></div>
  <button id="zoomOut" title="Zoom out">−</button>
  <button id="zoomIn" title="Zoom in">+</button>
  <button id="fitAll" title="Fit the complete topology">Fit all</button>
  <button id="fitSelected" title="Fit highlighted devices" disabled>Fit selection</button>
  <button id="actualSize" title="Show at 100%">100%</button>
  <button id="ports">Hide ports</button>
  <button id="hideZone" disabled>Hide region</button>
  <button id="legendButton">Legend</button>
  <button id="helpButton" title="Show controls">?</button>
  <button id="save">Save layout</button>
  <button id="reset">Reset layout</button>
</div>
<svg id="canvas" xmlns="http://www.w3.org/2000/svg">
  <g id="viewport">
    <g id="guides"></g><g id="serverGroups"></g><g id="links"></g><g id="portLabels"></g><g id="nodes"></g>
    <g id="focusLayer"><g id="focusServerGroups"></g><g id="focusLinks"></g><g id="focusPorts"></g><g id="focusNodes"></g></g>
  </g>
</svg>
<div id="details"></div>
<div id="legend" aria-label="Topology legend">
  <b>Topology legend</b>
  <div class="legend-row"><span class="legend-line tan"></span><span>TAN connection</span></div>
  <div class="legend-row"><span class="legend-line oob"></span><span>OOB connection</span></div>
  <div class="legend-row"><span class="legend-line oobofoob"></span><span>OOBofOOB connection</span></div>
  <div class="legend-row"><span class="legend-line management"></span><span>eth0 / BMC management</span></div>
  <div class="legend-row"><span class="legend-box spine"></span><span>Spine layer</span></div>
  <div class="legend-row"><span class="legend-box leaf"></span><span>Leaf layer</span></div>
</div>
<div id="welcome" hidden><div id="welcomeCard">
  <h2>Explore this topology</h2>
  <p>The complete network is fitted on screen first. Zoom in to read device and port labels.</p>
  <ul><li>Mouse wheel: move vertically</li><li>Horizontal wheel or Shift + wheel: move horizontally</li><li>Ctrl + wheel: zoom at the pointer</li><li>Click a device, port, link, or region to highlight related paths</li><li>Drag devices or server groups, then use Save layout</li></ul>
  <div id="welcomeActions"><button id="welcomeDismiss">Do not show again</button><button id="welcomeClose">Start exploring</button></div>
</div></div>
<script>
const graph = {payload};
const svg = document.getElementById('canvas');
const viewport = document.getElementById('viewport');
const guidesGroup = document.getElementById('guides');
const serverGroupsGroup = document.getElementById('serverGroups');
const linksGroup = document.getElementById('links');
const portsGroup = document.getElementById('portLabels');
const nodesGroup = document.getElementById('nodes');
const focusServerGroups = document.getElementById('focusServerGroups');
const focusLinks = document.getElementById('focusLinks');
const focusPorts = document.getElementById('focusPorts');
const focusNodes = document.getElementById('focusNodes');
const details = document.getElementById('details');
const NS = 'http://www.w3.org/2000/svg';
let width = innerWidth, height = innerHeight, scale = 1, panX = 0, panY = 0;
let dragging = null, panning = null, portsVisible = true, portsManuallySet = false, selected = null, selectedZone = null, serverGroups = [];
const hiddenZones = new Set();
const nodeMap = new Map(graph.nodes.map(n => [n.id, n]));
const topologySignature = graph.nodes.map(n=>n.id).sort().join('|').split('').reduce((hash,ch)=>((hash*31+ch.charCodeAt(0))>>>0),0);
const savedKey = 'dot-topology:v18:' + location.pathname + ':' + topologySignature;
const welcomeKey = 'dot-topology:welcome:v1';
const PORT_AUTO_HIDE_SCALE = .3;
const NODE_W = 190, NODE_H = 114, HALF_W = NODE_W / 2, HALF_H = NODE_H / 2, LARGE_NODE_W=NODE_W*2, LARGE_NODE_H=NODE_H*2;
const ZONES = ['TAN', 'OOB', 'OOBofOOB'];
const ROLES = ['Firewall', 'Border', 'Spine', 'Leaf', 'Server'];
const TOP_ROLES = ['Firewall', 'Border'];
const layout = {{zoneWidth: 1700, overlap: 560, gap: 90, left: 130, top: 125, zoneTop: 0, activeZones: [], zoneSlots: new Map(), zoneGeometry: new Map(), zoneGuides: new Map(), roleBands: [], totalWidth: 0, totalHeight: 0}};
function nodeDimensions(node) {{return node.role==='Server'?{{width:NODE_W,height:NODE_H,halfW:HALF_W,halfH:HALF_H}}:{{width:LARGE_NODE_W,height:LARGE_NODE_H,halfW:LARGE_NODE_W/2,halfH:LARGE_NODE_H/2}};}}

function roleColor(name) {{
  const n = name.toLowerCase();
  if (n.includes('fw') || n.includes('firewall')) return '#dc4c64';
  if (n.includes('border')) return '#e98b3a';
  if (n.includes('spine')) return '#9b72e8';
  if (n.includes('leaf') || n.includes('tor')) return '#308ad2';
  if (n.includes('oob')) return '#38a576';
  if (n.includes('controller')) return '#d0a832';
  return '#506c8c';
}}
function deviceRole(name) {{
  const n=name.toLowerCase();
  if (n.includes('firewall') || /(^|[-_])fw($|[-_])/.test(n)) return 'Firewall';
  if (n.includes('border')) return 'Border';
  if (n.includes('spine') || n.includes('core')) return 'Spine';
  if (n.includes('leaf') || n.includes('tor')) return 'Leaf';
  return 'Server';
}}
function explicitZone(name) {{
  const n=name.toLowerCase().replace(/[-_ ]/g,'');
  if (n.includes('oobofoob') || n.includes('ooboob') || n.includes('oobstagingleaf03') || n.includes('netriscontroller')) return 2;
  if (n.includes('tan')) return 0;
  if (n.includes('oob')) return 1;
  if (n.includes('border') || n.includes('firewall') || /(^|[-_])fw($|[-_])/.test(name.toLowerCase())) return 0;
  return null;
}}
function edgeZone(e) {{
  const endpoints=[nodeMap.get(e.source),nodeMap.get(e.target)],regional=endpoints.filter(n=>!TOP_ROLES.includes(n.role));
  const explicit=(regional.length?regional:endpoints).map(n=>explicitZone(n.id));
  if(explicit.includes(2))return 2;
  if((e.is_eth0||e.is_bmc)&&explicit.includes(1))return 1;
  if(explicit.includes(0))return 0;
  if(explicit.includes(1))return 1;
  const common=(regional[0]?.zones||[]).find(zone=>regional.slice(1).every(n=>n.zones?.includes(zone)));
  return common??regional[0]?.zone??endpoints[0].zone??0;
}}
function edgeNetwork(e) {{
  if(e.is_eth0)return 'eth0';
  if(e.is_bmc)return 'bmc';
  const zone=edgeZone(e);
  return zone===2?'oobofoob':zone===1?'oob':'tan';
}}
function serverGroupKey(name) {{
  const key=name.replace(/\\d+$/,'').replace(/[-_ ]+$/,'');
  return key||name;
}}
function compactPorts(values) {{
  const ports=[...new Set(values)].sort((a,b)=>a.localeCompare(b,undefined,{{numeric:true}})),groups=new Map(),literal=[];
  for(const port of ports){{const match=port.match(/^(.*?)(\\d+)$/);if(!match){{literal.push(port);continue;}}if(!groups.has(match[1]))groups.set(match[1],[]);groups.get(match[1]).push(+match[2]);}}
  const result=[];
  for(const [prefix,raw] of [...groups].sort((a,b)=>a[0].localeCompare(b[0],undefined,{{numeric:true}}))){{const nums=[...new Set(raw)].sort((a,b)=>a-b);let start=nums[0],last=nums[0];for(const number of [...nums.slice(1),null]){{if(number!==null&&number===last+1){{last=number;continue;}}result.push(start===last?`${{prefix}}${{start}}`:`${{prefix}}${{start}}-${{last}}`);if(number!==null)start=last=number;}}}}
  return [...result,...literal].sort((a,b)=>a.localeCompare(b,undefined,{{numeric:true}})).join(', ');
}}
function upstreamPlacement(node) {{
  const ownRank=ROLES.indexOf(node.role),candidates=[];
  for(const edge of graph.edges){{
    const onSource=edge.source===node.id,onTarget=edge.target===node.id;if(!onSource&&!onTarget)continue;
    const parent=nodeMap.get(onSource?edge.target:edge.source),parentRank=ROLES.indexOf(parent.role);
    if(parentRank<0||parentRank>=ownRank||!Number.isFinite(parent.x))continue;
    for(const link of edge.links){{candidates.push({{rank:parentRank,x:parent.x,id:parent.id,port:onSource?link.target_port:link.source_port}});}}
  }}
  if(!candidates.length)return null;
  const nearest=Math.max(...candidates.map(item=>item.rank));
  return candidates.filter(item=>item.rank===nearest).sort((a,b)=>a.x-b.x||comparePlacementPorts(a.port,b.port)||a.id.localeCompare(b.id,undefined,{{numeric:true}}))[0];
}}
function comparePlacementPorts(a,b) {{
  const aEth0=/^eth0$/i.test(a.trim()),bEth0=/^eth0$/i.test(b.trim());if(aEth0!==bEth0)return aEth0?1:-1;return a.localeCompare(b,undefined,{{numeric:true}});
}}
function orderByUpstream(devices) {{
  const keys=new Map(devices.map(node=>[node,upstreamPlacement(node)]));
  return [...devices].sort((a,b)=>{{const ka=keys.get(a),kb=keys.get(b);if(ka&&kb)return ka.x-kb.x||comparePlacementPorts(ka.port,kb.port)||ka.id.localeCompare(kb.id,undefined,{{numeric:true}})||a.id.localeCompare(b.id,undefined,{{numeric:true}});if(ka)return -1;if(kb)return 1;return a.id.localeCompare(b.id,undefined,{{numeric:true}});}});
}}
function layerSideMargin(zoneWidth) {{return Math.max(LARGE_NODE_W/2+140,zoneWidth*.065);}}
function placeLayerDevices(devices,zoneX,zoneWidth,bandY,cellW,cellH) {{
  const margin=layerSideMargin(zoneWidth),columns=Math.max(1,Math.floor((zoneWidth-margin*2)/cellW));
  devices.forEach((node,index)=>{{const row=Math.floor(index/columns),col=index%columns,rowCount=Math.min(columns,devices.length-row*columns),left=zoneX+margin,right=zoneX+zoneWidth-margin;node.x=rowCount===1?(left+right)/2:left+(right-left)*col/(rowCount-1);node.y=bandY+150+row*cellH;}});
  return Math.max(1,Math.ceil(devices.length/columns));
}}
function serverGroupWidth(devices,cellW) {{
  const byName=new Map();for(const n of devices){{const key=serverGroupKey(n.id);if(!byName.has(key))byName.set(key,[]);byName.get(key).push(n);}}
  const widths=[...byName.values()].map(members=>serverGroupBlockWidth(members,cellW));return widths.length?80+widths.reduce((sum,width)=>sum+width,0)+Math.max(0,widths.length-1)*45:0;
}}
function serverGroupBlockWidth(members,cellW) {{
  const signatures=members.map(memberConnectionSignature),uniform=members.length>1&&signatures.every(value=>value===signatures[0]),ids=new Set((uniform?[members[0]]:members).map(n=>n.id));
  const ports=graph.edges.filter(edge=>ids.has(edge.source)||ids.has(edge.target)).length;
  return Math.max(cellW+55,ports*76+70);
}}
function placeServerGroups(devices,zoneX,zoneWidth,bandY,cellW,cellH) {{
  const byName=new Map();
  const ordered=orderByUpstream(devices);
  for(const n of ordered){{const key=serverGroupKey(n.id);if(!byName.has(key))byName.set(key,[]);byName.get(key).push(n);}}
  const entries=[...byName.entries()];
  const gap=45;
  let cursorX=40,maxHeight=0;
  for(let [key,members] of entries){{
    members=orderByUpstream(members);
    const blockW=serverGroupBlockWidth(members,cellW),blockH=members.length*cellH+110;
    const group={{id:`${{members[0].zones.join('+')}}:${{key}}`,label:key,members,zones:[...new Set(members.flatMap(n=>n.zones))],bounds:null,el:null}};serverGroups.push(group);
    members.forEach((n,row)=>{{n.x=zoneX+cursorX+blockW/2;n.y=bandY+95+row*cellH;n.serverGroup=group;}});
    cursorX+=blockW+gap;maxHeight=Math.max(maxHeight,blockH);
  }}
  return 65+maxHeight+40;
}}
function memberConnectionSignature(member) {{
  const signature=[];
  for(const e of graph.edges){{
    const onSource=e.source===member.id,onTarget=e.target===member.id;if(!onSource&&!onTarget)continue;
    const other=nodeMap.get(onSource?e.target:e.source),network=edgeNetwork(e);
    for(const link of e.links){{const ownPort=onSource?link.source_port:link.target_port;signature.push(`${{ownPort.toLowerCase()}}|${{network}}|${{other.role}}|${{other.zones?.join('+')||other.zone}}`);}}
  }}
  return signature.sort().join('||');
}}
function analyzeServerGroupPatterns() {{
  for(const e of graph.edges){{
    if(!e._base) e._base={{count:e.count,source_label:e.source_label,target_label:e.target_label,links:e.links.map(link=>({{...link}}))}};
    e.count=e._base.count;e.source_label=e._base.source_label;e.target_label=e._base.target_label;e.links=e._base.links.map(link=>({{...link}}));e.hiddenByGroup=false;e.bundleMemberIds=null;
  }}
  for(const group of serverGroups){{
    const signatures=group.members.map(memberConnectionSignature);
    group.uniform=group.members.length>1&&signatures.every(value=>value===signatures[0]);
    group.representative=group.members[0];
  }}
  for(const group of serverGroups.filter(g=>g.uniform)){{
    const memberIds=new Set(group.members.map(n=>n.id)),buckets=new Map();
    for(const e of graph.edges){{
      const sourceMember=memberIds.has(e.source),targetMember=memberIds.has(e.target);if(sourceMember===targetMember)continue;
      const groupOnSource=sourceMember,other=groupOnSource?e.target:e.source;
      const ownPorts=e.links.map(link=>groupOnSource?link.source_port:link.target_port);
      const key=`${{other}}|${{edgeNetwork(e)}}|${{compactPorts(ownPorts)}}`;
      if(!buckets.has(key))buckets.set(key,[]);buckets.get(key).push({{e,groupOnSource}});
    }}
    for(const bucket of buckets.values()){{
      const chosen=bucket.find(item=>item.e.source===group.representative.id||item.e.target===group.representative.id)||bucket[0];
      const groupPorts=[],otherPorts=[],links=[],allIds=new Set();
      for(const item of bucket){{
        item.e.hiddenByGroup=item!==chosen;
        for(const link of item.e.links){{
          const sourceDevice=item.e.source,targetDevice=item.e.target;
          groupPorts.push(item.groupOnSource?link.source_port:link.target_port);otherPorts.push(item.groupOnSource?link.target_port:link.source_port);
          links.push({{...link,source_device:sourceDevice,target_device:targetDevice}});allIds.add(sourceDevice);allIds.add(targetDevice);
        }}
      }}
      chosen.e.count=links.length;chosen.e.links=links;chosen.e.bundleMemberIds=[...allIds];
      if(chosen.groupOnSource){{chosen.e.source_label=compactPorts(groupPorts);chosen.e.target_label=compactPorts(otherPorts);}}
      else{{chosen.e.source_label=compactPorts(otherPorts);chosen.e.target_label=compactPorts(groupPorts);}}
    }}
  }}
}}
function shouldRenderEdge(e) {{
  return !e.hiddenByGroup;
}}
function visibleEdgesForNode(n) {{
  const id=n.serverGroup?.uniform?n.serverGroup.representative.id:n.id;
  return graph.edges.filter(e=>e.el&&(e.source===id||e.target===id));
}}
function assignZones() {{
  graph.nodes.forEach(n=>{{n.role=deviceRole(n.id);const explicit=explicitZone(n.id);n.zones=TOP_ROLES.includes(n.role)?[]:explicit===null?[]:[explicit];}});
  for(const n of graph.nodes.filter(n=>n.role==='Server')){{
    const connected=new Set();
    for(const e of graph.edges){{const other=e.source===n.id?nodeMap.get(e.target):e.target===n.id?nodeMap.get(e.source):null;if(!other)continue;const zone=explicitZone(other.id);if(zone!==null&&!TOP_ROLES.includes(deviceRole(other.id)))connected.add(zone);}}
    if(n.zones.includes(2))continue;
    connected.delete(2);
    if(connected.has(0)&&connected.has(1))n.zones=[0,1];
    else if(!n.zones.length)n.zones=connected.size?[...connected].sort((a,b)=>a-b):[1];
  }}
  for(let pass=0;pass<6;pass++)for(const n of graph.nodes.filter(n=>!TOP_ROLES.includes(n.role)&&!n.zones.length)){{const connected=new Set();for(const e of graph.edges){{const other=e.source===n.id?nodeMap.get(e.target):e.target===n.id?nodeMap.get(e.source):null;if(other)other.zones?.forEach(zone=>connected.add(zone));}}n.zones=[...connected].sort((a,b)=>a-b);}}
  graph.nodes.forEach(n=>{{if(!TOP_ROLES.includes(n.role)&&!n.zones.length)n.zones=[1];n.zone=n.zones[0]??0;}});
}}
function svgEl(tag, attrs={{}}) {{ const el=document.createElementNS(NS,tag); for(const [k,v] of Object.entries(attrs)) el.setAttribute(k,v); return el; }}
function escapeText(s) {{ const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }}
function effectivePortsVisible() {{return portsVisible&&(portsManuallySet||scale>=PORT_AUTO_HIDE_SCALE);}}
function updatePortVisibility() {{
  const visible=effectivePortsVisible();portsGroup.style.display=visible?'':'none';focusPorts.style.display=visible?'':'none';
  const button=document.getElementById('ports');button.textContent=visible?'Hide ports':(portsVisible&&!portsManuallySet?'Show ports (auto-hidden)':'Show ports');
  button.title=portsVisible&&!portsManuallySet&&!visible?'Port labels are automatically hidden in the overview; click to force them visible.':'';
}}
function updateTransform() {{ viewport.setAttribute('transform', `translate(${{panX}} ${{panY}}) scale(${{scale}})`);updatePortVisibility(); }}
function initialPositions() {{
  assignZones();
  for(const e of graph.edges)if(e._base){{e.count=e._base.count;e.source_label=e._base.source_label;e.target_label=e._base.target_label;e.links=e._base.links.map(link=>({{...link}}));e.hiddenByGroup=false;e.bundleMemberIds=null;}}
  serverGroups=[];graph.nodes.forEach(n=>{{n.serverGroup=null;}});
  let saved=null;try{{saved=JSON.parse(localStorage.getItem(savedKey));}}catch(_){{}}
  const cols=7, serverCellW=225, layerCellW=425, cellH=320, groupCellH=NODE_H+6;
  layout.activeZones=[...new Set(graph.nodes.filter(n=>!TOP_ROLES.includes(n.role)).flatMap(n=>n.zones))].sort((a,b)=>a-b);
  if(layout.activeZones.includes(1)&&!layout.activeZones.includes(2))layout.activeZones.push(2);
  const hasTan=layout.activeZones.includes(0),hasOob=layout.activeZones.includes(1),hasOobOfOob=layout.activeZones.includes(2),mainCount=(hasTan?1:0)+(hasOob?1:0);
  const groups=new Map();
  for(const key of ['0','1','2','shared'])for(const role of ROLES)groups.set(`${{key}}:${{role}}`,[]);
  graph.nodes.filter(n=>!TOP_ROLES.includes(n.role)).forEach(n=>{{const key=n.role==='Server'&&n.zones.includes(0)&&n.zones.includes(1)?'shared':String(n.zone);groups.get(`${{key}}:${{n.role}}`).push(n);}});
  for(const list of groups.values())list.sort((a,b)=>a.id.localeCompare(b.id,undefined,{{numeric:true}}));
  const sharedNeeded=serverGroupWidth(groups.get('shared:Server'),serverCellW),tanNeeded=serverGroupWidth(groups.get('0:Server'),serverCellW),oobNeeded=serverGroupWidth(groups.get('1:Server'),serverCellW),thirdNeeded=serverGroupWidth(groups.get('2:Server'),serverCellW);
  layout.overlap=hasTan&&hasOob?Math.max(650,sharedNeeded):0;
  const layerCount=zone=>Math.max(...['Spine','Leaf'].map(role=>groups.get(`${{zone}}:${{role}}`).length),1),layerWidth=zone=>layerCount(zone)*layerCellW+2*(LARGE_NODE_W/2+140);
  const exclusiveWidth=Math.max(3600,tanNeeded,oobNeeded,layerWidth(0),layerWidth(1),Math.max(0,thirdNeeded*2-layout.overlap),Math.max(0,layerWidth(2)*2-layout.overlap));
  layout.zoneWidth=mainCount===2?exclusiveWidth+layout.overlap:Math.max(1700,exclusiveWidth,thirdNeeded*2);
  layout.totalWidth=layout.left*2+(mainCount===2?2*exclusiveWidth+layout.overlap:layout.zoneWidth);
  const tanX=layout.left,oobX=hasTan&&hasOob?layout.left+exclusiveWidth:layout.left;
  const tanContentX=tanX,oobContentX=hasTan&&hasOob?oobX+layout.overlap:oobX,tanContentWidth=hasTan&&hasOob?exclusiveWidth:layout.zoneWidth,oobContentWidth=hasTan&&hasOob?exclusiveWidth:layout.zoneWidth;
  const tanUpperX=tanX,oobUpperX=hasTan&&hasOob?oobX+layout.overlap/2:oobX,upperWidth=hasTan&&hasOob?exclusiveWidth+layout.overlap/2:layout.zoneWidth;
  let y=layout.top;
  layout.roleBands=[];
  for(const role of TOP_ROLES) {{
    const devices=orderByUpstream(graph.nodes.filter(n=>n.role===role));
    if(!devices.length)continue;
    const rows=Math.ceil(devices.length/cols),bandH=Math.max(420,rows*cellH+150);layout.roleBands.push({{role,y,height:bandH,outside:true}});
    devices.forEach((n,i)=>{{const row=Math.floor(i/cols),col=i%cols,rowCount=Math.min(cols,devices.length-row*cols),used=(rowCount-1)*layerCellW;n.x=layout.totalWidth/2-used/2+col*layerCellW;n.y=y+150+row*cellH;}});
    y+=bandH;
  }}
  layout.zoneGeometry=new Map();
  if(hasOobOfOob){{
    const zoneWidth=layout.zoneWidth/2,zoneX=hasOob?oobX+layout.zoneWidth/4:(layout.totalWidth-zoneWidth)/2,zoneTop=y-10,thirdDevices=['Spine','Leaf','Server'].flatMap(role=>groups.get(`2:${{role}}`));let zy=zoneTop+75;
    if(thirdDevices.length){{for(const role of ['Spine','Leaf']){{const list=orderByUpstream(groups.get(`2:${{role}}`));if(!list.length)continue;const rows=placeLayerDevices(list,zoneX,zoneWidth,zy,layerCellW,cellH);zy+=Math.max(750,rows*cellH+580);}}const serverNeed=placeServerGroups(groups.get('2:Server'),zoneX,zoneWidth,zy,serverCellW,groupCellH);zy+=Math.max(190,serverNeed);}}
    else zy=zoneTop+260;
    layout.zoneGeometry.set(2,{{x:zoneX,width:zoneWidth,minY:zoneTop,maxY:zy+30}});y=zy+95;
  }}
  const mainZones=[0,1].filter(zone=>layout.activeZones.includes(zone));
  layout.zoneTop=y-10;
  if(mainZones.length){{
    const sharedX=hasTan&&hasOob?oobX:null;let serverTop=null;y=layout.zoneTop+230;
    for(const role of ROLES.filter(role=>!TOP_ROLES.includes(role))){{
      if(role==='Server'){{serverTop=y-30;const band={{role,y,height:260}};layout.roleBands.push(band);let needed=260;if(hasTan)needed=Math.max(needed,placeServerGroups(groups.get('0:Server'),tanContentX,tanContentWidth,y,serverCellW,groupCellH));if(hasOob)needed=Math.max(needed,placeServerGroups(groups.get('1:Server'),oobContentX,oobContentWidth,y,serverCellW,groupCellH));if(sharedX!==null)needed=Math.max(needed,placeServerGroups(groups.get('shared:Server'),sharedX,layout.overlap,y,serverCellW,groupCellH));band.height=needed;y+=needed;continue;}}
      const shared=orderByUpstream(groups.get(`shared:${{role}}`)),sharedCols=Math.max(1,Math.floor((layout.overlap-70)/layerCellW)),zoneColumns=Math.max(1,Math.floor((upperWidth-2*layerSideMargin(upperWidth))/layerCellW));let rows=Math.max(1,Math.ceil(shared.length/sharedCols));for(const zone of mainZones)rows=Math.max(rows,Math.ceil(groups.get(`${{zone}}:${{role}}`).length/zoneColumns));const bandH=Math.max(810,rows*cellH+635);layout.roleBands.push({{role,y,height:bandH}});
      for(const zone of mainZones){{const raw=groups.get(`${{zone}}:${{role}}`),list=orderByUpstream(raw),zoneX=zone===0?tanUpperX:oobUpperX,zoneWidth=upperWidth;placeLayerDevices(list,zoneX,zoneWidth,y,layerCellW,cellH);}}
      shared.forEach((n,i)=>{{const row=Math.floor(i/sharedCols),col=i%sharedCols,rowCount=Math.min(sharedCols,shared.length-row*sharedCols),used=(rowCount-1)*layerCellW;n.x=sharedX+layout.overlap/2-used/2+col*layerCellW;n.y=y+150+row*cellH;}});y+=bandH;
    }}
    const mainBottom=y+70;if(hasTan)layout.zoneGeometry.set(0,{{x:tanX,width:layout.zoneWidth,minY:layout.zoneTop,maxY:mainBottom,serverTop,upperX:tanUpperX,upperWidth}});if(hasOob)layout.zoneGeometry.set(1,{{x:oobX,width:layout.zoneWidth,minY:layout.zoneTop,maxY:mainBottom,serverTop,upperX:oobUpperX,upperWidth}});
  }}
  layout.totalHeight=Math.max(y+100,...[...layout.zoneGeometry.values()].map(g=>g.maxY+70));
  analyzeServerGroupPatterns();
  if(saved)graph.nodes.forEach(n=>{{const p=saved[n.id];if(p){{n.x=p.x;n.y=p.y;}}}});
}}
function fitView() {{
  const toolbar=80, sx=(width-30)/layout.totalWidth, sy=(height-toolbar-20)/layout.totalHeight;
  scale=Math.max(.12,Math.min(1,Math.min(sx,sy)));panX=(width-layout.totalWidth*scale)/2;panY=toolbar;
  updateTransform();
}}
function fitVisibleView() {{
  const visibleNodes=graph.nodes.filter(n=>TOP_ROLES.includes(n.role)||n.zones.some(zone=>!hiddenZones.has(zone)));
  if(!visibleNodes.length)return;
  let minX=Math.min(...visibleNodes.map(n=>n.x-nodeDimensions(n).halfW))-90,maxX=Math.max(...visibleNodes.map(n=>n.x+nodeDimensions(n).halfW))+90;
  let minY=Math.min(...visibleNodes.map(n=>n.y-nodeDimensions(n).halfH))-90,maxY=Math.max(...visibleNodes.map(n=>n.y+nodeDimensions(n).halfH))+90;
  for(const [zone,guide] of layout.zoneGuides){{if(hiddenZones.has(zone))continue;for(const part of guide.parts){{const x=+part.getAttribute('x'),y=+part.getAttribute('y'),w=+part.getAttribute('width'),h=+part.getAttribute('height');minX=Math.min(minX,x);maxX=Math.max(maxX,x+w);minY=Math.min(minY,y);maxY=Math.max(maxY,y+h);}}}}
  const toolbar=82,availableH=height-toolbar-18,boundsW=Math.max(1,maxX-minX),boundsH=Math.max(1,maxY-minY);
  const widthFit=(width-28)/boundsW,normalFit=Math.min(widthFit,availableH/boundsH);
  scale=Math.max(.12,Math.min(1.4,hiddenZones.size?Math.min(widthFit,normalFit*1.65):normalFit));
  panX=(width-boundsW*scale)/2-minX*scale;
  panY=boundsH*scale>availableH?toolbar-minY*scale:toolbar+(availableH-boundsH*scale)/2-minY*scale;updateTransform();
}}
function fitNodes(nodes) {{
  if(!nodes.length)return false;let minX=Infinity,maxX=-Infinity,minY=Infinity,maxY=-Infinity;
  for(const n of nodes){{const d=nodeDimensions(n);minX=Math.min(minX,n.x-d.halfW);maxX=Math.max(maxX,n.x+d.halfW);minY=Math.min(minY,n.y-d.halfH);maxY=Math.max(maxY,n.y+d.halfH);}}
  const padding=110,toolbar=82;minX-=padding;maxX+=padding;minY-=padding;maxY+=padding;const boundsW=Math.max(1,maxX-minX),boundsH=Math.max(1,maxY-minY),availableH=height-toolbar-18;
  scale=Math.max(.18,Math.min(2.5,Math.min((width-28)/boundsW,availableH/boundsH)));panX=(width-boundsW*scale)/2-minX*scale;panY=toolbar+(availableH-boundsH*scale)/2-minY*scale;updateTransform();return true;
}}
function zoomAtCenter(factor) {{const x=width/2,y=height/2,old=scale;scale=Math.max(.12,Math.min(4,scale*factor));panX=x-(x-panX)*scale/old;panY=y-(y-panY)*scale/old;updateTransform();}}
function edgeTouchesHiddenZone(e) {{
  return hiddenZones.has(e.zoneClass??edgeZone(e));
}}
function applyZoneVisibility() {{
  clearSelection();
  for(const [zone,guide] of layout.zoneGuides){{const hidden=hiddenZones.has(zone);guide.parts.forEach(part=>part.classList.toggle('hidden-by-zone',hidden));guide.title.classList.toggle('hidden-by-zone',hidden);}}
  graph.nodes.forEach(n=>n.el.classList.toggle('hidden-by-zone',!TOP_ROLES.includes(n.role)&&n.zones.every(zone=>hiddenZones.has(zone))));
  serverGroups.forEach(group=>group.el.classList.toggle('hidden-by-zone',group.zones.every(zone=>hiddenZones.has(zone))));
  graph.edges.filter(e=>e.el).forEach(e=>{{const hidden=edgeTouchesHiddenZone(e);e.el.classList.toggle('hidden-by-zone',hidden);e.aLabel.classList.toggle('hidden-by-zone',hidden);e.bLabel.classList.toggle('hidden-by-zone',hidden);}});
  updateHideButton();fitVisibleView();
}}
function updateHideButton() {{
  const button=document.getElementById('hideZone');
  if(selectedZone!==null&&!hiddenZones.has(selectedZone)){{button.disabled=false;button.textContent=`Hide ${{ZONES[selectedZone]}}`;}}
  else if(hiddenZones.size){{button.disabled=false;button.textContent='Show all regions';}}
  else{{button.disabled=true;button.textContent='Hide region';}}
}}
function drawGuides() {{
  guidesGroup.replaceChildren();layout.zoneGuides=new Map();
  const colors=['#102a3a','#15283b','#24243d'];
  for(const z of layout.activeZones) {{
    const geometry=layout.zoneGeometry.get(z);if(!geometry)continue;
    const parts=[],bases=[];
    if(geometry.serverTop!==null&&geometry.serverTop!==undefined){{
      parts.push(svgEl('rect',{{class:'zone-bg',x:geometry.upperX,y:geometry.minY,width:geometry.upperWidth,height:geometry.serverTop-geometry.minY,fill:colors[z],'fill-opacity':'.42'}}));
      bases.push({{minX:geometry.upperX,maxX:geometry.upperX+geometry.upperWidth,minY:geometry.minY,maxY:geometry.serverTop}});
      parts.push(svgEl('rect',{{class:'zone-bg',x:geometry.x,y:geometry.serverTop,width:geometry.width,height:geometry.maxY-geometry.serverTop,fill:colors[z],'fill-opacity':'.42'}}));
      bases.push({{minX:geometry.x,maxX:geometry.x+geometry.width,minY:geometry.serverTop,maxY:geometry.maxY}});
    }}else{{parts.push(svgEl('rect',{{class:'zone-bg',x:geometry.x,y:geometry.minY,width:geometry.width,height:geometry.maxY-geometry.minY,fill:colors[z],'fill-opacity':'.42'}}));bases.push({{minX:geometry.x,maxX:geometry.x+geometry.width,minY:geometry.minY,maxY:geometry.maxY}});}}
    const title=svgEl('text',{{class:`zone-title ${{z<2?'main':''}}`,x:(geometry.upperX??geometry.x)+(geometry.upperWidth??geometry.width)/2,y:geometry.minY+(z<2?120:43)}});title.textContent=ZONES[z];
    const guide={{parts,title,bases,split:parts.length===2}};layout.zoneGuides.set(z,guide);
    parts.forEach(part=>part.addEventListener('click',ev=>{{ev.stopPropagation();selectZone(z,guide);}}));title.addEventListener('click',ev=>{{ev.stopPropagation();selectZone(z,guide);}});
    guidesGroup.append(...parts,title);
  }}
  for(const band of layout.roleBands) {{
    if(band.role==='Spine'||band.role==='Leaf'){{const background=svgEl('rect',{{class:`layer-band ${{band.role.toLowerCase()}}`,x:layout.left-85,y:band.y-18,width:layout.totalWidth-layout.left*2+125,height:band.height}});guidesGroup.appendChild(background);}}
    const line=svgEl('line',{{class:'layer-line',x1:layout.left-85,y1:band.y-18,x2:layout.totalWidth-layout.left+40,y2:band.y-18}});guidesGroup.appendChild(line);
    const title=svgEl('text',{{class:'layer-title',x:18,y:band.y+14}});title.textContent=band.role;guidesGroup.appendChild(title);
  }}
}}
function makePortLabel(text) {{
  const g=svgEl('g',{{class:'port-label'}}),r=svgEl('rect'),t=svgEl('text',{{y:'1'}});t.textContent=text;
  const w=Math.max(34,text.length*6.1+12);r.setAttribute('x',-w/2);r.setAttribute('y',-10);r.setAttribute('width',w);r.setAttribute('height',20);g.labelWidth=w;g.append(r,t);return g;
}}
function nodeLabel(group,label,node) {{
  const text=svgEl('text',{{x:'0'}});
  let lines=[label];
  if(label.length>15){{const middle=label.length/2,cuts=[...label.matchAll(/[-_ ]/g)].map(match=>match.index).filter(index=>index>2&&index<label.length-3);const cut=cuts.length?cuts.sort((a,b)=>Math.abs(a-middle)-Math.abs(b-middle))[0]:Math.floor(middle);lines=[label.slice(0,cut+1).trim(),label.slice(cut+1).trim()];}}
  lines=lines.slice(0,2);const longest=Math.max(...lines.map(line=>line.length));
  const dimensions=nodeDimensions(node),fontSize=Math.max(1,Math.min(51,(dimensions.width-18)/Math.max(1,longest*.56),(dimensions.height-18)/Math.max(1,lines.length*1.18)));
  const lineHeight=fontSize*1.18;text.style.fontSize=`${{fontSize}}px`;
  lines.forEach((line,i)=>{{const span=svgEl('tspan',{{x:'0',y:String((i-(lines.length-1)/2)*lineHeight+fontSize*.32)}});span.textContent=line;text.appendChild(span);}});group.appendChild(text);
}}
function drawServerGroups() {{
  serverGroupsGroup.replaceChildren();
  for(const group of serverGroups){{group.el=svgEl('g',{{class:'server-group'}});group.box=svgEl('rect');group.title=svgEl('text');group.title.textContent=group.uniform?`${{group.label}} × ${{group.members.length}}`:group.label;group.el.append(group.box,group.title);group.el.addEventListener('pointerdown',ev=>startGroupDrag(ev,group));group.el.addEventListener('click',ev=>{{ev.stopPropagation();selectServerGroup(group);}});serverGroupsGroup.appendChild(group.el);}}
}}
function connectionSide(node,other) {{
  const ownRank=ROLES.indexOf(node.role),otherRank=ROLES.indexOf(other.role);if(otherRank<ownRank)return 'top';if(otherRank>ownRank)return 'bottom';if(other.x<node.x)return 'left';if(other.x>node.x)return 'right';return other.y<node.y?'top':'bottom';
}}
function endpointSide(node,other,edge,onSource) {{
  const ownPorts=edge.links.map(link=>onSource?link.source_port:link.target_port);
  if(['Firewall','Border','Spine','Leaf'].includes(node.role)&&ownPorts.some(port=>port.toLowerCase()==='eth0')){{
    if(other.x<node.x)return 'left';if(other.x>node.x)return 'right';
    return other.id.localeCompare(node.id,undefined,{{numeric:true}})<0?'left':'right';
  }}
  return connectionSide(node,other);
}}
function assignSideSlots(target,buckets,bounds,horizontalPadding,verticalPadding) {{
  target.portSlots=new Map();for(const [side,items] of Object.entries(buckets)){{const horizontal=side==='top'||side==='bottom',coordinate=item=>horizontal?item.otherX:item.otherY;items.sort((a,b)=>coordinate(a)-coordinate(b)||a.label.localeCompare(b.label,undefined,{{numeric:true}})||a.key.localeCompare(b.key));const start=horizontal?bounds.minX+horizontalPadding:bounds.minY+verticalPadding,end=horizontal?bounds.maxX-horizontalPadding:bounds.maxY-verticalPadding,laneEnds=[];items.forEach((item,index)=>{{const position=items.length===1?(start+end)/2:start+(end-start)*index/(items.length-1),span=horizontal?Math.max(34,item.label.length*6.1+12):20,itemStart=position-span/2,itemEnd=position+span/2;let lane=laneEnds.findIndex(last=>itemStart>=last+6);if(lane<0){{lane=laneEnds.length;laneEnds.push(itemEnd);}}else laneEnds[lane]=itemEnd;target.portSlots.set(item.key,{{side,index,total:items.length,lane}});}});}}
}}
function prepareEndpointSlots(edges) {{
  for(const node of graph.nodes){{const dimensions=nodeDimensions(node),bounds={{minX:node.x-dimensions.halfW,maxX:node.x+dimensions.halfW,minY:node.y-dimensions.halfH,maxY:node.y+dimensions.halfH}},horizontalPadding=Math.min(38,dimensions.halfW*.3),verticalPadding=Math.min(24,dimensions.halfH*.3),buckets={{top:[],right:[],bottom:[],left:[]}};for(const edge of edges){{if(edge.source===node.id){{const other=nodeMap.get(edge.target);if(node.serverGroup&&other.serverGroup!==node.serverGroup)continue;buckets[endpointSide(node,other,edge,true)].push({{key:`${{edge.id}}:source`,label:edge.source_label,otherX:other.x,otherY:other.y}});}}else if(edge.target===node.id){{const other=nodeMap.get(edge.source);if(node.serverGroup&&other.serverGroup!==node.serverGroup)continue;buckets[endpointSide(node,other,edge,false)].push({{key:`${{edge.id}}:target`,label:edge.target_label,otherX:other.x,otherY:other.y}});}}}}assignSideSlots(node,buckets,bounds,horizontalPadding,verticalPadding);}}
  for(const group of serverGroups){{const buckets={{top:[],right:[],bottom:[],left:[]}};for(const edge of edges){{const source=nodeMap.get(edge.source),target=nodeMap.get(edge.target);if(source.serverGroup===group&&target.serverGroup!==group)buckets[connectionSide(source,target)].push({{key:`${{edge.id}}:source`,label:edge.source_label,otherX:target.x,otherY:target.y}});if(target.serverGroup===group&&source.serverGroup!==group)buckets[connectionSide(target,source)].push({{key:`${{edge.id}}:target`,label:edge.target_label,otherX:source.x,otherY:source.y}});}}assignSideSlots(group,buckets,group.bounds,45,18);}}
}}
function updateServerGroupBounds() {{
  for(const group of serverGroups){{
    const minX=Math.min(...group.members.map(n=>n.x-HALF_W))-32,maxX=Math.max(...group.members.map(n=>n.x+HALF_W))+32;
    const minY=Math.min(...group.members.map(n=>n.y-HALF_H))-20,maxY=Math.max(...group.members.map(n=>n.y+HALF_H))+20;
    group.bounds={{minX,maxX,minY,maxY}};
    for(const [key,value] of Object.entries({{x:minX,y:minY,width:maxX-minX,height:maxY-minY}}))group.box.setAttribute(key,value);
    updateGroupTitle(group,minX,maxX,maxY);
  }}
}}
function updateGroupTitle(group,minX,maxX,maxY) {{
  const label=group.uniform?`${{group.label}} × ${{group.members.length}}`:group.label,maxWidth=maxX-minX-24,middle=label.length/2,cuts=[...label.matchAll(/[-_ ]/g)].map(match=>match.index).filter(index=>index>2&&index<label.length-3);let lines=[label];
  if(label.length*33*.58>maxWidth){{const cut=cuts.length?cuts.sort((a,b)=>Math.abs(a-middle)-Math.abs(b-middle))[0]:Math.floor(middle);lines=[label.slice(0,cut+1).trim(),label.slice(cut+1).trim()];}}
  const longest=Math.max(...lines.map(line=>line.length)),fontSize=Math.max(1,Math.min(33,maxWidth/Math.max(1,longest*.58))),lineHeight=fontSize*1.18,x=(minX+maxX)/2;group.title.style.fontSize=`${{fontSize}}px`;group.title.replaceChildren();lines.forEach((line,index)=>{{const span=svgEl('tspan',{{x,y:maxY+36+index*lineHeight}});span.textContent=line;group.title.appendChild(span);}});
}}
function updateZoneBounds() {{
  for(const [zone,guide] of layout.zoneGuides){{
    const allMembers=graph.nodes.filter(n=>n.zones.includes(zone)&&!TOP_ROLES.includes(n.role)),margin=55;
    const memberSets=guide.split?[allMembers.filter(n=>n.role!=='Server'),allMembers.filter(n=>n.role==='Server')]:[allMembers];
    guide.parts.forEach((part,index)=>{{const base=guide.bases[index],members=memberSets[index];let minX=base.minX,maxX=base.maxX,minY=base.minY,maxY=base.maxY;for(const n of members){{const dimensions=nodeDimensions(n);minX=Math.min(minX,n.x-dimensions.halfW-margin);maxX=Math.max(maxX,n.x+dimensions.halfW+margin);if(zone===2)minY=Math.min(minY,n.y-dimensions.halfH-margin);maxY=Math.max(maxY,n.y+dimensions.halfH+margin);}}if(!guide.split||index===1)for(const group of serverGroups.filter(g=>g.zones.includes(zone))){{const b=group.bounds;minX=Math.min(minX,b.minX-18);maxX=Math.max(maxX,b.maxX+18);if(zone===2)minY=Math.min(minY,b.minY-18);maxY=Math.max(maxY,b.maxY+88);}}for(const [key,value] of Object.entries({{x:minX,y:minY,width:maxX-minX,height:maxY-minY}}))part.setAttribute(key,value);}});
    const titlePart=guide.parts[0],titleX=+titlePart.getAttribute('x')+(+titlePart.getAttribute('width'))/2;guide.title.setAttribute('x',titleX);guide.title.setAttribute('y',+titlePart.getAttribute('y')+(zone<2?120:43));
  }}
  const third=layout.zoneGuides.get(2),oob=layout.zoneGuides.get(1);
  if(third&&oob){{const part=third.parts[0],oobPart=oob.parts[0],center=+part.getAttribute('x')+(+part.getAttribute('width'))/2,target=(+oobPart.getAttribute('width'))/2;part.setAttribute('x',center-target/2);part.setAttribute('width',target);third.title.setAttribute('x',center);}}
}}
function sideSlotPoint(bounds,slot,horizontalPadding,verticalPadding) {{
  const horizontal=slot.side==='top'||slot.side==='bottom',start=horizontal?bounds.minX+horizontalPadding:bounds.minY+verticalPadding,end=horizontal?bounds.maxX-horizontalPadding:bounds.maxY-verticalPadding,position=slot.total===1?(start+end)/2:start+(end-start)*slot.index/(slot.total-1);if(slot.side==='top')return {{x:position,y:bounds.minY}};if(slot.side==='bottom')return {{x:position,y:bounds.maxY}};if(slot.side==='left')return {{x:bounds.minX,y:position}};return {{x:bounds.maxX,y:position}};
}}
function portLabelPlacement(label,x,y,slot,ux,uy,segmentLength) {{
  const labelWidth=label.labelWidth;
  const projectedHalf=Math.abs(ux)*labelWidth/2+Math.abs(uy)*10,lane=slot?.lane??0;
  const baseDistance=Math.min(projectedHalf+10+lane*26,Math.max(14,segmentLength*.38));
  return {{label,x,y,ux,uy,labelWidth,segmentLength,baseDistance}};
}}
function positionPortLabels(placements) {{
  const occupied=[],overlaps=(a,b)=>a.left<b.right+6&&a.right+6>b.left&&a.top<b.bottom+6&&a.bottom+6>b.top;
  placements.sort((a,b)=>a.segmentLength-b.segmentLength||a.labelWidth-b.labelWidth);
  for(const p of placements){{
    const maxDistance=Math.max(p.baseDistance,p.segmentLength*.45),distances=[];
    for(let distance=p.baseDistance;distance<=maxDistance+.1;distance+=28)distances.push(distance);
    if(distances.at(-1)<maxDistance-1)distances.push(maxDistance);
    let chosen=null;
    for(const perpendicular of [0,-24,24,-48,48]){{
      for(const distance of distances){{const x=p.x+p.ux*distance-p.uy*perpendicular,y=p.y+p.uy*distance+p.ux*perpendicular,box={{left:x-p.labelWidth/2,right:x+p.labelWidth/2,top:y-10,bottom:y+10}};if(!occupied.some(other=>overlaps(box,other))){{chosen={{x,y,box}};break;}}}}
      if(chosen)break;
    }}
    if(!chosen){{const distance=p.baseDistance,x=p.x+p.ux*distance,y=p.y+p.uy*distance;chosen={{x,y,box:{{left:x-p.labelWidth/2,right:x+p.labelWidth/2,top:y-10,bottom:y+10}}}};}}
    occupied.push(chosen.box);p.label.setAttribute('transform',`translate(${{chosen.x}} ${{chosen.y}})`);
  }}
}}
function endpointBoundary(n,ux,uy,useGroup,slotKey) {{
  if(useGroup&&n.serverGroup?.bounds){{
    const b=n.serverGroup.bounds,slot=n.serverGroup.portSlots?.get(slotKey);
    if(slot)return sideSlotPoint(b,slot,45,18);
    const tx=ux>0?(b.maxX-n.x)/ux:ux<0?(b.minX-n.x)/ux:Infinity;
    const ty=uy>0?(b.maxY-n.y)/uy:uy<0?(b.minY-n.y)/uy:Infinity;
    const distance=Math.max(0,Math.min(tx,ty));return {{x:n.x+ux*distance,y:n.y+uy*distance}};
  }}
  const dimensions=nodeDimensions(n),slot=n.portSlots?.get(slotKey);if(slot)return sideSlotPoint({{minX:n.x-dimensions.halfW,maxX:n.x+dimensions.halfW,minY:n.y-dimensions.halfH,maxY:n.y+dimensions.halfH}},slot,Math.min(38,dimensions.halfW*.3),Math.min(24,dimensions.halfH*.3));const distance=Math.min(dimensions.halfW/Math.max(Math.abs(ux),.0001),dimensions.halfH/Math.max(Math.abs(uy),.0001));
  return {{x:n.x+ux*distance,y:n.y+uy*distance}};
}}
function draw() {{
  restoreFocus();drawGuides();drawServerGroups();linksGroup.replaceChildren(); portsGroup.replaceChildren(); nodesGroup.replaceChildren();
  graph.edges.forEach(e=>{{e.el=e.aLabel=e.bLabel=null;}});const visibleEdges=graph.edges.filter(shouldRenderEdge);
  updateServerGroupBounds();
  prepareEndpointSlots(visibleEdges);
  const degree=new Map(graph.nodes.map(n=>[n.id,0])),incident=new Map(graph.nodes.map(n=>[n.id,0]));
  visibleEdges.forEach(e=>{{degree.set(e.source,degree.get(e.source)+1);degree.set(e.target,degree.get(e.target)+1);}});
  for(const e of visibleEdges) {{
    const a=nodeMap.get(e.source),b=nodeMap.get(e.target);
    e.zoneClass=edgeZone(e);e.network=edgeNetwork(e);
    e.el=svgEl('line',{{class:`link ${{e.network}}`,'stroke-width':String(2+Math.log2(e.count+1)*2),x1:a.x,y1:a.y,x2:b.x,y2:b.y}});
    e.el.addEventListener('click',ev=>{{ev.stopPropagation();selectEdge(e);}}); linksGroup.appendChild(e.el);
    e.sourceOrder=incident.get(e.source);e.sourceDegree=degree.get(e.source);incident.set(e.source,e.sourceOrder+1);
    e.targetOrder=incident.get(e.target);e.targetDegree=degree.get(e.target);incident.set(e.target,e.targetOrder+1);
    e.aLabel=makePortLabel(e.source_label);e.aLabel.addEventListener('click',ev=>{{ev.stopPropagation();selectEdge(e);}});portsGroup.appendChild(e.aLabel);
    e.bLabel=makePortLabel(e.target_label);e.bLabel.addEventListener('click',ev=>{{ev.stopPropagation();selectEdge(e);}});portsGroup.appendChild(e.bLabel);
  }}
  for(const n of graph.nodes) {{
    n.el=svgEl('g',{{class:'node'}});const dimensions=nodeDimensions(n),box=svgEl('rect',{{x:-dimensions.halfW,y:-dimensions.halfH,width:dimensions.width,height:dimensions.height,fill:roleColor(n.id)}});n.el.append(box);nodeLabel(n.el,n.label,n);
    n.el.addEventListener('pointerdown',ev=>startDrag(ev,n));
    n.el.addEventListener('click',ev=>{{ev.stopPropagation();selectNode(n);}});
    n.el.addEventListener('dblclick',ev=>{{ev.stopPropagation();n.serverGroup?selectServerGroup(n.serverGroup):selectNode(n);}});
    nodesGroup.appendChild(n.el);
  }}
  updatePositions();
}}
function updatePositions() {{
  for(const n of graph.nodes) n.el.setAttribute('transform',`translate(${{n.x}} ${{n.y}})`);
  updateServerGroupBounds();
  updateZoneBounds();
  prepareEndpointSlots(graph.edges.filter(e=>e.el));
  const labelPlacements=[];
  for(const e of graph.edges) {{
    if(!e.el)continue;
    const a=nodeMap.get(e.source),b=nodeMap.get(e.target),dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1,ux=dx/d,uy=dy/d;
    const sharedGroup=a.serverGroup&&a.serverGroup===b.serverGroup;
    const start=endpointBoundary(a,ux,uy,!sharedGroup,`${{e.id}}:source`),end=endpointBoundary(b,-ux,-uy,!sharedGroup,`${{e.id}}:target`);
    const ax=start.x,ay=start.y,bx=end.x,by=end.y,linkDx=bx-ax,linkDy=by-ay,segmentLength=Math.sqrt(linkDx*linkDx+linkDy*linkDy)||1,linkUx=linkDx/segmentLength,linkUy=linkDy/segmentLength;
    for(const [k,v] of Object.entries({{x1:ax,y1:ay,x2:bx,y2:by}})) e.el.setAttribute(k,v);
    const aSlots=!sharedGroup&&a.serverGroup?a.serverGroup.portSlots:a.portSlots,bSlots=!sharedGroup&&b.serverGroup?b.serverGroup.portSlots:b.portSlots,aSlot=aSlots?.get(`${{e.id}}:source`),bSlot=bSlots?.get(`${{e.id}}:target`);
    labelPlacements.push(portLabelPlacement(e.aLabel,ax,ay,aSlot,linkUx,linkUy,segmentLength),portLabelPlacement(e.bLabel,bx,by,bSlot,-linkUx,-linkUy,segmentLength));
  }}
  positionPortLabels(labelPlacements);
}}
function graphPoint(ev) {{ const r=svg.getBoundingClientRect();return {{x:(ev.clientX-r.left-panX)/scale,y:(ev.clientY-r.top-panY)/scale}}; }}
function startDrag(ev,n) {{ ev.stopPropagation();const p=graphPoint(ev);dragging={{n,dx:n.x-p.x,dy:n.y-p.y,start:p,moved:false}}; }}
function startGroupDrag(ev,group) {{
  ev.stopPropagation();const p=graphPoint(ev);
  dragging={{group,start:p,moved:false,origins:group.members.map(n=>({{n,x:n.x,y:n.y}}))}};
}}
function expandTanLeftWithDrag(movedNodes) {{
  if(!movedNodes.some(n=>n.zones.includes(0)))return;const guide=layout.zoneGuides.get(0);if(!guide)return;
  const relevantPart=movedNodes.every(n=>n.role==='Server')&&guide.parts[1]?guide.parts[1]:guide.parts[0],currentMin=+relevantPart.getAttribute('x'),targetMin=Math.min(...movedNodes.map(n=>n.x-nodeDimensions(n).halfW-55));if(targetMin>=currentMin)return;
  const delta=targetMin-currentMin,moved=new Set(movedNodes);
  for(const role of ROLES){{if(movedNodes.some(n=>n.role===role))continue;const candidates=graph.nodes.filter(n=>n.role===role&&!moved.has(n));if(!candidates.length)continue;const anchor=candidates.reduce((left,n)=>n.x<left.x?n:left,candidates[0]),targets=anchor.serverGroup?.members||[anchor];if(targets.some(n=>moved.has(n)))continue;targets.forEach(n=>{{n.x+=delta;}});}}
}}
svg.addEventListener('pointermove',ev=>{{ if(dragging){{const p=graphPoint(ev),dx=p.x-dragging.start.x,dy=p.y-dragging.start.y;dragging.moved=dragging.moved||Math.abs(dx)>1||Math.abs(dy)>1;let movedNodes;if(dragging.group){{dragging.origins.forEach(item=>{{item.n.x=item.x+dx;item.n.y=item.y+dy;}});movedNodes=dragging.group.members;}}else{{dragging.n.x=p.x+dragging.dx;dragging.n.y=p.y+dragging.dy;movedNodes=[dragging.n];}}expandTanLeftWithDrag(movedNodes);updatePositions();}}else if(panning){{panX=ev.clientX-panning.x;panY=ev.clientY-panning.y;updateTransform();}} }});
svg.addEventListener('pointerup',()=>{{const completed=dragging;if(completed?.moved){{markLayoutDirty();completed.group?selectServerGroup(completed.group):selectNode(completed.n);}}dragging=null;panning=null;svg.classList.remove('panning');}});
svg.addEventListener('pointerdown',ev=>{{if(ev.target===svg){{panning={{x:ev.clientX-panX,y:ev.clientY-panY}};svg.classList.add('panning');clearSelection();}}}});
svg.addEventListener('wheel',ev=>{{
  ev.preventDefault();if(ev.ctrlKey&&ev.deltaY){{const old=scale,factor=ev.deltaY<0?1.12:.89;scale=Math.max(.12,Math.min(4,scale*factor));const r=svg.getBoundingClientRect(),x=ev.clientX-r.left,y=ev.clientY-r.top;panX=x-(x-panX)*scale/old;panY=y-(y-panY)*scale/old;updateTransform();return;}}
  const horizontal=ev.shiftKey||Math.abs(ev.deltaX)>Math.abs(ev.deltaY);
  if(horizontal){{const movement=ev.shiftKey&&Math.abs(ev.deltaX)<=Math.abs(ev.deltaY)?ev.deltaY:ev.deltaX;panX-=movement;updateTransform();return;}}
  if(ev.deltaY){{panY-=ev.deltaY;updateTransform();}}
}},{{passive:false}});
function savePositions() {{
  try{{localStorage.setItem(savedKey,JSON.stringify(Object.fromEntries(graph.nodes.map(n=>[n.id,{{x:n.x,y:n.y}}]))));return true;}}
  catch(error){{alert('Could not save the layout in this browser: '+error.message);return false;}}
}}
function markLayoutDirty() {{const button=document.getElementById('save');button.classList.add('dirty');button.textContent='Save layout *';}}
function restoreFocus() {{
  while(focusServerGroups.firstChild)serverGroupsGroup.appendChild(focusServerGroups.firstChild);
  while(focusLinks.firstChild)linksGroup.appendChild(focusLinks.firstChild);
  while(focusPorts.firstChild)portsGroup.appendChild(focusPorts.firstChild);
  while(focusNodes.firstChild)nodesGroup.appendChild(focusNodes.firstChild);
}}
function clearSelection() {{restoreFocus();selected=null;selectedZone=null;details.style.display='none';document.querySelectorAll('.dim,.selected').forEach(e=>e.classList.remove('dim','selected'));document.getElementById('fitSelected').disabled=true;updateHideButton();}}
function elevateFocus(activeNodes,activeEdges,extraGroups=[]) {{
  const groups=new Set(extraGroups);for(const id of activeNodes){{const n=nodeMap.get(id);if(n?.serverGroup)groups.add(n.serverGroup);}}
  groups.forEach(group=>focusServerGroups.appendChild(group.el));
  graph.edges.filter(e=>e.el&&activeEdges.has(e.id)).forEach(e=>focusLinks.appendChild(e.el));
  graph.edges.filter(e=>e.el&&activeEdges.has(e.id)).forEach(e=>{{focusPorts.append(e.aLabel,e.bLabel);}});
  graph.nodes.filter(n=>activeNodes.has(n.id)).forEach(n=>focusNodes.appendChild(n.el));
  focusPorts.style.display=effectivePortsVisible()?'':'none';document.getElementById('fitSelected').disabled=activeNodes.size===0;
}}
function highlightPaths(activeNodes,activeEdges) {{
  graph.nodes.forEach(n=>{{const on=activeNodes.has(n.id);n.el.classList.toggle('selected',on);n.el.classList.toggle('dim',!on);}});
  graph.edges.filter(e=>e.el).forEach(e=>{{const on=activeEdges.has(e.id);e.el.classList.toggle('selected',on);e.el.classList.toggle('dim',!on);e.aLabel.classList.toggle('selected',on);e.bLabel.classList.toggle('selected',on);e.aLabel.classList.toggle('dim',!on);e.bLabel.classList.toggle('dim',!on);}});
  serverGroups.forEach(group=>group.el.classList.toggle('dim',!group.members.some(n=>activeNodes.has(n.id))));
}}
function selectNode(n) {{
  clearSelection();selected=n.id;const connected=visibleEdgesForNode(n),activeNodes=new Set([n.id]),activeEdges=new Set();
  connected.forEach(e=>{{activeNodes.add(e.source);activeNodes.add(e.target);activeEdges.add(e.id);}});highlightPaths(activeNodes,activeEdges);elevateFocus(activeNodes,activeEdges);
  details.innerHTML=`<b>${{escapeText(n.id)}}</b><div>${{connected.length}} neighboring device(s)</div>`+connected.map(e=>{{const mine=e.source===n.id?e.source_label:e.target_label,other=e.source===n.id?e.target:e.source,theirs=e.source===n.id?e.target_label:e.source_label;return `<div class="pair">${{escapeText(mine)}} ↔ ${{escapeText(other)}} : ${{escapeText(theirs)}}</div>`}}).join('');details.style.display='block';
}}
function selectEdge(e) {{clearSelection();const activeNodes=new Set(e.bundleMemberIds||[e.source,e.target]),activeEdges=new Set([e.id]);highlightPaths(activeNodes,activeEdges);elevateFocus(activeNodes,activeEdges);const rows=e.links.map(x=>`<div class="pair">${{escapeText(x.source_device||e.source)}}:${{escapeText(x.source_port)}} ↔ ${{escapeText(x.target_device||e.target)}}:${{escapeText(x.target_port)}}</div>`).join('');details.innerHTML=`<b>${{e.count}} physical link(s)</b>${{rows}}`;details.style.display='block';}}
function selectServerGroup(group) {{
  clearSelection();const activeNodes=new Set(group.members.map(n=>n.id)),activeEdges=new Set();
  graph.edges.filter(e=>e.el&&(activeNodes.has(e.source)||activeNodes.has(e.target))).forEach(e=>{{activeEdges.add(e.id);activeNodes.add(e.source);activeNodes.add(e.target);}});
  highlightPaths(activeNodes,activeEdges);group.el.classList.add('selected');elevateFocus(activeNodes,activeEdges,[group]);
  details.innerHTML=`<b>${{escapeText(group.label)}}</b><div>${{group.members.length}} grouped device(s)${{group.uniform?' · one shared connection pattern shown':''}} · drag this frame to move them together</div>`;details.style.display='block';
}}
function selectZone(zone,guide) {{
  clearSelection();selectedZone=zone;guide.parts.forEach(part=>part.classList.add('selected'));const regionalNodes=new Set(graph.nodes.filter(n=>n.zones.includes(zone)&&!TOP_ROLES.includes(n.role)).map(n=>n.id)),activeNodes=new Set(regionalNodes),activeEdges=new Set();
  for(const e of graph.edges.filter(e=>e.el&&!edgeTouchesHiddenZone(e))){{
    if(e.zoneClass!==zone)continue;
    const a=nodeMap.get(e.source),b=nodeMap.get(e.target),aRegional=regionalNodes.has(a.id),bRegional=regionalNodes.has(b.id);
    if(aRegional||bRegional){{activeEdges.add(e.id);activeNodes.add(a.id);activeNodes.add(b.id);}}
  }}
  for(const e of graph.edges.filter(e=>e.el&&!edgeTouchesHiddenZone(e))){{const a=nodeMap.get(e.source),b=nodeMap.get(e.target);if(TOP_ROLES.includes(a.role)&&TOP_ROLES.includes(b.role)&&(activeNodes.has(a.id)||activeNodes.has(b.id))){{activeEdges.add(e.id);activeNodes.add(a.id);activeNodes.add(b.id);}}}}
  highlightPaths(activeNodes,activeEdges);elevateFocus(activeNodes,activeEdges);updateHideButton();
  const topCount=[...activeNodes].filter(id=>TOP_ROLES.includes(nodeMap.get(id).role)).length;
  details.innerHTML=`<b>${{ZONES[zone]}} network</b><div>${{regionalNodes.size}} regional device(s) · ${{topCount}} connected FW/Border · ${{activeEdges.size}} highlighted link(s)</div>`;details.style.display='block';
}}
document.getElementById('ports').onclick=()=>{{const visible=effectivePortsVisible();portsManuallySet=true;portsVisible=!visible;updatePortVisibility();}};
document.getElementById('hideZone').onclick=()=>{{
  if(selectedZone!==null&&!hiddenZones.has(selectedZone))hiddenZones.add(selectedZone);
  else if(hiddenZones.size)hiddenZones.clear();
  applyZoneVisibility();
}};
document.getElementById('save').onclick=ev=>{{if(savePositions()){{ev.target.classList.remove('dirty');ev.target.textContent='Saved ✓';setTimeout(()=>{{ev.target.textContent='Save layout';}},1400);}}}};
document.getElementById('reset').onclick=()=>{{localStorage.removeItem(savedKey);hiddenZones.clear();initialPositions();fitView();draw();clearSelection();const save=document.getElementById('save');save.classList.remove('dirty');save.textContent='Save layout';}};
document.getElementById('zoomIn').onclick=()=>zoomAtCenter(1.25);
document.getElementById('zoomOut').onclick=()=>zoomAtCenter(.8);
document.getElementById('fitAll').onclick=()=>fitVisibleView();
document.getElementById('actualSize').onclick=()=>{{const x=width/2,y=height/2,old=scale;scale=1;panX=x-(x-panX)/old;panY=y-(y-panY)/old;updateTransform();}};
document.getElementById('fitSelected').onclick=()=>fitNodes(graph.nodes.filter(n=>n.el.classList.contains('selected')));
const searchInput=document.getElementById('search'),searchResults=document.getElementById('searchResults');let searchMatches=[],searchIndex=0;
function chooseSearchResult(index){{if(!searchMatches.length)return;searchIndex=(index+searchMatches.length)%searchMatches.length;selectNode(searchMatches[searchIndex]);searchResults.querySelectorAll('.search-result').forEach((el,i)=>el.classList.toggle('active',i===searchIndex));}}
function updateSearch(){{
  const q=searchInput.value.trim().toLowerCase();clearSelection();searchResults.replaceChildren();searchMatches=q?graph.nodes.filter(n=>n.id.toLowerCase().includes(q)).sort((a,b)=>a.id.localeCompare(b.id,undefined,{{numeric:true}})):[];searchIndex=0;
  if(!q){{searchResults.style.display='none';return;}}
  if(!searchMatches.length){{const empty=document.createElement('div');empty.className='search-empty';empty.textContent='No matching devices';searchResults.appendChild(empty);searchResults.style.display='block';return;}}
  searchMatches.slice(0,40).forEach((n,index)=>{{const row=document.createElement('div');row.className='search-result';row.textContent=n.id;row.setAttribute('role','option');row.onclick=()=>{{chooseSearchResult(index);searchInput.value=n.id;searchResults.style.display='none';}};searchResults.appendChild(row);}});
  if(searchMatches.length>40){{const more=document.createElement('div');more.className='search-empty';more.textContent=`${{searchMatches.length-40}} more matches - type more characters`;searchResults.appendChild(more);}}
  searchResults.style.display='block';chooseSearchResult(0);
}}
searchInput.addEventListener('input',updateSearch);
searchInput.addEventListener('keydown',ev=>{{if(ev.key==='Enter'&&searchMatches.length){{ev.preventDefault();chooseSearchResult(searchIndex+1);}}else if(ev.key==='Escape')searchResults.style.display='none';}});
document.addEventListener('pointerdown',ev=>{{if(!document.getElementById('searchWrap').contains(ev.target))searchResults.style.display='none';}});
const legend=document.getElementById('legend');document.getElementById('legendButton').onclick=()=>legend.classList.toggle('open');
const welcome=document.getElementById('welcome');function closeWelcome(persist=false){{welcome.hidden=true;if(persist)try{{localStorage.setItem(welcomeKey,'1');}}catch(_){{}}}}
document.getElementById('helpButton').onclick=()=>{{welcome.hidden=false;}};document.getElementById('welcomeClose').onclick=()=>closeWelcome(false);document.getElementById('welcomeDismiss').onclick=()=>closeWelcome(true);
addEventListener('resize',()=>{{width=innerWidth;height=innerHeight;}});
initialPositions();draw();fitView();
document.getElementById('stats').textContent=`${{graph.nodes.length}} devices · ${{graph.edges.filter(e=>e.el).length}} displayed links · ${{graph.edges.reduce((s,e)=>s+(e._base?.count??e.count),0)}} physical links`;
updateHideButton();
try{{welcome.hidden=localStorage.getItem(welcomeKey)==='1';}}catch(_){{welcome.hidden=false;}}
</script>
</body>
</html>
'''


def convert(
    path: Path,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    output: Path | None = None,
) -> Path:
    nodes, edges = parse_dot(path)
    nodes, edges = filter_topology(nodes, edges, include, exclude)
    if output is None:
        suffixes: list[str] = []
        if include:
            suffixes.append("include-" + "-".join(re.sub(r"[^a-zA-Z0-9_-]+", "-", term).strip("-") for term in include))
        if exclude:
            suffixes.append("exclude-" + "-".join(re.sub(r"[^a-zA-Z0-9_-]+", "-", term).strip("-") for term in exclude))
        output = path.with_name(path.stem + ("--" + "--".join(suffixes) if suffixes else "") + ".html")
    output.parent.mkdir(parents=True, exist_ok=True)
    document = build_html(path, nodes, edges)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(document)
            temporary_path = Path(temporary.name)
        temporary_path.chmod(0o644)
        temporary_path.replace(output)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    physical = sum(int(edge["count"]) for edge in edges)
    print(f"Created: {output} ({len(nodes)} devices, {len(edges)} device links, {physical} physical links)")
    return output


def find_inputs(value: Path) -> list[Path]:
    if value.is_file():
        if value.suffix.casefold() != ".dot":
            raise ValueError(f"input file is not a .dot file: {value}")
        return [value]
    if not value.is_dir():
        raise ValueError(f"input path does not exist: {value}")
    matches = sorted(
        set(value.glob("*-lldpq.dot")),
        key=lambda path: natural_key(path.name),
    )
    if not matches:
        raise ValueError(f"no *-lldpq.dot files found in directory: {value}")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert LLDP-style DOT links to draggable standalone HTML topology files."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-f", "--dot-file", type=Path, help="convert one specified .dot file")
    source.add_argument(
        "-d",
        "--directory",
        type=Path,
        help="convert every *-lldpq.dot file directly inside this directory",
    )
    parser.add_argument(
        "--network-list",
        type=parse_network_terms,
        default=(),
        metavar="NAME[,NAME...]",
        help="keep links where either device name contains one of these values",
    )
    parser.add_argument(
        "--network-exclude",
        type=parse_network_terms,
        default=(),
        metavar="NAME[,NAME...]",
        help="remove links where either device name contains one of these values",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output HTML path (only valid when exactly one DOT file is selected)",
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="legacy form: a .dot file or a directory containing *-lldpq.dot",
    )
    args = parser.parse_args()
    try:
        named_input = args.dot_file or args.directory
        if named_input is not None and args.input is not None:
            parser.error("do not combine the positional input with --dot-file or --directory")
        selected = named_input or args.input
        if selected is None:
            parser.error("specify --dot-file FILE, --directory DIR, or a positional input path")
        selected = selected.expanduser().resolve()
        if args.dot_file is not None and not selected.is_file():
            raise ValueError(f"--dot-file is not a file: {selected}")
        if args.directory is not None and not selected.is_dir():
            raise ValueError(f"--directory is not a directory: {selected}")
        inputs = find_inputs(selected)
        if args.output is not None and len(inputs) != 1:
            raise ValueError("--output requires exactly one input DOT file")
        output = args.output.expanduser().resolve() if args.output is not None else None
        for path in inputs:
            convert(path, args.network_list, args.network_exclude, output)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
