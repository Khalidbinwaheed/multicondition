import subprocess
import time
import json
import urllib.request
import asyncio
import websockets

proc = subprocess.Popen([
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    '--headless=new',
    '--remote-debugging-port=9229',
    'http://127.0.0.1:8501'
])

async def inspect():
    await asyncio.sleep(4)
    resp = urllib.request.urlopen('http://127.0.0.1:9229/json')
    tabs = json.loads(resp.read().decode())
    target = [t for t in tabs if t.get('type') == 'page'][0]
    
    async with websockets.connect(target['webSocketDebuggerUrl']) as ws:
        js = """
        (() => {
            const btn = document.querySelector('button');
            const btnP = btn ? btn.querySelector('p, div, span') : null;
            const lbl = document.querySelector('label');
            const sel = document.querySelector('[data-baseweb="select"]');
            return {
                btnText: btn ? btn.innerText : null,
                btnColor: btn ? getComputedStyle(btn).color : null,
                btnPColor: btnP ? getComputedStyle(btnP).color : null,
                lblText: lbl ? lbl.innerText : null,
                lblColor: lbl ? getComputedStyle(lbl).color : null,
                selText: sel ? sel.innerText : null,
                selColor: sel ? getComputedStyle(sel).color : null
            };
        })()
        """
        await ws.send(json.dumps({'id': 1, 'method': 'Runtime.evaluate', 'params': {'expression': js, 'returnByValue': True}}))
        rep = await ws.recv()
        data = json.loads(rep)
        print(json.dumps(data.get('result', {}).get('result', {}).get('value', {}), indent=2))

try:
    asyncio.run(inspect())
finally:
    proc.terminate()
