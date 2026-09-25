import json
import urllib.request
import asyncio
import websockets

async def inspect():
    resp = urllib.request.urlopen('http://127.0.0.1:9227/json')
    tabs = json.loads(resp.read().decode())
    target = [t for t in tabs if t.get('type') == 'page'][0]
    
    async with websockets.connect(target['webSocketDebuggerUrl']) as ws:
        # Check selectbox label and value HTML
        script = """
        (() => {
            const btn = document.querySelector('button');
            const select = document.querySelector('[data-baseweb="select"]');
            const label = document.querySelector('[data-testid="stWidgetLabel"]');
            const progress = document.querySelector('[data-testid="stProgress"]');
            return {
                btn_html: btn ? btn.outerHTML : null,
                btn_color: btn ? window.getComputedStyle(btn).color : null,
                btn_p_color: btn && btn.querySelector('p') ? window.getComputedStyle(btn.querySelector('p')).color : null,
                label_html: label ? label.outerHTML : null,
                label_color: label ? window.getComputedStyle(label).color : null,
                select_html: select ? select.outerHTML.substring(0, 300) : null,
                select_color: select ? window.getComputedStyle(select).color : null,
                progress_html: progress ? progress.outerHTML : null
            };
        })()
        """
        await ws.send(json.dumps({'id': 1, 'method': 'Runtime.evaluate', 'params': {'expression': script, 'returnByValue': True}}))
        reply = await ws.recv()
        data = json.loads(reply)
        print(json.dumps(data.get('result', {}).get('result', {}).get('value', {}), indent=2))

asyncio.run(inspect())
