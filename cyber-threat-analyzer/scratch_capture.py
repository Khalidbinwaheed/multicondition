import subprocess
import time
import json
import urllib.request
import asyncio
import websockets
import base64
import os

proc = subprocess.Popen([
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    '--headless=new',
    '--remote-debugging-port=9226',
    '--window-size=1400,1400',
    'http://127.0.0.1:8501'
])

async def capture():
    await asyncio.sleep(2)
    resp = urllib.request.urlopen('http://127.0.0.1:9226/json')
    tabs = json.loads(resp.read().decode())
    target = [t for t in tabs if t.get('type') == 'page'][0]
    ws_url = target['webSocketDebuggerUrl']
    
    async with websockets.connect(ws_url) as ws:
        for _ in range(25):
            await ws.send(json.dumps({
                'id': 10,
                'method': 'Runtime.evaluate',
                'params': {'expression': 'document.querySelector(".title-text") !== null'}
            }))
            reply = await ws.recv()
            data = json.loads(reply)
            if data.get('result', {}).get('result', {}).get('value') is True:
                print('Page rendered!')
                break
            await asyncio.sleep(0.5)
            
        await asyncio.sleep(1.5)
        await ws.send(json.dumps({'id': 20, 'method': 'Page.captureScreenshot'}))
        reply = await ws.recv()
        data = json.loads(reply)
        img_b64 = data['result']['data']
        with open('app_screenshot.png', 'wb') as f:
            f.write(base64.b64decode(img_b64))
        print('Screenshot captured successfully!')

try:
    asyncio.run(capture())
finally:
    proc.terminate()
