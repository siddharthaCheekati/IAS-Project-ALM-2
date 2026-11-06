"""Start three independent localhost websites. Ctrl+C stops all of them."""
import subprocess, sys, pathlib, time, webbrowser
root = pathlib.Path(__file__).resolve().parent
children = []
try:
    for name, port in [('CryptoVault', 8001), ('SecureTunnel', 8002), ('Sentinel', 8003)]:
        children.append(subprocess.Popen([sys.executable, 'app.py', str(port)], cwd=root / name))
        print(f'{name}: http://127.0.0.1:{port}', flush=True)
    time.sleep(1)
    webbrowser.open((root / 'index.html').as_uri())
    while all(p.poll() is None for p in children):
        time.sleep(1)
finally:
    for p in children:
        p.terminate()
    for p in children:
        p.wait()
