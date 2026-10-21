"""Run the exact documented server and smoke commands in a clean Python process."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

class LaunchTests(unittest.TestCase):
    def test_documented_startup_and_smoke(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp,socket.socket() as probe:
            probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
            env=os.environ.copy();env.pop('VERCEL',None)
            env.update({'DATABASE_URL':'sqlite:///'+tmp+'/launch.db','SESSION_SECRET':'local-test-only-32-byte-session-secret','PYTHONUNBUFFERED':'1'})
            process=subprocess.Popen([sys.executable,'main.py','--port',str(port)],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            try:
                base='http://127.0.0.1:'+str(port)
                deadline=time.monotonic()+5
                while True:
                    try:
                        with urlopen(base+'/healthz',timeout=.4) as response:
                            self.assertEqual(response.status,200)
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic()>deadline:
                            self.fail('Documented server failed to become ready.')
                        time.sleep(.03)
                smoke=subprocess.run([sys.executable,'scripts/smoke.py','--base',base],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10)
                self.assertEqual(smoke.returncode,0,smoke.stdout)
                self.assertIn('/api/check rejects non-web URL: 400',smoke.stdout)
                print('\nDocumented launch smoke output:\n'+smoke.stdout)
            finally:
                process.terminate()
                try:process.communicate(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=3)
