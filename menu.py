"""
menu.py

Interactive menu for running lab demos and starting/stopping servers.

Usage: run with Python 3 in the repo root. The menu can launch demo scripts as
foreground tasks or start servers as background processes (so you can test clients
against them in other terminals).

This is a convenience tool for lab-style, menu-driven exercises.
"""

import subprocess
import sys
import os
import shlex
import time
from typing import Dict

PY = sys.executable
CWD = os.getcwd()

# Mapping short names to script filenames
SCRIPTS = {
    'hash_server': 'hash_server.py',
    'hash_client': 'hash_client.py',
    'multipart_server': 'multipart_server.py',
    'multipart_client': 'multipart_client.py',
    'hash_performance': 'hash_performance.py',
    'hash_util': 'hash_util.py',
    'paillier_demo': 'paillier_cipher.py',
    'rsa_homomorphic': 'rsa_homomorphic.py',
    'elgamal_homomorphic': 'elgamal_homomorphic.py',
    'sse_demo': 'sse_demo.py',
    'pkse_demo': 'pkse_demo.py',
    'sig_server': 'sig_server.py',
    'sig_client': 'sig_client.py',
}

# Track background processes we started: name -> Popen
running_bg: Dict[str, subprocess.Popen] = {}


def run_foreground(script: str, args: str = ''):
    path = os.path.join(CWD, script)
    if not os.path.exists(path):
        print(f"Script not found: {script}")
        return
    cmd = [PY, path] + (shlex.split(args) if args else [])
    print('Running:', ' '.join(cmd))
    subprocess.run(cmd)


def start_background(script: str, args: str = ''):
    path = os.path.join(CWD, script)
    if not os.path.exists(path):
        print(f"Script not found: {script}")
        return
    if script in running_bg:
        print(f"Already running in background: {script} (pid {running_bg[script].pid})")
        return
    cmd = [PY, path] + (shlex.split(args) if args else [])
    p = subprocess.Popen(cmd)
    running_bg[script] = p
    print(f"Started {script} as background process (pid {p.pid})")


def stop_background(script: str):
    p = running_bg.get(script)
    if not p:
        print(f"Not running: {script}")
        return
    print(f"Stopping {script} (pid {p.pid})...")
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
    del running_bg[script]
    print(f"Stopped {script}")


def list_background():
    if not running_bg:
        print('No background processes started from this menu.')
        return
    for name, p in running_bg.items():
        status = 'running' if p.poll() is None else f'exited (code {p.returncode})'
        print(f"{name}: pid={p.pid}, {status}")


def prompt_choice(prompt: str, choices: Dict[int, str]) -> int:
    for k, v in choices.items():
        print(f"{k}. {v}")
    try:
        sel = int(input(prompt).strip())
    except Exception:
        return -1
    return sel


def menu_loop():
    while True:
        print('\n=== IS Lab Menu ===')
        print('1) Compute custom hash (hash_util)')
        print('2) Run hash performance experiment (hash_performance)')
        print('3) Start/stop hash server (hash_server)')
        print('4) Start/stop multipart server (multipart_server)')
        print('5) Run clients: hash client / multipart client (foreground)')
        print('6) Paillier demo (paillier_cipher)')
        print('7) RSA homomorphic demo (rsa_homomorphic)')
        print('8) ElGamal homomorphic demo (elgamal_homomorphic)')
        print('9) SSE demo (sse_demo)')
        print('10) PKSE demo (pkse_demo)')
        print('11) Start/stop signature server (sig_server)')
        print('12) Use signature client (sig_client)')
        print('13) List background servers')
        print('14) Stop a background server')
        print('0) Exit')

        try:
            choice = int(input('Select an option: ').strip())
        except Exception:
            print('Invalid choice')
            continue

        if choice == 0:
            print('Exiting. Stopping background processes started by this menu...')
            for name in list(running_bg.keys()):
                stop_background(name)
            break

        elif choice == 1:
            msg = input('Enter message to hash: ')
            # call hash_util directly so we get immediate result
            try:
                import importlib
                hu = importlib.import_module('hash_util')
                print('Hash (hex):', hu.custom_hash_hex(msg))
            except Exception as e:
                print('Error importing or running hash_util:', e)

        elif choice == 2:
            run_foreground(SCRIPTS['hash_performance'])

        elif choice == 3:
            sub = prompt_choice('1) Start  2) Stop  3) Status\nYour choice: ', {1:'Start',2:'Stop',3:'Status'})
            if sub == 1:
                start_background(SCRIPTS['hash_server'])
            elif sub == 2:
                stop_background(SCRIPTS['hash_server'])
            elif sub == 3:
                p = running_bg.get(SCRIPTS['hash_server'])
                if p: print(f"hash_server pid={p.pid}, running={p.poll() is None}")
                else: print('hash_server not started')

        elif choice == 4:
            sub = prompt_choice('1) Start  2) Stop  3) Status\nYour choice: ', {1:'Start',2:'Stop',3:'Status'})
            if sub == 1:
                start_background(SCRIPTS['multipart_server'])
            elif sub == 2:
                stop_background(SCRIPTS['multipart_server'])
            elif sub == 3:
                p = running_bg.get(SCRIPTS['multipart_server'])
                if p: print(f"multipart_server pid={p.pid}, running={p.poll() is None}")
                else: print('multipart_server not started')

        elif choice == 5:
            sub = prompt_choice('1) Run hash_client  2) Run multipart_client\nYour choice: ', {1:'hash_client',2:'multipart_client'})
            if sub == 1:
                msg = input('Message to send to hash server: ')
                run_foreground(SCRIPTS['hash_client'], shlex.quote(msg))
            elif sub == 2:
                msg = input('Message to send: ')
                parts = input('Number of parts (default 3): ').strip() or '3'
                run_foreground(SCRIPTS['multipart_client'], f'{shlex.quote(msg)} --parts {parts}')

        elif choice == 6:
            run_foreground(SCRIPTS['paillier_demo'])

        elif choice == 7:
            run_foreground(SCRIPTS['rsa_homomorphic'])

        elif choice == 8:
            run_foreground(SCRIPTS['elgamal_homomorphic'])

        elif choice == 9:
            run_foreground(SCRIPTS['sse_demo'])

        elif choice == 10:
            run_foreground(SCRIPTS['pkse_demo'])

        elif choice == 11:
            sub = prompt_choice('1) Start  2) Stop  3) Status\nYour choice: ', {1:'Start',2:'Stop',3:'Status'})
            if sub == 1:
                start_background(SCRIPTS['sig_server'])
            elif sub == 2:
                stop_background(SCRIPTS['sig_server'])
            elif sub == 3:
                p = running_bg.get(SCRIPTS['sig_server'])
                if p: print(f"sig_server pid={p.pid}, running={p.poll() is None}")
                else: print('sig_server not started')

        elif choice == 12:
            # Interactive signature client: ask for op, alg, message, key, signature
            op = input('Operation (sign / verify): ').strip()
            alg = input('Algorithm (RSA / ELGAMAL / SCHNORR): ').strip()
            message = input('Message: ')
            key = input('Key (JSON string): ')
            sig = ''
            if op == 'verify':
                sig = input('Signature (hex or comma-separated): ')
            args_json = f"--op {op} --alg {alg} --message {shlex.quote(message)} --key '{key}'"
            if sig:
                args_json += f" --signature '{sig}'"
            run_foreground(SCRIPTS['sig_client'], args_json)

        elif choice == 13:
            list_background()

        elif choice == 14:
            list_background()
            to_stop = input('Enter script name to stop (e.g. hash_server.py): ').strip()
            if to_stop:
                stop_background(to_stop)

        else:
            print('Unknown option')


if __name__ == '__main__':
    print('Menu runner for IS Lab demos')
    menu_loop()
