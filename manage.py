import argparse
import os
import subprocess
import sys
from datetime import datetime, timedelta

REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')

def list_reports():
    if not os.path.isdir(REPORTS_DIR):
        print('No reports directory found')
        return
    for name in sorted(os.listdir(REPORTS_DIR)):
        path = os.path.join(REPORTS_DIR, name)
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        print(f"{name}\t{mtime}")

def clean_reports(days: int):
    if not os.path.isdir(REPORTS_DIR):
        print('No reports directory found')
        return
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    for name in os.listdir(REPORTS_DIR):
        path = os.path.join(REPORTS_DIR, name)
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        if mtime < cutoff:
            os.remove(path)
            removed += 1
    print(f'Removed {removed} reports older than {days} days')

def run_server():
    # Run server.py using current Python interpreter
    subprocess.run([sys.executable, 'server.py'])

def main():
    p = argparse.ArgumentParser(description='Manage WAF-Auto small tasks')
    sub = p.add_subparsers(dest='cmd')
    sub.add_parser('list-reports')
    cr = sub.add_parser('clean-reports')
    cr.add_argument('--days', type=int, default=30)
    sub.add_parser('run-server')
    args = p.parse_args()
    if args.cmd == 'list-reports':
        list_reports()
    elif args.cmd == 'clean-reports':
        clean_reports(args.days)
    elif args.cmd == 'run-server':
        run_server()
    else:
        p.print_help()

if __name__ == '__main__':
    main()
