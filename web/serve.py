"""起一个本地静态服务器并打开查看器 —— 给演示用。

为什么需要它：浏览器不允许 file:// 页面 fetch 本地文件（CORS 限制）。
直接双击 web/index.html 会读不到数据，得走 HTTP。

    python web/serve.py

会打开 http://127.0.0.1:8000/web/index.html
查看器会自动去找 out/findings_ai.json，找不到就退到 out/findings.json。

只监听 127.0.0.1（本机），不对外暴露。
纯标准库，无依赖。
"""
import http.server
import os
import socket
import socketserver
import sys
import threading
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # 仓库根目录 —— 从这里起服务，
                                      # 这样 ../out/findings_ai.json 才够得着
PORT = int(os.environ.get('ACG_WEB_PORT', '8000'))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def end_headers(self):
        # 演示时改了数据刷新就能看到，不要缓存
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def log_message(self, fmt, *args):
        # 默认日志太吵，只看非 200
        if args and str(args[1]) != '200':
            sys.stderr.write('  %s\n' % (fmt % args))


def port_busy(port):
    with socket.socket() as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def main():
    port = PORT
    while port_busy(port):
        print('[!] 端口 %d 被占用，试 %d' % (port, port + 1))
        port += 1

    url = 'http://127.0.0.1:%d/web/index.html' % port

    with socketserver.TCPServer(('127.0.0.1', port), Handler) as httpd:
        print('AI-CryptoGuard 查看器')
        print('  根目录 : %s' % ROOT)
        print('  地址   : %s' % url)
        print('  停止   : Ctrl+C')
        print()
        for name in ('findings_ai.json', 'findings.json'):
            p = os.path.join(ROOT, 'out', name)
            print('  %-20s %s' % (name, '找到' if os.path.exists(p) else '缺失'))
        print()
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\n已停止。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
