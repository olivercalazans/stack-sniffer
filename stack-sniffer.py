import requests
import sys
from argparse  import ArgumentParser as ArgParser
from threading import Thread, Lock


class StackSniffer:

    __slots__ = ('_redirec', '_url', '_server_info', '_responses', '_lock')

    def __init__(self):
        self._redirec:     bool = None
        self._url:          str = None
        self._server_info: dict = {}
        self._responses:   list = []
        self._lock:        Lock = Lock()


    
    def analyze(self):
        self._parse_args()
        self._validate_url()        
        self._get_server_info()
        self._analyze_responses()
        self._display_results()

    

    def _parse_args(self):
        parser = ArgParser(description='Stack-Sniffer')
        parser.add_argument('--url', type=str, help='URL')
        parser.add_argument('-r', '--redirec', action='store_true', help='Allow redirection')
        args = parser.parse_args(self._get_args())

        self._url     = args.url
        self._redirec = args.redirec 



    @staticmethod
    def _get_args() -> list[str]:        
        if len(sys.argv) < 2:
            StackSniffer._abort('Missing arguments')
        
        return sys.argv[1:]

    

    @staticmethod
    def _abort(msg: str):
        print(f'[ ERROR ] {msg}')
        sys.exit()

    

    def _validate_url(self):
        if not self._url.startswith(('http://', 'https://')):
            self._url = 'http://' + self._url



    def _get_server_info(self):
        USER_AGENTS = [
            'curl/7.81.0',
            'python-requests/2.31.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ]

        threads = []
        for user in USER_AGENTS:
            headers = {
                'User-Agent': user,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }

            t = Thread(target=self._make_request, args=(headers,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    

    def _make_request(self, headers: dict):
        try:
            response = requests.head(
                self._url, headers=headers, 
                timeout=5, allow_redirects=self._redirec
            )
            
            with self._lock:
                self._responses.append(response)

        except Exception:
            pass

    

    def _analyze_responses(self):
        HEADERS_TO_CHECK = [
            'Server', 'X-Powered-By', 'X-Generator', 
            'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Runtime', 'X-Frame-Options'
        ]

        for resp in self._responses:
            self._server_info = {
                'location':   resp.url,
                'status_code':resp.status_code,
            }

            for header in HEADERS_TO_CHECK:
                if header in resp.headers:
                    self._server_info[header] = resp.headers[header]


        
    def _display_results(self):
        self._display_header()
        self._display_info()

    

    def _display_header(self):
        print(f'[@] Target -> {self._url}')
    


    def _display_info(self):
        bigger  = max(self._server_info, key=len)
        max_len = len(bigger) + 3

        for k, value in self._server_info.items():
            space = max_len - len(k)
            desc  = self._format_str(k)
            print(f'{desc}{space * '.'}: {value}')


    
    @staticmethod
    def _format_str(string: str) -> str:
        string = string.replace('_', ' ')
        return string.title()




if __name__ == "__main__":
    analyzer = StackSniffer()
    analyzer.analyze()