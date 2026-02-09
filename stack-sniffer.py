import requests
import sys
from argparse    import ArgumentParser as ArgParser



class StackSniffer:

    HEADERS = {
        'User-Agent': 'python-requests/2.31.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }


    __slots__ = ('_redirec', '_url', '_server_info')

    def __init__(self):
        self._redirec:     bool = None
        self._url:          str = None
        self._server_info: dict = {}


    
    def analyze(self):
        self._parse_args()
        self._validate_url()        
        self._get_server_info()
        self._display_results()

    

    def _parse_args(self):
        parser = ArgParser(description='Stack-Sniffer')
        parser.add_argument('--url', type=str, help='URL')
        parser.add_argument('-R', '--redirec', action='store_true', help='Allow redirection')
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
        HEADERS_TO_CHECK = [
            'Server', 'X-Powered-By', 'X-Generator', 
            'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Runtime', 'X-Frame-Options'
        ]

        try:
            response = requests.head(
                self._url, headers=self.HEADERS, 
                timeout=5, allow_redirects=self._redirec
            )
            
            self._server_info = {
                'location':    response.url,
                'status_code': response.status_code,
            }
            
            for header in HEADERS_TO_CHECK:
                if header in response.headers:
                    self._server_info[header] = response.headers[header]
                
        except Exception as e:
            self._abort(str(e))


        
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