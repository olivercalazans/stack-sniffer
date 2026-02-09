import requests
import sys



class StackSniffer:

    HEADERS = {
        'User-Agent': 'python-requests/2.31.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }


    def __init__(self):
        self._url:         str  = None
        self._server_info: dict = {}


    
    def analyze(self):
        self._get_url()
        self._validate_url()        
        self._get_server_info()
        self._display_results()



    def _get_url(self):
        len_args = len(sys.argv)
        
        if len_args < 2:
            self._abort('Missing URL')
        elif len_args > 2:
            self._abort(f'Too many arguments. Only a URL is necessary')
        
        self._url = sys.argv[1]

    

    @staticmethod
    def _abort(msg: str):
        print(f'[ ERROR ] {msg}')
        sys.exit()

    

    def _validate_url(self):
        if not self._url.startswith(('http://', 'https://')):
            self._url = 'https://' + self._url



    def _get_server_info(self):
        HEADERS_TO_CHECK = [
            'Server', 'X-Powered-By', 'X-Generator', 
            'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Runtime', 'X-Frame-Options'
        ]
        try:
            response = requests.head(
                self._url, headers=self.HEADERS, 
                timeout=5, allow_redirects=True
            )
            
            self._server_info = {
                'location':   response.url,
                'status_code': response.status_code,
            }
            
            for header in HEADERS_TO_CHECK:
                if header in response.headers:
                    self._server_info[header] = response.headers[header]
            
            
        except Exception as e:
            self._abort(str(e))


        
    def _display_results(self):
            for k, v in self._server_info.items():
                print(f'{k}: {v}')

    
    



if __name__ == "__main__":
    analyzer = StackSniffer()
    analyzer.analyze()