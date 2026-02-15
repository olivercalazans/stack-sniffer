import sys
from argparse     import ArgumentParser as ArgParser
from bs4          import BeautifulSoup
from dataclasses  import dataclass, field
from requests     import Request, get, RequestException
from threading    import Thread, Lock
from urllib.parse import urlparse, urljoin




@dataclass(slots=True)
class Data:
    _lock     : Lock          = Lock()
    base_url  : str           = None
    redirect  : bool          = None
    responses : list[Request] = field(default_factory=list)
    urls      : set[str]      = field(default_factory=set)


    def add_response(self, response: Request):
        with self._lock:
            self.responses.append(response)




class StackSniffer:

    USER_AGENTS = [
        'curl/7.81.0',
        'python-requests/2.31.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ]

    __slots__ = ('data')

    def __init__(self):
        self.data: Data = Data()


    
    def analyze(self):
        self._parse_args()
        self._create_threads_for_requests()
        self._analyze_headers()
        self._analyze_htmls()
    


    def _parse_args(self):
        parser = ArgParser(description='Stack-Sniffer')
        parser.add_argument('--url', type=str, help='URL')
        parser.add_argument('-r', '--redirect', action='store_true', help='Allow redirection')
        args = parser.parse_args(self._get_args())

        self.data.base_url = self._validate_url(args.url)
        self.data.redirect = args.redirect



    @staticmethod
    def _get_args() -> list[str]:        
        if len(sys.argv) < 2:
            StackSniffer._abort('Missing arguments')
        
        return sys.argv[1:]

    

    @staticmethod
    def _abort(msg: str):
        print(f'[ ERROR ] {msg}')
        sys.exit()

    

    @staticmethod
    def _validate_url(url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url



    def _create_threads_for_requests(self):
        threads: list[Thread] = []

        for user in self.USER_AGENTS:
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
            response = get(
                self.data.base_url, headers=headers, 
                timeout=5, allow_redirects=self.data.redirect
            )

            response.raise_for_status()
            self.data.add_response(response)

        except (Exception, RequestException):
            pass


    
    def _analyze_headers(self):
        with HeaderSniffer(self.data):
            ... 
    

    def _analyze_htmls(self):
        with HtmlSniffer(self.data):
            ...




class HeaderSniffer:
    
    HEADERS_TO_CHECK = [
        'Server', 'X-Powered-By', 'X-Generator', 'Last-Modified', 'X-AspNet-Version',
        'X-AspNetMvc-Version', 'X-Runtime', 'X-Frame-Options', 'Location'
    ]

    __slots__ = ('_info', 'data')

    def __init__(self, data: Data):
        self.data  : Data = data
        self._info : dict = {}
    


    def __enter__(self):
        self._analyze_responses()
        self._display_results()
        self._update_url()
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        return False



    def _analyze_responses(self):
        for response in self.data.responses:
            self._info = { 'status_code': response.status_code }
            self._analyze_header(response)
    


    def _analyze_header(self, response: Request):
        for header in self.HEADERS_TO_CHECK:
            if header in response.headers:
                self._info[header] = response.headers[header]



    def _display_results(self):
        bigger  = max(self._info, key=len)
        max_len = len(bigger) + 3

        for k, value in self._info.items():
            space = max_len - len(k)
            desc  = self._format_str(k)
            print(f'{desc}{space * '.'}: {value}')

    

    @staticmethod
    def _format_str(string: str) -> str:
        string = string.replace('_', ' ')
        return string.title()
    


    def _update_url(self):
        if self.data.redirect and 'Location' in self._info:        
            self.data.base_url = self._info['Location']
    




class HtmlSniffer:

    TAGS_AND_ATTRIBUTES = {
        'a': 'href',       'img': 'src',     'link': 'href',
        'form': 'action',  'area': 'href',   'base': 'href',
        'embed': 'src',    'frame': 'src',   'script': 'src',  
        'iframe': 'src',   'source': 'src',
    }

    __slots__ = ('data', '_soup', '_netloc')

    def __init__(self, data: Data):
        self.data    : Data          = data
        self._soup   : BeautifulSoup = None
        self._netloc : str           = urlparse(self.data.base_url).netloc

    

    def __enter__(self):
        self._analyze_responses()
        self._display_results()
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    

    def _analyze_responses(self):
        while self.data.responses:
            response   = self.data.responses.pop() 
            self._soup = BeautifulSoup(response.text, 'html.parser')
            self._find_url_in_html()
            
    

    def _find_url_in_html(self):
        for tag, attribute in self.TAGS_AND_ATTRIBUTES.items():
            for element in self._soup.find_all(tag):
                valor = element.get(attribute)

                if not valor:
                    continue

                absolut_url = urljoin(self.data.base_url, valor)
                parsed      = urlparse(absolut_url)

                if parsed.netloc and parsed.netloc != self._netloc:
                    continue
                
                clean_url = parsed._replace(fragment='').geturl()
                self.data.urls.add(clean_url)
    


    def _display_results(self):
        print('\nLinks found')
        for i, url in enumerate(self.data.urls, start=1):
            print(f'{i:>3}. {url}')





if __name__ == "__main__":
    analyzer = StackSniffer()
    analyzer.analyze()