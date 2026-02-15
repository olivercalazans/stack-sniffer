import sys
from argparse     import ArgumentParser as ArgParser
from bs4          import BeautifulSoup
from dataclasses  import dataclass, field
from requests     import Request, get, RequestException
from threading    import Thread, Lock
from urllib.parse import urlparse, urljoin




@dataclass(slots=True)
class Data:
    _lock      : Lock           = field(default_factory=Lock)
    responses  : list[Request]  = field(default_factory=list)
    urls       : set[str]       = field(default_factory=set)
    known_urls : set[str]       = field(default_factory=set)
    info       : dict[str, str] = field(default_factory=dict)
    _base_url  : str            = None
    redirect   : bool           = None
    _verbose   : bool           = None


    @property
    def base_url(self) -> str:
        return self._base_url


    @base_url.setter
    def base_url(self, new_url: str):
        new_url = new_url.rstrip('/')
        self._base_url = new_url
        self.known_urls.add(new_url)


    def add_response(self, response: Request):
        with self._lock:
            self.responses.append(response)
    

    def display_progress(self, msg: str):
        if self._verbose:
            print(msg)
    

    def add_url(self, new_url: str):
        new_url = new_url.rstrip('/')

        if new_url in self.known_urls:
            return

        self.urls.add(new_url)
        self.known_urls.add(new_url)




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
        self._validate_url()
        self._create_threads_for_requests()
        self._update_base_url()
        self._analyze_headers()
        self._analyze_htmls()
        self._display_results()
    


    def _parse_args(self):
        parser = ArgParser(description='Stack-Sniffer')
        parser.add_argument('--url', type=str, help='URL')
        parser.add_argument('-v', '--verbose',  action='store_true', help='Display progress')
        parser.add_argument('-r', '--redirect', action='store_true', help='Allow redirection')
        args = parser.parse_args(self._get_args())

        self.data.base_url = args.url
        self.data._verbose = args.verbose
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

    

    def _validate_url(self):
        if self.data.base_url.startswith(('http://', 'https://')):
            return
        
        incomplited_url    = self.data.base_url
        self.data.base_url = 'http://' + incomplited_url
        self.data.display_progress(f'[!] URL changed: {incomplited_url} -> {self.data.base_url}')



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
    


    def _update_base_url(self):
        if not self.data.redirect:
            return
        
        urls = set()
        for resp in self.data.responses:
            urls.add(resp.url)
        
        if len(urls) > 1:
            self._abort(f'Different URL redirections: {urls}')

        self.data.base_url = next(iter(urls))
        self.data.display_progress(f'[!] Redirected to {self.data.base_url}')
            


    def _analyze_headers(self):
        with HeaderSniffer(self.data):
            ... 
    

    def _analyze_htmls(self):
        with UrlSniffer(self.data):
            ...

    

    def _display_results(self):
        self._display_header_info()
        self._display_links_info()
    


    def _display_header_info(self):
        bigger  = max(self.data.info, key=len)
        max_len = len(bigger) + 3

        for k, value in self.data.info.items():
            space = max_len - len(k)
            desc  = self._format_str(k)
            print(f'[#] {desc}{space * '.'}: {value}')

    

    @staticmethod
    def _format_str(string: str) -> str:
        string = string.replace('_', ' ')
        return string.title()
    


    def _display_links_info(self):
        print(f'[$] URLs found: {len(self.data.known_urls)}')
        
        for i, url in enumerate(self.data.known_urls, start=1):
            print(f'{i:>3}. {url}')





class HeaderSniffer: 
    
    HEADERS_TO_CHECK = [
        'Server', 'X-Powered-By', 'X-Generator', 'Last-Modified', 'X-AspNet-Version',
        'X-AspNetMvc-Version', 'X-Runtime', 'X-Frame-Options', 'Location'
    ]

    __slots__ = ('data')

    def __init__(self, data: Data):
        self.data: Data = data
    


    def __enter__(self):
        self.data.display_progress('[*] Analyzing headers')
        
        for response in self.data.responses:
            self.data.info['status_code'] = response.status_code
            self._analyze_header(response)
        
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        return False



    def _analyze_header(self, response: Request):
        for header in self.HEADERS_TO_CHECK:
            if header in response.headers:
                self.data.info[header] = response.headers[header]




class UrlSniffer:

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
        self.data.display_progress('[*] Analyzing HTMLs')
        
        while self.data.responses:
            response   = self.data.responses.pop() 
            self._soup = BeautifulSoup(response.text, 'html.parser')
            self._find_url_in_html()
        
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
            
    

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
                self.data.add_url(clean_url)





if __name__ == "__main__":
    analyzer = StackSniffer()
    analyzer.analyze()