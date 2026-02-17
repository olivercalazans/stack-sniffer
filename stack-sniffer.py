import sys
from argparse     import ArgumentParser as ArgParser
from bs4          import BeautifulSoup
from requests     import Request, get, RequestException
from threading    import Thread, Lock
from urllib.parse import urlparse, urljoin



class StackSniffer:

    __slots__ = (
        '_lock', '_responses', '_known_urls', '_info', '_url', '_redirect', '_verbose'
    )

    def __init__(self):
        self._lock       : Lock           = Lock()
        self._responses  : list[Request]  = []
        self._known_urls : set[str]       = set()
        self._info       : dict[str, str] = {}
        self._url        : str            = None
        self._redirect   : bool           = None
        self._verbose    : bool           = None



    def _add_response(self, response: Request):
        with self._lock:
            self._responses.append(response)
    


    def _display_progress(self, msg: str):
        if self._verbose:
            print(msg)



    def _set_base_url(self, new_url: str):
        new_url   = new_url.rstrip('/')
        self._url = new_url
        self._known_urls.add(new_url)
    


    @staticmethod
    def _abort(msg: str):
        print(f'[ ERROR ] {msg}')
        sys.exit()


    
    def analyze(self):
        self._parse_args()
        self._create_threads_for_requests()
        self._update_base_url()
        self._sniff_headers()
        self._sniff_for_urls()
        self._display_header_info()
        self._display_links_info()
    


    def _parse_args(self):
        parser = ArgParser(description='Stack-Sniffer')
        parser.add_argument('--url', type=str, help='URL')
        parser.add_argument('-v', '--verbose',  action='store_true', help='Display progress')
        parser.add_argument('-r', '--redirect', action='store_true', help='Allow redirection')
        args = parser.parse_args(self._get_args())

        self._verbose  = args.verbose
        self._redirect = args.redirect
        self._validate_url(args.url)



    @staticmethod
    def _get_args() -> list[str]:        
        if len(sys.argv) < 2:
            StackSniffer._abort('Missing arguments')
        
        return sys.argv[1:]

    

    def _validate_url(self, new_url: str):
        if new_url.startswith(('http://', 'https://')):
            self._set_base_url(new_url)
            return
        
        self._set_base_url('http://' + new_url)
        self._display_progress(f'[!] URL changed: {new_url} -> {self._url}')




    def _create_threads_for_requests(self):
        USER_AGENTS = [
            'curl/7.81.0',
            'python-requests/2.31.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ]
        
        threads: list[Thread] = []
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
            response = get(
                self._url, headers=headers, 
                timeout=5, allow_redirects=self._redirect
            )

            response.raise_for_status()
            self._add_response(response)

        except (Exception, RequestException):
            pass
    


    def _update_base_url(self):
        if not self._redirect:
            return
        
        urls = set()
        for resp in self._responses:
            urls.add(resp.url)
        
        if len(urls) > 1:
            self._abort(f'Different URL redirections: {urls}')

        self._url = next(iter(urls))
        self._display_progress(f'[!] Redirected to {self._url}')

    

    # HEADERS ==============================================================================================
    def _sniff_headers(self):
        self._display_progress('[*] Analyzing headers')
        
        for response in self._responses:
            self._info['status_code'] = response.status_code
            self._analyze_header(response)
        


    def _analyze_header(self, response: Request):
        HEADERS_TO_CHECK = [
            'Server', 'X-Powered-By', 'X-Generator', 'Last-Modified', 'X-AspNet-Version',
            'X-AspNetMvc-Version', 'X-Runtime', 'X-Frame-Options', 'Location'
        ]

        for header in HEADERS_TO_CHECK:
            if header in response.headers:
                self._info[header] = response.headers[header]
    


    # URLS =================================================================================================
    def _sniff_for_urls(self):
        self._display_progress('[*] Analyzing HTMLs')
        netloc = urlparse(self._url).netloc
        
        while self._responses:
            response = self._responses.pop() 
            soup     = BeautifulSoup(response.text, 'html.parser')
            self._find_url_in_html(soup, netloc)
                    
    

    def _find_url_in_html(self, soup: BeautifulSoup, netloc: str):
        TAGS_AND_ATTRIBUTES = {
            'a': 'href',     'link': 'href',   'form': 'action',  
            'area': 'href',  'base': 'href',   'embed': 'src',    
            'frame': 'src',  'script': 'src',  'iframe': 'src',   'source': 'src',
        }

        for tag, attribute in TAGS_AND_ATTRIBUTES.items():
            for element in soup.find_all(tag):
                valor = element.get(attribute)

                if not valor:
                    continue

                absolut_url = urljoin(self._url, valor)
                parsed      = urlparse(absolut_url)

                if parsed.netloc and parsed.netloc != netloc:
                    continue
                
                clean_url = parsed._replace(fragment='').geturl()
                self._known_urls.add(clean_url.rstrip('/'))

    

    # DISPLAY ==============================================================================================    
    def _display_header_info(self):
        bigger  = max(self._info, key=len)
        max_len = len(bigger) + 3

        for k, value in self._info.items():
            space = max_len - len(k)
            desc  = self._format_str(k)
            print(f'[#] {desc}{space * '.'}: {value}')

    

    @staticmethod
    def _format_str(string: str) -> str:
        string = string.replace('_', ' ')
        return string.title()
    


    def _display_links_info(self):
        print(f'[$] URLs found:')
        urls = sorted(self._known_urls)
        
        for i, url in enumerate(urls, start=1):
            print(f'{i:>3}. {url}')





if __name__ == "__main__":
    analyzer = StackSniffer()
    analyzer.analyze()