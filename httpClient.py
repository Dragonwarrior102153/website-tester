import requests
import re
from bs4 import BeautifulSoup
import urllib.parse
from validateUrl import ValidateUrl

class HttpClient:
    def __init__(self, url, timeout, maxSize: str = "2 MB") -> None:
        self.url = url
        self.timeout = timeout
        self.maxSize = self.parsSize(maxSize)

    @staticmethod
    def parsSize(size: str) -> int:
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)\s*", size, re.I)   #i highkey used ai for this line
        if not match:
            raise ValueError("Enter a size such as '2 MB'")

        factors = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
        amount = float(match.group(1))
        unit = match.group(2).upper()
        
        return int(amount * factors[unit])

    def getMsg(self, url) -> tuple[requests.Response, bytes] | str:
        try:
            response = requests.get(url, timeout=self.timeout, stream=True)
            content = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                content.extend(chunk)

                if len(content) > self.maxSize:
                    response.close()
                    raise ValueError("Response exceeds maximum size")

            return response, bytes(content)

        except requests.exceptions.RequestException as err:
            return str(err)

    def findPagesFromPage(self, url) -> set:
        paths = set()
        getResponse = self.getMsg(url)
        if (not isinstance(getResponse, str)):
            response, content = getResponse
            contentType = response.headers.get("Content-Type")
            if(contentType and "text/html" in contentType.lower()):
                soup = BeautifulSoup(content, "html.parser")
                for path in soup.find_all("a"):
                    relLink = path.get("href")
                    if (isinstance(relLink, str)):
                        link = urllib.parse.urljoin(self.url, relLink)
                        if (ValidateUrl(link).validate()):             
                            paths.add(link)

            return paths
            
        else:
            return set()

    def findAllPages(self, maxPages) -> set:
        allPages = set()
        visited = set()
        toVisit = {self.url}

        x = 0
        while(toVisit and x < maxPages):
            toVisit = toVisit.difference(visited)

            allPages.update(toVisit)

            if not toVisit:
                break

            pageChecked = next(iter(toVisit))

            pages = self.findPagesFromPage(pageChecked)

            visited.add(pageChecked)
            toVisit.remove(pageChecked)

            allPages.update(pages)
            toVisit.update(pages)

            x+=1 

        return allPages
