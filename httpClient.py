import requests
from bs4 import BeautifulSoup
import urllib.parse
from validateUrl import ValidateUrl

class HttpClient:
    def __init__(self, url, timeout) -> None:
        self.url = url
        self.timeout = timeout


    def getMsg(self, url) -> requests.Response | str:
        try:
            response = requests.get(url, timeout=self.timeout)

            return response

        except requests.exceptions.RequestException as err:
            return str(err)

    def findPagesFromPage(self, url) -> set:
        paths = set()
        getResponse = self.getMsg(url)
        if (not isinstance(getResponse, str)):
            contentType = getResponse.headers.get("Content-Type")
            if(contentType and "text/html" in contentType.lower()):
                soup = BeautifulSoup(getResponse.text, "html.parser")
                for path in soup.find_all("a"):
                    relLink = path.get("href")
                    if (isinstance(relLink, str)):
                        link = urllib.parse.urljoin(self.url, relLink)
                        if (ValidateUrl(link).checkScheme()):             
                            paths.update(link)

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

            pageChecked = next(iter(toVisit))

            pages = self.findPagesFromPage(pageChecked)
            visited.update(toVisit)
            toVisit.remove(pageChecked)

            allPages.update(pages)
            toVisit.update(pages)

            x+=1 

        return allPages


