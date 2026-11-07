import requests
from bs4 import BeautifulSoup
import urllib.parse
from validateUrl import ValidateUrl

class HttpClient:
    def __init__(self, url, timeout) -> None:
        self.url = url
        self.timeout = timeout


    def getMsg(self) -> requests.Response | str:
        try:
            response = requests.get(self.url, timeout=self.timeout)

            return response

        except requests.exceptions.RequestException as err:
            return str(err)

    def findPages(self) -> set | None:
        paths = set()
        getHtml = self.getMsg()
        if (not isinstance(getHtml, str)):
            contentType = getHtml.headers.get("Content-Type")
            if(contentType and "text/html" in contentType.lower()):
                soup = BeautifulSoup(getHtml.text, "html.parser")
                for path in soup.find_all("a"):
                    link = path.get("href")
                    if (isinstance(link, str) and ValidateUrl(link).checkScheme()):             
                        paths.add(link)

            return paths
        
        else:
            return None

