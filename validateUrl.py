import urllib.parse
import validators
import socket
import http.client 

class ValidateUrl():
    def __init__(self, url) -> None:
        self.url = url
        self.parsedUrl = urllib.parse.urlparse(self.url) #ts doesnt do validation

    def validateStructure(self) -> bool:
        if (validators.url(self.url)):
            return True
        else:
            return False

    #only http and https (no other stuff)
    def checkScheme(self) -> bool:        
        return (self.parsedUrl.scheme in ["http", "https"])
    
    #port must be valid
    def checkPort(self) -> bool:
        if (self.parsedUrl.port is not None ):
            return (0 < self.parsedUrl.port <= 65535)
        else:
            return True
        

    #resolve the ipv4 addr of the url
    def dnsResolution(self) -> str | None:
        ipAddr = socket.gethostbyname(self.parsedUrl.hostname) if self.parsedUrl.hostname else None
        return ipAddr


    def checkConn(self) -> bool:  
        conn = None
        if (self.parsedUrl.port is not None):
            port = self.parsedUrl.port              #use the port if it is explicitly stated
        elif (self.parsedUrl.scheme == "http"):
            port = 80                               #use port 80 for http
        else:
            port = 443                              #use port 443 for https
        try:
            response = None
            if (self.parsedUrl.hostname is not None):
                conn = http.client.HTTPConnection(self.parsedUrl.hostname, port, timeout=5) if (self.parsedUrl.scheme == "http") else http.client.HTTPSConnection(self.parsedUrl.hostname, port, timeout=5)
                if (self.parsedUrl.path):
                    if (self.parsedUrl.query):
                        path = urllib.parse.urljoin(self.parsedUrl.path, self.parsedUrl.query)
                    else:
                        path = self.parsedUrl.path
                else:
                    path = "/"
                conn.request("HEAD", path) #HEAD so it js gets the headers instead of the whole content
                response = conn.getresponse()
                self.statusCode = response.status
            
            if (response):
                return True
            else:
                return False
    
        except (OSError, http.client.HTTPException, ValueError):
            return False

        finally:
            if (conn is not None):
                conn.close()
        

