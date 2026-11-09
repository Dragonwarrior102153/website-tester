import sys
import time
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from httpClient import HttpClient
from securityToolkitDb import SecToolDb
from validateUrl import ValidateUrl

class CLI:
    def __init__(self) -> None:
        self.act = ""
        self.gameLoop = True
        while(self.gameLoop):
            self.defaultPrompt()
            if (self.act.lower() == "validate"):
                self.validate()
            elif (self.act.lower() == "scope"):
                self.changeScope()
            elif (self.act.lower() == "show"):
                self.showScope()
            elif (self.act.lower() == "paths"):
                self.getPaths()
            elif (self.act.lower() == "path"):
                self.getPath()
            elif (self.act.lower() == "dns"):
                self.dnsResolution()
            elif (self.act.lower() == "body"):
                self.bodyMsg()
            elif (self.act.lower() == "status"):
                self.statusMsg()
            elif (self.act.lower() == "exit"):
                self.exit()


    def defaultPrompt(self):
        print("Actions\n\nValidate: validate the structure of the url")
        print("Body: display the body html tags of the url \nStatus: dipslay the status code of the connection")
        print("Paths: find all the pages from the url (recursively)\nPath: find the links from the page")
        print("Show: show links in scope\nScope: add a link to scope")
        print("DNS: resolve the ip address (ipv4) of the url\nExit: exit the application")
        print("\nFormat of the url should be https://yoursite.com (or just paste the url from a browser)")
        self.act = input("\ntype in the associated text: \n")

    def bodyMsg(self):
        url = input("enter the url: \n")
        size = input("enter max size of the file (format: 5 B, or 12 MB)\n")
        result = HttpClient(url, 10, size).getMsg(url)
        if isinstance(result, str):
            print(result)
        else:
            response, content = result
            print(content.decode(response.encoding or "utf-8", errors="replace"))

    def statusMsg(self):
        url = input("enter the url: \n")
        size = input("enter max size of the file (format: 5 B, or 12 MB)\n")
        result = HttpClient(url, 10, size).getMsg(url)
        if isinstance(result, str):
            print(result)
        else:
            response, _ = result
            print(response.status_code)

    def changeScope(self):
        url = input("which base url should be added to scope: \n")
        SecToolDb("registeredTargets").create(url, (time.time()))

    def showScope(self):
        print(SecToolDb("registeredTargets").readAll())

    def validate(self):
        url = input("enter the url: \n")
        print(ValidateUrl(url).validate())

    def getPaths(self):
        url = input("enter the url: \n")
        max = int(input("up to how many pages can the client initiate a connection with? \n"))
        size = input("enter max size of the file (format: 5 B, or 12 MB)\n")
        print(HttpClient(url, 10, size).findAllPages(max))

    def getPath(self):
        url = input("enter the url: \n")
        size = input("enter max size of the file (format: 5 B, or 12 MB)\n")
        print(HttpClient(url, 10, size).findPagesFromPage(url))

    def dnsResolution(self):
        url = input("enter the url: \n")
        print(ValidateUrl(url).dnsResolution())

    def exit(self):
        self.gameLoop = False