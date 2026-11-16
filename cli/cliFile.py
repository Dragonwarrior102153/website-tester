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
            if hasattr(self, "url"):
                self.actionPrompt()
            else:
                self.defaultPrompt()

            if (self.act.lower() == "url" or self.act.lower() == "info"):
                self.urlGet()
            elif (self.act.lower() == "validate"):
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
            elif (self.act.lower() == "forms"):
                self.findForms()
            elif (self.act.lower() == "form security"):
                self.analyzeFormSec()
            elif (self.act.lower() == "analyze headers"):
                self.analyzeHeaders()
            elif (self.act.lower() == "cookies"):
                self.findCookies()
            elif (self.act.lower() == "exit"):
                self.exit()


    def defaultPrompt(self):
        print("\nShow: show links in scope\nScope: add a link to scope")
        print("URL: Enter the url to be scanned\nExit: exit the application")
        print("\nFormat of the url should be https://yoursite.com (or just paste the url from a browser)")
        self.act = input("\ntype in the associated text: \n")

    def urlGet(self):
        self.url = input("\nenter the url: \n")
        self.size = input("enter max size of the file (format: 5 B, or 12 MB)\n")

    def actionPrompt(self):
        print("\nActions\n\nValidate: validate the structure of the url")
        print("Body: display the body html tags of the url \nStatus: dipslay the status code of the connection")
        print("Paths: find all the pages from the url (recursively)\nPath: find the links from the page")
        print("DNS: resolve the ip address (ipv4) of the url")
        print("\nFormat of the url should be https://yoursite.com (or just paste the url from a browser)")
        print("Analyze headers: check the url's headers for some important ones\nCookies: find cookies int the url")
        print("Forms: find all the forms and input fields in the form in the url")
        print("Form security: check if the forms have some basic secure configurations")
        print("Scope: add a link to scope\nShow: show links in scope")
        print("URL/Info: enter or change the site info\nExit: exit the application")
        self.act = input("\ntype in the associated text: \n")

    def bodyMsg(self):
        result = HttpClient(self.url, 10, self.size).getMsg(self.url)
        if isinstance(result, str):
            print(result)
        else:
            response, content = result
            print(content.decode(response.encoding or "utf-8", errors="replace"))

    def statusMsg(self):
        result = HttpClient(self.url, 10, self.size).getMsg(self.url)
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
        print(ValidateUrl(self.url).validate())

    def getPaths(self):
        max = int(input("up to how many pages can the client initiate a connection with? \n"))
        print(HttpClient(self.url, 10, self.size).findAllPages(max))

    def getPath(self):
        print(HttpClient(self.url, 10, self.size).findPagesFromPage(self.url))

    def dnsResolution(self):
        print(ValidateUrl(self.url).dnsResolution())

    def findForms(self):
        print(HttpClient(self.url, 10, self.size).findForms(self.url))

    def analyzeFormSec(self):
        print(HttpClient(self.url, 10, self.size).checkFormSecurity(self.url))

    def findCookies(self):
        print(HttpClient(self.url, 10, self.size).checkCookies(self.url))

    def analyzeHeaders(self):
        print(HttpClient(self.url, 10, self.size).checkSecHeaders(self.url))

    def exit(self):
        self.gameLoop = False