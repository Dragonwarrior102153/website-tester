import requests
import re
from bs4 import BeautifulSoup
import urllib.parse
from validateUrl import ValidateUrl
from headerCheckEnum import HeaderVals
from cookie import Cookie

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

    #caller must close the response
    def getMsg(self, url) -> tuple[requests.Response, bytes] | str:
        response = None
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
            try:
                contentType = response.headers.get("Content-Type")
                if(contentType and "text/html" in contentType.lower()):
                    soup = BeautifulSoup(content, "html.parser")
                    for path in soup.find_all("a"):
                        relLink = path.get("href")
                        if (isinstance(relLink, str)):
                            link = urllib.parse.urljoin(response.url, relLink)
                            if (ValidateUrl(link).validate()):             
                                paths.add(link)
            finally:
                response.close()

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

    #find forms the user fills in
    def findForms(self, url) -> tuple[list[dict], list[list[dict]]] | None:
        forms = []
        inputs = []
        getMsg = self.getMsg(url)
        if (not isinstance(getMsg, str)):
            response, content = getMsg
            try:
                soup = BeautifulSoup(content, "html.parser")
                for form in soup.find_all("form"):
                    forms.append(form.attrs)
                    inputs.append([inputTag.attrs for inputTag in form.find_all(["input", "textarea", "select", "button"])])

            finally:
                response.close()

            return (forms, inputs)
        
        else:
            return None

    #holy grail of if else statements and indents😭
    def checkSecHeaders(self, url) -> list[dict[str, str | HeaderVals | None]] | str:
        securityHeaders = ["Content-Security-Policy", "Strict-Transport-Security",
                            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
        passsecurityHeaders: list[dict[str, str | HeaderVals | None]] = [{"header": None, "status": None, "value": None} for x in range(len(securityHeaders))]
        getMsg = self.getMsg(url)
        if (not isinstance(getMsg, str)):
            response = None
            try:
                response, content = getMsg
                for index, secHeader in enumerate(securityHeaders):
                    value = response.headers.get(secHeader)
                    passsecurityHeaders[index]["header"] = secHeader
                    match secHeader:
                        case ("X-Content-Type-Options"):
                            if (value is not None):
                                if (value.strip().lower() == "nosniff"):
                                    passsecurityHeaders[index]["status"] = HeaderVals.PASS
                                    passsecurityHeaders[index]["value"] = value

                                else:
                                    passsecurityHeaders[index]["status"] = HeaderVals.MISCONFIGURED
                                    passsecurityHeaders[index]["value"] = value

                            else:
                                passsecurityHeaders[index]["status"] = HeaderVals.MISSING
                                passsecurityHeaders[index]["value"] = None

                        case ("Strict-Transport-Security"):
                            if (urllib.parse.urlparse(url).scheme.lower() == "http"):
                                passsecurityHeaders[index]["status"] = HeaderVals.INAPPLICABLE
                                passsecurityHeaders[index]["value"] = None

                            elif (value is None):                            
                                passsecurityHeaders[index]["status"] = HeaderVals.MISSING
                                passsecurityHeaders[index]["value"] = value

                            else:
                                directives = [directive.strip() for directive in value.split(";")]
                                foundMaxAge = False
                                for directive in directives:
                                    if (directive.startswith("max-age=")):
                                        maxAge = directive.split("max-age=")[1]

                                        if (not maxAge or not str.isdigit(maxAge) or int(maxAge) <= 0):
                                            passsecurityHeaders[index]["status"] = HeaderVals.MISCONFIGURED
                                            passsecurityHeaders[index]["value"] = maxAge 

                                        elif (foundMaxAge is False):
                                            if (int(maxAge) >= 31536000):                                      
                                                passsecurityHeaders[index]["status"] = HeaderVals.PASS
                                                passsecurityHeaders[index]["value"] = maxAge
                                            else:                                      
                                                passsecurityHeaders[index]["status"] = HeaderVals.WEAK
                                                passsecurityHeaders[index]["value"] = maxAge                                     

                                        else:
                                            passsecurityHeaders[index]["status"] = HeaderVals.MISCONFIGURED
                                            passsecurityHeaders[index]["value"] = "duplicates found"

                                        foundMaxAge = True

                                if (not foundMaxAge):
                                    passsecurityHeaders[index]["status"] = HeaderVals.MISSING
                                    passsecurityHeaders[index]["value"] = None

                        case ("Referrer-Policy"):
                            passing = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"] 
                            weak = ["no-referrer-when-downgrade", "origin", "origin-when-cross-origin"]
                            value = value.split(",") if value else None
                            value = value[- 1] if value else None
                            if (value is not None):
                                if (value.strip().lower() in passing):
                                    passsecurityHeaders[index]["status"] = HeaderVals.PASS
                                    passsecurityHeaders[index]["value"] = value

                                elif (value.strip().lower() in weak):
                                    passsecurityHeaders[index]["status"] = HeaderVals.WEAK
                                    passsecurityHeaders[index]["value"] = value

                                else:
                                    passsecurityHeaders[index]["status"] = HeaderVals.MISCONFIGURED
                                    passsecurityHeaders[index]["value"] = value

                            else:
                                passsecurityHeaders[index]["status"] = HeaderVals.MISSING
                                passsecurityHeaders[index]["value"] = None

                        case ("Permissions-Policy"):
                            allowedForms = {"", "*", "self", "src"}
                            #only checks some common features for now
                            validFeatures = {"camera","microphone","geolocation","fullscreen","payment","usb","screen-wake-lock"}

                            if (value is not None):
                                if (value):
                                    directives = [directive.strip() for directive in value.split(",")]
                                    valid = True
                                    for directive in directives:
                                        try:
                                            name, val = directive.split("=", 1)
                                            val = val.strip()
                                        except ValueError:
                                            valid = False
                                            break
                                        if (not val.startswith("(") or not val.endswith(")")):
                                            valid = False
                                            break
                                        allowList = val[1:-1].split()
                                        policies = [valOptions.strip() for valOptions in allowList]
                                        if (not name in validFeatures):
                                            valid = False
                                            break
                                        for policy in policies:
                                            policy = str(policy)
                                            if ("*" in policies and len(policies) > 1):
                                                valid = False
                                                break
                                            if (policy in allowedForms or (policy.startswith('"') and policy.endswith('"') and ValidateUrl(policy.strip('"')).validate()[0])):
                                                continue
                                            else:
                                                valid = False
                                                break
                                    if (valid):
                                        passsecurityHeaders[index]["status"] = HeaderVals.PASS
                                        passsecurityHeaders[index]["value"] = value
                                    else:
                                        passsecurityHeaders[index]["status"] = HeaderVals.MISCONFIGURED
                                        passsecurityHeaders[index]["value"] = value

                                else:
                                    passsecurityHeaders[index]["status"] = HeaderVals.MISCONFIGURED
                                    passsecurityHeaders[index]["value"] = value

                            else:
                                passsecurityHeaders[index]["status"] = HeaderVals.MISSING
                                passsecurityHeaders[index]["value"] = None

                        case ("Content-Security-Policy"):
                            pass

            finally:
                if (response is not None):
                    response.close()
                return passsecurityHeaders

        else:
            return getMsg

    def checkCookies(self, url) -> list[Cookie] | str:
        getMsg = self.getMsg(url)
        response = None
        cookieOverview = []
        if (not isinstance(getMsg, str)):
            try:
                response, content = getMsg
                cookies = response.cookies

                for cookie in cookies:
                    cookieObj = Cookie(
                                        cookie.name,
                                        cookie.secure,
                                        cookie.has_nonstandard_attr("HttpOnly"),
                                        cookie.get_nonstandard_attr("SameSite"),
                                        cookie.domain,
                                        cookie.path,
                                        cookie.expires,
                                        cookie.get_nonstandard_attr("Max-Age"),
                                        cookie.has_nonstandard_attr("Partitioned"),
                                        cookie.get_nonstandard_attr("Priority")
                                        )
                    cookieOverview.append(cookieObj)

                return cookieOverview
            
            finally: 
                if (response is not None):
                    response.close()

        else:
            return getMsg

    def checkFormSecurity(self, url):
        forms = self.findForms(url)
        if (forms is not None):
            forms, inputs = forms
            formsSec = [{"Scheme": None, "Submission URL": None, "Method": None, "Password Exists": False, "External Submission": False} for x in range(len(forms))]
            
            for index, form in enumerate(forms):
                action = form.get("action")
                resolvedAction = urllib.parse.urljoin(url, action or url)

                passwordFound = False
                for inputTag in inputs[index]:
                    if (inputTag.get("type", "").lower() == "password"):
                            passwordFound = True
                            break

                pageParsed = urllib.parse.urlparse(url)
                actionParsed = urllib.parse.urlparse(resolvedAction)
                pagePort = pageParsed.port or (443 if pageParsed.scheme == "https" else 80)
                actionPort = actionParsed.port or (443 if actionParsed.scheme == "https" else 80)
                pageOrigin = (pageParsed.scheme, pageParsed.hostname, pagePort)
                actionOrigin = (actionParsed.scheme, actionParsed.hostname, actionPort)
                isExternal = pageOrigin != actionOrigin

                formsSec[index]["Scheme"] = urllib.parse.urlparse(resolvedAction).scheme
                formsSec[index]["Submission URL"] = resolvedAction
                formsSec[index]["Method"] = form.get("method", "get").lower()
                formsSec[index]["Password Exists"] = passwordFound
                formsSec[index]["External Submission"] = isExternal

            return formsSec

        else: 
            return None