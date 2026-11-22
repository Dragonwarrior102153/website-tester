import requests
import re
from bs4 import BeautifulSoup
import urllib.parse
from validateUrl import ValidateUrl
from headerCheckEnum import HeaderVals
from cookie import Cookie
from findings import Findings

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

    @staticmethod
    def _requestError(checkName: str, url: str, error: str | None = None) -> Findings:
        description = f"{checkName} could not be completed."
        evidence = {"url": url}
        if (error is not None):
            description = f"{description} {error}"
            evidence["error"] = error

        return Findings(checkName, "ERROR", "NONE", description, evidence)



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
    def checkSecHeaders(self, url) -> list[Findings]:
        securityHeaders = ["Strict-Transport-Security", "Permissions-Policy",
                            "X-Content-Type-Options", "Referrer-Policy"]
        passsecurityHeaders: list[dict[str, str | HeaderVals | None]] = [{"header": None, "status": None, "value": None} for _ in range(len(securityHeaders))]
        getMsg = self.getMsg(url)
        if isinstance(getMsg, str):
            return [self._requestError("Security header check", url, getMsg)]

        response, _ = getMsg
        try:
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
            response.close()

        severityByStatus = {
            HeaderVals.PASS: "NONE",
            HeaderVals.MISSING: "MEDIUM",
            HeaderVals.WEAK: "LOW",
            HeaderVals.MISCONFIGURED: "MEDIUM",
            HeaderVals.INAPPLICABLE: "NONE",
        }
        findings = []
        for headerResult in passsecurityHeaders:
            status = headerResult["status"]
            statusName = status.name if isinstance(status, HeaderVals) else "ERROR"
            findings.append(
                Findings(
                    f"Security header: {headerResult['header']}",
                    statusName,
                    severityByStatus.get(status, "NONE") if isinstance(status, HeaderVals) else "NONE",
                    f"{headerResult['header']} check status: {statusName.lower().replace('_', ' ')}.",
                    {"header": headerResult["header"], "value": headerResult["value"]},
                )
            )
        return findings

    def checkCookies(self, url) -> list[Findings]:
        getMsg = self.getMsg(url)
        if isinstance(getMsg, str):
            return [self._requestError("Cookie check", url, getMsg)]

        response, _ = getMsg
        findings = []
        try:
            for cookie in response.cookies:
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
                    cookie.get_nonstandard_attr("Priority"),
                )
                findings.append(
                    Findings(
                        f"Cookie: {cookie.name}",
                        "OBSERVED",
                        "NONE",
                        "Cookie attributes were collected; no pass/fail policy is applied.",
                        cookieObj.cookieAttr,
                    )
                )
        finally:
            response.close()
        return findings

    def checkFormSecurity(self, url) -> list[Findings]:
        forms = self.findForms(url)
        if forms is None:
            return [self._requestError("Form security check", url)]

        forms, inputs = forms
        findings = []
        for index, (form, formInputs) in enumerate(zip(forms, inputs), start=1):
            action = form.get("action")
            resolvedAction = urllib.parse.urljoin(url, action or url)
            passwordFound = any(
                inputTag.get("type", "").lower() == "password"
                for inputTag in formInputs
            )

            pageParsed = urllib.parse.urlparse(url)
            actionParsed = urllib.parse.urlparse(resolvedAction)
            pagePort = pageParsed.port or (443 if pageParsed.scheme == "https" else 80)
            actionPort = actionParsed.port or (443 if actionParsed.scheme == "https" else 80)
            pageOrigin = (pageParsed.scheme, pageParsed.hostname, pagePort)
            actionOrigin = (actionParsed.scheme, actionParsed.hostname, actionPort)
            isExternal = pageOrigin != actionOrigin
            scheme = actionParsed.scheme.lower()
            method = form.get("method", "get").lower()

            issues = []
            if (scheme != "https"):
                issues.append("The form does not submit over HTTPS.")
            if (passwordFound and method == "get"):
                issues.append("The password field is submitted using GET.")
            if (isExternal):
                issues.append("The form submits to a different origin.")

            hasInsecurePasswordSubmission = passwordFound and (
                method == "get" or scheme != "https"
            )
            if (hasInsecurePasswordSubmission):
                status = "MISCONFIGURED"
                severity = "HIGH"
            elif (scheme != "https"):
                status = "WEAK"
                severity = "MEDIUM"
            elif (isExternal):
                status = "WEAK"
                severity = "LOW"
            else:
                status = "PASS"
                severity = "NONE"

            description = " ".join(issues) if issues else (
                "The form submits over HTTPS to the same origin and does not "
                "submit a password using GET."
            )
            findings.append(
                Findings(
                    f"Form {index} security",
                    status,
                    severity,
                    description,
                    {
                        "scheme": scheme,
                        "submission_url": resolvedAction,
                        "method": method,
                        "password_exists": passwordFound,
                        "external_submission": isExternal,
                    },
                )
            )
        return findings

    