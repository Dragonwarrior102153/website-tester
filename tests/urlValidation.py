import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from validateUrl import ValidateUrl
from httpClient import HttpClient
from securityToolkitDb import SecToolDb
import time

def main():
    validate = ValidateUrl("ftp:/smth.com")
    print(validate.validate())

    SecToolDb("registeredTargets").create(validate.parsedUrl.hostname, validate.url, time.time())
    
    http = HttpClient("https://terra.hackclub.com/", 10)
    print(http.getMsg(http.url).text)
    


if (__name__ == "__main__"):
    main()