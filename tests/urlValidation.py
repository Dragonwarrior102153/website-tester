import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from validateUrl import ValidateUrl
from httpClient import HttpClient

def main():
    validate = ValidateUrl("ftp:/smth.com")
    print(validate.validate())

    http = HttpClient("https://terra.hackclub.com/", 10)
    print(http.getMsg().text)
    


if (__name__ == "__main__"):
    main()