import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from validateUrl import ValidateUrl
from httpClient import HttpClient
from securityToolkitDb import SecToolDb
import time

def main():
    
    http = HttpClient("", 10)
    print(http.findAllPages(10))
    

 
if (__name__ == "__main__"):
    main()