import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from validateUrl import ValidateUrl
from httpClient import HttpClient
from securityToolkitDb import SecToolDb
import time

def main():
    
    print(ValidateUrl("http://localhost:8501").validateStructure())
    
    SecToolDb("registeredTargets").delete("https://httpbin.org/")
    print(SecToolDb("registeredTargets").readAll())


if (__name__ == "__main__"):
    main()