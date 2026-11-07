import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from validateUrl import ValidateUrl

def main():
    validate = ValidateUrl("ftp:/smth.com")
    print(validate.validate())
    


if (__name__ == "__main__"):
    main()