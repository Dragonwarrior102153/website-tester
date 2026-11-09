# Website Tester

## What it is

Website Tester is a command-line tool for checking and exploring websites you own
or have permission to test. It can validate a URL, check its connection, resolve
its IPv4 address, fetch a page's HTML or status code, and find links on a page or
across a limited number of pages.

The tool also lets you save base URLs in a local scope list. The `Validate`
action checks that the exact URL has been added to this list first. The list is
a reminder and a validation gate; it does not automatically restrict the other
actions to those URLs.

## Run the packaged Windows executable

If you are using the packaged `WebsiteTester.exe`, you do not need to install
Python or the project libraries separately.

1. Open the folder containing `WebsiteTester.exe`
2. Double-click `WebsiteTester.exe`, or open a terminal in that folder and run:

   ```powershell
   .\WebsiteTester.exe
   ```

3. Use the command-line menu as described below. The local scope database is
   created in the current working directory.

## Run from source: requirements

Use these requirements only if you want to run the Python source code instead
of the packaged executable:

- Python 3.10 or newer
- The Python packages listed in [`requirements.txt`](requirements.txt):
  - `beautifulsoup4`
  - `requests`
  - `validators`

The other modules used by the program, including SQLite support, come with
Python.

## Run from source

1. Open a terminal in the project folder.
2. Install the required packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Start the command-line menu:

   ```bash
   python cli/main.py
   ```

4. Type an action at the prompt. For `Validate`, first choose `Scope` and add
   the exact URL you want to validate (for example, `https://example.com`).
5. Follow the prompts for the chosen action. When asked for a maximum response
   size, enter a number and unit such as `2 MB`; for `Paths`, also enter the
   maximum number of pages to visit.
6. Choose `Exit` when you're done.

The local scope database is created in the current working directory as
`SecurityToolkitDb`.

Only test websites you own or have explicit permission to assess.

## Motivation

I made this because I am interested in learning more about cybersecurity in the future, and I think this will be a good foundation for me.

<img width="309" height="93" alt="Screenshot 2026-11-08 190353" src="https://github.com/user-attachments/assets/fa6eddd4-641b-4adf-b739-9b26872ab5be" />
<img width="599" height="355" alt="Screenshot 2026-11-08 190302" src="https://github.com/user-attachments/assets/a013b8cc-a026-4041-bcdd-849f819eaef5" />
<img width="894" height="448" alt="Screenshot 2026-11-08 190136" src="https://github.com/user-attachments/assets/df8372ef-4363-4841-8d8f-0d4a0620c5c5" />
<img width="459" height="436" alt="Screenshot 2026-11-08 190113" src="https://github.com/user-attachments/assets/009fc731-4172-4ec7-90c6-31e974755c2b" />

