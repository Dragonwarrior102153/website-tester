# Website Tester

## What it is

Website Tester is a web-based GUI for checking and exploring websites you own
or have permission to test. Add approved base URLs to the local scope list,
then run targeted or full assessments for security headers, cookies, and forms.
Results are presented in tables and charts, with an optional PDF report
download.

The assessment tools are intended for authorized use only. The scope list helps
you keep track of approved targets, but you remain responsible for confirming
permission before every assessment.

## Features

- Validate website URLs and registered targets
- Review security headers and cookie configuration
- Inspect forms and basic form-security indicators
- Run full assessments across headers, cookies, and forms
- View severity summaries in tables and charts
- Download findings as a PDF assessment report
- Keep an approved-target scope in a local SQLite database

## Run the application

### Requirements

- Python 3.10 or newer
- Packages listed in [`requirements.txt`](requirements.txt)

The project also uses SQLite support provided by Python.

### Start from source

1. Open a terminal in the project folder.
2. Install the required packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Start the Streamlit interface:

   ```bash
   streamlit run gui/main.py
   ```

4. Open the local URL shown in the terminal.
5. Use **Dashboard** to manage registered targets or **Assessment** to scan a
   target and download an assessment report.

The local database is stored as `registeredTargets` by the GUI.

## Motivation
I made this as a small Python tool to learn website validation and crawling. It checks URLs, fetches web pages, parses links, and explores a site in a limited way, with a local scope list to keep testing focused on approved websites. Additionally, I am interested in learning more about cybersecurity in the future, and I think this project is a useful way to explore relevant concepts while building a useful tool.

<img width="309" height="93" alt="Screenshot 2026-11-08 190353" src="https://github.com/user-attachments/assets/fa6eddd4-641b-4adf-b739-9b26872ab5be" />
<img width="599" height="355" alt="Screenshot 2026-11-08 190302" src="https://github.com/user-attachments/assets/a013b8cc-a026-4041-bcdd-849f819eaef5" />
<img width="894" height="448" alt="Screenshot 2026-11-08 190136" src="https://github.com/user-attachments/assets/df8372ef-4363-4841-8d8f-0d4a0620c5c5" />
<img width="459" height="436" alt="Screenshot 2026-11-08 190113" src="https://github.com/user-attachments/assets/009fc731-4172-4ec7-90c6-31e974755c2b" />

