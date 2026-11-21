import streamlit as st

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from httpClient import HttpClient
from validateUrl import ValidateUrl
from securityToolkitDb import SecToolDb

import time

class WebsiteTesterGui:
    def __init__(self) -> None:
        self.secToolDb = SecToolDb("registeredTargets")

        # Sidebar navigation
        page = st.sidebar.selectbox(
            "Navigation",
            ["Dashboard", "Assessment"]
        )

        if (page == "Dashboard"):

            st.title("Security Toolkit")

            col1, col2 = st.columns(2)

            with col1:
                targets = self.secToolDb.readAll()
                st.metric("Registered Targets", len(targets))

            with col2:
                url = st.text_input("URL")
                subCol1, subCol2 = st.columns([2,3])
                with subCol1:
                    if (st.button("Add URL to Scope")):
                        valid, err = ValidateUrl(url).validateUnkown()
                        if (valid):
                            self.secToolDb.create(url, time.time())
                            st.success(f"Added '{url}' to scope")
                        else:
                            st.error(f"'{url}' could not be validated. Failed {err}")
                with subCol2:
                    if (st.button("Delete URL From Scope")):
                        deleted = False
                        for id, target, _ in targets:
                            if (url == target):
                                self.secToolDb.delete(url)
                                st.success(f"Deleted '{url}'")
                                deleted = True
                        if (not deleted):
                            st.error(f"]{url}' is not in scope")
                            
                    
        elif (page == "Assessment"):

            st.title("Security Assessment")

            url = st.text_input("Target URL")

            assessmentType = st.selectbox(
                "Assessment Type",
                ["Full Assessment", "Headers", "Cookies", "Forms"]
            )

            if (st.button("Run Assessment")):

                if (not url):
                    st.error("Enter a URL first.")

                else:
                    with st.spinner("Assessing target..."):
                        st.success(
                            f"Assessment requested for {url}"
                        )

                        st.write("Type:", assessmentType)

