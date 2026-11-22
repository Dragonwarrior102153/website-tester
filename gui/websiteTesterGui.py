import streamlit as st

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from httpClient import HttpClient
from validateUrl import ValidateUrl
from securityToolkitDb import SecToolDb
from findings import Findings

import time
import datetime
import pandas as pd

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
                
                if (st.button("Show Targets")):
                    self.showScope()

            with col2:
                url = st.text_input("URL")
                subCol1, subCol2 = st.columns([2,3])
                outside = st.empty()
                with subCol1:
                    if (st.button("Add URL to Scope")):
                        valid, err = ValidateUrl(url).validateUnkown()
                        if (valid):
                            self.secToolDb.create(url, time.time())
                            outside.success(f"Added '{url}' to scope")
                        else:
                            outside.error(f"'{url}' could not be validated. Failed {err}")
                with subCol2:
                    if (st.button("Delete URL From Scope")):
                        deleted = False
                        for id, target, _ in targets:
                            if (url == target):
                                self.secToolDb.delete(url)
                                outside.success(f"Deleted '{url}'")
                                deleted = True
                        if (not deleted):
                            outside.error(f"]{url}' is not in scope")
                            
                    
        elif (page == "Assessment"):

            st.title("Security Assessment")

            url = st.text_input("Target URL")

            col1, col2 = st.columns(2)
            
            with col1:
                assessmentType = st.selectbox(
                    "Assessment Type",
                    ["Full Assessment", "Headers", "Cookies", "Forms"]
                )
            
            with col2:
                size = st.text_input("Max Size per Page")

            if (st.button("Run Assessment")):
                valid, err = ValidateUrl(url).validateUnkown()
                if (not valid):
                    st.error(f"Invalid URL. \n{err}")

                else:
                    with st.spinner("Assessing target..."):
                        maxSize = size if size else "5 MB"
                        self.client = HttpClient(url, 10, maxSize)
                        self.headerCheck()
                        st.success(
                            f"Assessment requested for {url}"
                        )

                        st.write("Type:", assessmentType)
    
    @st.dialog("Displaying Targets")
    def showScope(self):
        targets = self.secToolDb.readAll()
        convertedTargets = [
        (url, datetime.datetime.fromtimestamp(float(timestamp)).strftime("%m/%d/%Y %I:%M %p"))
        for id, url, timestamp in targets]
        df = pd.DataFrame(convertedTargets, columns=["URL", "Time When Added"])
        df.index.name = "Index"
        st.dataframe(df)
    
    @st.dialog("Displaying Cookies")      
    def scanCookies(self):
        self.cookies = self.client.checkCookies(self.client.url)
        self.findingsData = [finding.dictionary() for finding in self.cookies]
        df = pd.DataFrame(self.findingsData)
        st.dataframe(df, hide_index=True)
        
    @st.dialog("Displaying Header Check Results")
    def headerCheck(self):
        self.headerCheckResult = self.client.checkSecHeaders(self.client.url)
        self.findingsData = [finding.dictionary() for finding in self.headerCheckResult]
        df = pd.DataFrame(self.findingsData)
        st.dataframe(df, hide_index=True)