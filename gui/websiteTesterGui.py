import streamlit as st

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from httpClient import HttpClient
from validateUrl import ValidateUrl
from securityToolkitDb import SecToolDb

from pdfExporter import generatePDF

import time
import datetime
import pandas as pd
import plotly.graph_objects as go


class WebsiteTesterGui:
    def __init__(self) -> None:
        self.secToolDb = SecToolDb("registeredTargets")
        
        if ("dataFound" not in st.session_state):
            st.session_state.dataFound = []

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
                sizeCol, pagesCol = st.columns(2)
                with sizeCol:
                    size = st.text_input("Max Size per Page", placeholder="5 MB")
                with pagesCol:
                    maxPagesText = st.text_input(
                        "Max Pages to Crawl",
                        placeholder="10",
                        help="Leave empty to crawl up to 10 pages."
                    )

            subCol1, subCol2 = st.columns(2)
            with subCol1:
                runBtn = st.button("Run Assessment")
                
            if (runBtn):
                valid, err = ValidateUrl(url).validateUnkown()
                if (not valid):
                    st.error(f"Invalid URL. \n{err}")

                else:
                    with st.spinner("Assessing target..."):
                        maxSize = size if size else "5 MB"
                        try:
                            maxPages = int(maxPagesText) if maxPagesText.strip() else 10
                            if maxPages <= 0:
                                raise ValueError
                        except (AttributeError, ValueError):
                            st.error("Max Pages to Crawl must be a positive whole number.")
                            return

                        self.client = HttpClient(url, 10, maxSize, maxPages)
                        match (assessmentType):
                            case ("Headers"):
                                self.headerCheck()
                            case ("Cookies"):
                                self.scanCookies()
                            case ("Forms"):
                                self.formSecCheck()
                            case ("Full Assessment"):
                                self.showFullScan()
                            
                        with subCol1:    
                            st.success(
                                f"Assessment requested for {url}. Type: {assessmentType}"
                            )
                        
            none = 0
            low = 0
            medium = 0
            high = 0
            
            for data in st.session_state.dataFound:
                match (data["severity"]):
                    case ("HIGH"):
                        high += 1
                    case ("MEDIUM"):
                        medium += 1
                    case ("LOW"):
                        low += 1
                    case ("NONE"):
                        none += 1
                        
            with subCol1:
                if (st.session_state.dataFound):
                    pdf = generatePDF(url, st.session_state.dataFound)
                    st.download_button(
                        label="Download Assessment Report",
                        data=pdf,
                        file_name="Security_Assessment.pdf",
                        mime="application/pdf"
                    )
                    
            
            with subCol2:
                fig = go.Figure(data=[go.Pie(
                    labels=["None", "Low", "Medium", "High"],
                    values=[none, low, medium, high],
                    hole=.3,
                    marker=dict(
                        colors=["#7D7D7D", "#FFFF00", "#FFAE00", "#FF1900"]
                    )
                )])
                st.plotly_chart(fig, width="stretch", height=400)
                fig.update_layout(
                    margin=dict(l=0, r=0, t=0, b=0),
                )
                fig.update_traces(domain=dict(y=[0.25, 1]))
    
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
        cookies = self.client.checkCookies(self.client.url)
        st.session_state.dataFound = [finding.dictionary() for finding in cookies]
        df = pd.DataFrame(st.session_state.dataFound)
        st.dataframe(df, hide_index=True)
        
    @st.dialog("Displaying Header Check Results")
    def headerCheck(self):
        headerCheckResult = self.client.checkSecHeaders(self.client.url)
        st.session_state.dataFound = [finding.dictionary() for finding in headerCheckResult]
        df = pd.DataFrame(st.session_state.dataFound)
        st.dataframe(df, hide_index=True)
        
    @st.dialog("Displaying Form Security Results")
    def formSecCheck(self):
        formCheckResult = self.client.checkFormSecurity(self.client.url)
        st.session_state.dataFound = [finding.dictionary() for finding in formCheckResult]
        df = pd.DataFrame(st.session_state.dataFound)
        st.dataframe(df, hide_index=True)
        
    @st.dialog("Showing Full Assessment Results", width="large")
    def showFullScan(self):
        tab1, tab2, tab3, = st.tabs(["Headers", "Cookies", "Forms"])
        pages = self.client.findAllPages()

        headerResultFound = []
        cookiesFound = []
        formSecFound = []

        for page in sorted(pages):
            headerResultFound.extend(
                finding.dictionary() for finding in self.client.checkSecHeaders(page)
            )
            cookiesFound.extend(
                finding.dictionary() for finding in self.client.checkCookies(page)
            )
            formSecFound.extend(
                finding.dictionary() for finding in self.client.checkFormSecurity(page)
            )
        
        with tab1:
            st.subheader("Header Scan Results")
            df = pd.DataFrame(headerResultFound)
            st.dataframe(df, hide_index=True)
        
        with tab2:
            df = pd.DataFrame(cookiesFound)
            st.dataframe(df, hide_index=True)
            
        with tab3:
            df = pd.DataFrame(formSecFound)
            st.dataframe(df, hide_index=True)
            
        st.session_state.dataFound = formSecFound + cookiesFound + headerResultFound