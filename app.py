import os
import traceback
import streamlit as st
from helper import WebScanner, save_report, save_json_report, process_with_ai
from fpdf import FPDF
import json
import datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="AI Web Vulnerability Scanner", 
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main > div {
        padding-top: 2rem;
    }
    
    .stButton > button {
        width: 100%;
        border-radius: 10px;
        height: 3em;
        font-weight: 600;
        transition: all 0.3s;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .vulnerability-card {
        background: linear-gradient(135deg, #ff6b6b, #ee5a52);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    
    .success-card {
        background: linear-gradient(135deg, #51cf66, #40c057);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    
    .info-card {
        background: linear-gradient(135deg, #339af0, #228be6);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div style='text-align: center; margin-bottom: 2rem;'>
    <h1 style='color: #4a5568; font-size: 3rem; margin-bottom: 0.5rem;'>🛡️ AI Web Vulnerability Scanner</h1>
    <p style='color: #718096; font-size: 1.2rem;'>Advanced security scanning with AI-powered analysis</p>
</div>
""", unsafe_allow_html=True)

# Initialize session state
for key in ["scan_results", "json_path", "pdf_path", "scan_history"]:
    if key not in st.session_state:
        st.session_state[key] = None if key != "scan_history" else []

# Sidebar
with st.sidebar:
    st.markdown("### 📊 Dashboard Overview")
    
    # Quick stats
    if st.session_state["scan_results"]:
        data = st.session_state["scan_results"]
        vuln_count = len(data["results"])
        open_ports_count = len(data["open_ports"]) if data["open_ports"] else 0
        
        st.markdown(f"""
        <div class="metric-card">
            <h3>{vuln_count}</h3>
            <p>Vulnerabilities Found</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div class="info-card">
            <h3>{open_ports_count}</h3>
            <p>Open Ports</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 🔧 Quick Actions")
    if st.button("🗂️ View Scan History", use_container_width=True):
        st.session_state.show_history = True
    
    if st.button("📋 Export All Reports", use_container_width=True):
        st.session_state.show_export = True

# Main content area
col1, col2 = st.columns([2, 3])

with col1:
    # Scan Input Section
    st.markdown("### 🎯 Target Configuration")
    
    with st.container():
        target_url = st.text_input(
            "Target URL", 
            placeholder="https://example.com",
            help="Enter the URL you want to scan for vulnerabilities"
        )
        
        # Advanced options in expander
        with st.expander("⚙️ Advanced Options"):
            scan_depth = st.slider("Scan Depth", 1, 5, 3)
            timeout = st.number_input("Timeout (seconds)", 5, 60, 30)
            custom_headers = st.text_area("Custom Headers (JSON format)", placeholder='{"User-Agent": "Custom Scanner"}')
    
    # Action buttons
    st.markdown("### 🚀 Actions")
    col_scan, col_ai = st.columns(2)
    
    with col_scan:
        run_scan = st.button("🔍 Start Scan", type="primary", use_container_width=True)
    
    with col_ai:
        run_ai = st.button("🤖 AI Analysis", use_container_width=True)

with col2:
    # Results Dashboard
    st.markdown("### 📊 Scan Results Dashboard")
    
    if st.session_state["scan_results"]:
        data = st.session_state["scan_results"]
        
        # Create metrics row
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
        
        with metric_col1:
            st.metric(
                label="Vulnerabilities",
                value=len(data["results"]),
                delta=f"Target: {data['target'].split('//')[1][:20]}..."
            )
        
        with metric_col2:
            st.metric(
                label="Open Ports", 
                value=len(data["open_ports"]) if data["open_ports"] else 0,
                delta="Active Services"
            )
        
        with metric_col3:
            st.metric(
                label="Services Detected",
                value=len(data["service_versions"]) if data["service_versions"] else 0,
                delta="Fingerprinted"
            )
        
        with metric_col4:
            st.metric(
                label="Scan Status",
                value="Complete",
                delta="✅ Success"
            )
        
        # Vulnerability severity chart (mock data for demonstration)
        if data["results"]:
            vuln_data = []
            for vuln, url, guide in data["results"]:
                # Mock severity classification
                if "SQL" in vuln.upper():
                    severity = "Critical"
                elif "XSS" in vuln.upper():
                    severity = "High"
                else:
                    severity = "Medium"
                vuln_data.append({"Vulnerability": vuln, "Severity": severity, "URL": url})
            
            df = pd.DataFrame(vuln_data)
            severity_counts = df['Severity'].value_counts()
            
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Distribution by Severity",
                color_discrete_map={
                    'Critical': '#ff6b6b',
                    'High': '#ffa726',
                    'Medium': '#ffcc02',
                    'Low': '#66bb6a'
                }
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("👆 Enter a target URL and click 'Start Scan' to begin analysis")

# Main content sections
st.markdown("---")

# Scan execution
if run_scan:
    if not target_url or not (target_url.startswith("http://") or target_url.startswith("https://")):
        st.error("⚠️ Please enter a valid URL with scheme (http:// or https://)")
    else:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("🔍 Initializing scanner...")
        progress_bar.progress(20)
        
        try:
            scanner = WebScanner(target_url.strip())
            
            status_text.text("🌐 Scanning target for vulnerabilities...")
            progress_bar.progress(50)
            
            results, open_ports, closed_ports, filtered_ports, service_versions, os_info = scanner.scan()
            
            status_text.text("📊 Generating reports...")
            progress_bar.progress(80)
            
            # Store results
            st.session_state["scan_results"] = {
                "results": results,
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "filtered_ports": filtered_ports,
                "service_versions": service_versions,
                "os_info": os_info,
                "target": target_url.strip(),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Add to scan history
            if "scan_history" not in st.session_state:
                st.session_state["scan_history"] = []
            st.session_state["scan_history"].append({
                "target": target_url.strip(),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "vulnerabilities": len(results),
                "status": "Complete"
            })
            
            # Save reports
            pdf_path = save_report(results, open_ports, closed_ports, filtered_ports, service_versions, os_info)
            json_path = save_json_report(results, open_ports, closed_ports, filtered_ports, service_versions, os_info, target_url.strip())
            
            st.session_state["pdf_path"] = pdf_path if isinstance(pdf_path, str) and os.path.exists(pdf_path) else None
            st.session_state["json_path"] = json_path if isinstance(json_path, str) and os.path.exists(json_path) else None
            
            progress_bar.progress(100)
            status_text.text("✅ Scan completed successfully!")
            
            st.success("🎉 Vulnerability scan completed! Check the results above.")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Scan failed: {str(e)}")
            st.exception(e)

# Results display
if st.session_state["scan_results"]:
    data = st.session_state["scan_results"]
    
    # Vulnerabilities section
    st.markdown("### ⚠️ Vulnerability Details")
    
    if data["results"]:
        for i, (vuln, url, guide) in enumerate(data["results"]):
            with st.expander(f"🚨 {vuln}", expanded=i==0):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**Target URL:** `{url}`")
                    st.markdown(f"**Learning Resource:** [Security Guide]({guide})")
                with col2:
                    if st.button(f"📋 Copy URL", key=f"copy_{i}"):
                        st.write("URL copied to clipboard!")
    else:
        st.markdown("""
        <div class="success-card">
            <h3>🎉 No Vulnerabilities Found!</h3>
            <p>Your target appears to be secure from common web vulnerabilities.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Technical details in tabs
    st.markdown("### 🔧 Technical Analysis")
    tab1, tab2, tab3 = st.tabs(["🔌 Port Analysis", "🛠️ Service Detection", "💻 System Information"])
    
    with tab1:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("**Open Ports**")
            if data["open_ports"]:
                for port in data["open_ports"]:
                    st.code(f"Port {port}")
            else:
                st.info("No open ports detected")
        
        with col2:
            st.markdown("**Closed Ports**")
            if data["closed_ports"]:
                st.text(f"{len(data['closed_ports'])} ports closed")
            else:
                st.info("No closed ports detected")
        
        with col3:
            st.markdown("**Filtered Ports**")
            if data["filtered_ports"]:
                st.text(f"{len(data['filtered_ports'])} ports filtered")
            else:
                st.info("No filtered ports detected")
    
    with tab2:
        if data["service_versions"]:
            st.json(data["service_versions"])
        else:
            st.info("No service banners detected")
    
    with tab3:
        st.markdown(f"**OS Information:** {data['os_info']}")
    
    # Download section
    st.markdown("### 📥 Export Reports")
    download_col1, download_col2 = st.columns(2)
    
    with download_col1:
        if st.session_state["pdf_path"]:
            with open(st.session_state["pdf_path"], "rb") as f:
                st.download_button(
                    "📄 Download PDF Report",
                    f,
                    file_name=f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
        else:
            st.button("📄 PDF Not Available", disabled=True, use_container_width=True)
    
    with download_col2:
        if st.session_state["json_path"]:
            with open(st.session_state["json_path"], "rb") as f:
                st.download_button(
                    "📊 Download JSON Report",
                    f,
                    file_name=f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
        else:
            st.button("📊 JSON Not Available", disabled=True, use_container_width=True)

# AI Analysis section
if run_ai:
    if not st.session_state.get("json_path"):
        st.warning("⚠️ Please run a scan first to generate data for AI analysis.")
    else:
        with st.spinner("🤖 Running AI security analysis..."):
            try:
                ai_output = process_with_ai(st.session_state["json_path"])
                
                st.markdown("### 🧠 AI Security Analysis")
                
                # Create tabs for different views
                analysis_tab1, analysis_tab2 = st.tabs(["📋 Analysis Report", "📊 Structured View"])
                
                with analysis_tab1:
                    st.text_area(
                        "AI Analysis Results",
                        ai_output if isinstance(ai_output, str) else str(ai_output),
                        height=400,
                        help="Detailed AI analysis of the vulnerability scan results"
                    )
                
                with analysis_tab2:
                    # Try to structure the AI output if it's JSON-like
                    try:
                        if isinstance(ai_output, str):
                            structured_data = json.loads(ai_output)
                            st.json(structured_data)
                        else:
                            st.json(ai_output)
                    except:
                        st.text(ai_output)
                
                # Save AI analysis
                output_dir = "ai_reports"
                os.makedirs(output_dir, exist_ok=True)
                
                # Save JSON
                json_path = os.path.join(output_dir, f"ai_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                with open(json_path, "w", encoding="utf-8") as jf:
                    json.dump({"ai_analysis": ai_output, "timestamp": datetime.datetime.now().isoformat()}, jf, indent=4, ensure_ascii=False)
                
                # Save PDF
                pdf_path = os.path.join(output_dir, f"ai_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                
                today = datetime.datetime.now().strftime("%A, %d %B %Y")
                pdf.cell(0, 10, txt=f"AI Analysis Report - {today}", ln=True, align='C')
                pdf.ln(10)
                
                ai_output_str = str(ai_output)
                pdf.multi_cell(0, 10, ai_output_str[:2000])  # Limit to prevent PDF issues
                pdf.output(pdf_path)
                
                st.success("✅ AI analysis completed and saved!")
                
                # Download buttons for AI analysis
                ai_col1, ai_col2 = st.columns(2)
                with ai_col1:
                    with open(json_path, "r", encoding="utf-8") as f:
                        st.download_button(
                            "📊 Download AI Analysis (JSON)",
                            f,
                            file_name=f"ai_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json",
                            use_container_width=True
                        )
                
                with ai_col2:
                    with open(pdf_path, "rb") as f:
                        st.download_button(
                            "📄 Download AI Analysis (PDF)",
                            f,
                            file_name=f"ai_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                        
            except Exception as e:
                st.error("❌ AI analysis failed:")
                st.code(traceback.format_exc())

# Scan History (if enabled)
if st.session_state.get("show_history") and st.session_state.get("scan_history"):
    st.markdown("---")
    st.markdown("### 📊 Scan History")
    
    history_df = pd.DataFrame(st.session_state["scan_history"])
    st.dataframe(history_df, use_container_width=True)
    
    if st.button("Clear History"):
        st.session_state["scan_history"] = []
        st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #718096; padding: 2rem;'>
    <p>🛡️ AI Web Vulnerability Scanner | Built with Streamlit | Secure • Fast • Intelligent</p>
</div>
""", unsafe_allow_html=True)