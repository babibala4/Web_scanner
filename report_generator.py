from datetime import datetime
import json
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import plotly.graph_objects as go
import plotly.utils
import base64
from io import BytesIO

def generate_professional_report(scan_results):
    """Generate a professional 5+ years experience level security report"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"reports/security_scan_{timestamp}.pdf"
    
    # Ensure reports directory exists
    os.makedirs('reports', exist_ok=True)
    
    # Create PDF document
    doc = SimpleDocTemplate(
        report_filename,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#2c3e50')
    )
    
    heading_style = ParagraphStyle(
        'Heading2',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#34495e')
    )
    
    # Add title
    elements.append(Paragraph("Web Application Security Assessment Report", title_style))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    elements.append(Spacer(1, 10))
    
    vuln_stage = scan_results.get('vuln_stage', 'Unknown')
    vuln_colors = {
        'Critical': colors.red,
        'High': colors.orange,
        'Medium': colors.yellow,
        'Low': colors.green,
        'Default': colors.gray
    }
    
    summary_text = f"""
    This report presents the findings of a comprehensive security assessment conducted on 
    <b>{scan_results['target']}</b> on <b>{scan_results['timestamp']}</b>. 
    The assessment utilized multiple scanning tools to identify potential vulnerabilities 
    and security misconfigurations.
    <br/><br/>
    <b>Overall Risk Level: <font color='{vuln_colors.get(vuln_stage, colors.gray)}'>{vuln_stage}</font></b>
    <br/><br/>
    A total of <b>{len(scan_results.get('vulnerabilities', []))}</b> potential security issues were identified.
    """
    
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Scan Information
    elements.append(Paragraph("SCAN INFORMATION", heading_style))
    scan_info = [
        ["Target", scan_results['target']],
        ["Scan Date", scan_results['timestamp']],
        ["Scan Type", scan_results['scan_type']],
        ["Requested By", scan_results['gmail']],
        ["Scan ID", scan_results['scan_id']]
    ]
    
    info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(info_table)
    elements.append(Spacer(1, 20))
    
    # Vulnerability Summary Chart
    elements.append(Paragraph("VULNERABILITY SUMMARY", heading_style))
    
    # Create severity distribution
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for vuln in scan_results.get('vulnerabilities', []):
        severity = vuln.get('severity', 'Low')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Generate chart using Plotly
    fig = go.Figure(data=[
        go.Bar(
            x=list(severity_counts.keys()),
            y=list(severity_counts.values()),
            marker_color=['red', 'orange', 'yellow', 'green']
        )
    ])
    
    fig.update_layout(
        title="Vulnerability Severity Distribution",
        xaxis_title="Severity Level",
        yaxis_title="Number of Findings",
        showlegend=False
    )
    
    # Convert plot to image
    img_bytes = fig.to_image(format="png", width=600, height=400)
    img_buffer = BytesIO(img_bytes)
    
    # Add chart to PDF
    elements.append(Image(img_buffer, width=5*inch, height=3*inch))
    elements.append(Spacer(1, 20))
    
    # Detailed Findings
    elements.append(Paragraph("DETAILED FINDINGS", heading_style))
    
    for i, vuln in enumerate(scan_results.get('vulnerabilities', []), 1):
        vuln_text = f"""
        <b>{i}. {vuln.get('title', 'Unknown Vulnerability')}</b><br/>
        <b>Severity:</b> {vuln.get('severity', 'Low')}<br/>
        <b>Description:</b> {vuln.get('description', 'No description provided')}<br/>
        <b>Impact:</b> {vuln.get('impact', 'Impact not specified')}<br/>
        <b>Recommendation:</b> {vuln.get('recommendation', 'No recommendation provided')}<br/>
        """
        elements.append(Paragraph(vuln_text, styles['Normal']))
        elements.append(Spacer(1, 10))
    
    # Scanner Results
    elements.append(Paragraph("SCANNER OUTPUTS", heading_style))
    
    for scanner_name, scanner_result in scan_results['results'].items():
        if scanner_result.get('success'):
            elements.append(Paragraph(f"{scanner_name.upper()} Results:", styles['Heading3']))
            
            if scanner_name == 'curl' and 'security_analysis' in scanner_result:
                # Format curl security analysis nicely
                security = scanner_result['security_analysis']
                
                # Present security headers
                if security['present']:
                    elements.append(Paragraph("✓ Present Security Headers:", styles['Normal']))
                    for header in security['present']:
                        elements.append(Paragraph(f"  • {header}", styles['Normal']))
                
                if security['missing']:
                    elements.append(Paragraph("✗ Missing Security Headers:", styles['Normal']))
                    for header in security['missing']:
                        elements.append(Paragraph(f"  • {header}", styles['Normal']))
                
                elements.append(Paragraph(f"Security Score: {security['score']}/100", styles['Normal']))
            else:
                # Truncate long outputs
                output = scanner_result.get('output', 'No output')
                if len(output) > 500:
                    output = output[:500] + "... (truncated)"
                elements.append(Paragraph(output.replace('\n', '<br/>'), styles['Code']))
            
            elements.append(Spacer(1, 10))
    
    # Recommendations
    elements.append(Paragraph("RECOMMENDATIONS", heading_style))
    
    recommendations = [
        "1. Implement missing security headers identified in the curl analysis",
        "2. Address critical and high severity vulnerabilities immediately",
        "3. Conduct regular security assessments using multiple scanning tools",
        "4. Keep all systems and applications patched and updated",
        "5. Implement a Web Application Firewall (WAF) for additional protection",
        "6. Conduct penetration testing for critical applications",
        "7. Develop and maintain an incident response plan"
    ]
    
    for rec in recommendations:
        elements.append(Paragraph(rec, styles['Normal']))
        elements.append(Spacer(1, 5))
    
    # Footer
    elements.append(Spacer(1, 30))
    footer_text = f"""
    <i>Report generated by WebScan Professional v1.0 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i><br/>
    <i>This report is confidential and intended for authorized personnel only.</i>
    """
    elements.append(Paragraph(footer_text, styles['Italic']))
    
    # Build PDF
    doc.build(elements)
    
    return report_filename

def analyze_vulnerabilities(results):
    """Analyze scanner results to extract vulnerabilities"""
    vulnerabilities = []
    
    # Analyze Nmap results
    if 'nmap' in results and results['nmap'].get('success'):
        nmap_output = results['nmap'].get('output', '')
        
        # Look for vulnerability patterns in Nmap output
        if "VULNERABLE" in nmap_output or "CVE-" in nmap_output:
            vulnerabilities.append({
                'title': 'Potential Vulnerabilities Detected by Nmap',
                'severity': 'High',
                'description': 'Nmap vulnerability scripts detected potential security issues',
                'impact': 'System may be vulnerable to various attacks',
                'recommendation': 'Review Nmap output and patch identified vulnerabilities'
            })
    
    # Analyze Nikto results
    if 'nikto' in results and results['nikto'].get('success'):
        nikto_output = results['nikto'].get('output', '')
        
        # Count Nikto findings
        finding_count = nikto_output.count('+')
        if finding_count > 10:
            severity = 'Critical'
        elif finding_count > 5:
            severity = 'High'
        elif finding_count > 2:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        if finding_count > 0:
            vulnerabilities.append({
                'title': f'Web Server Vulnerabilities ({finding_count} findings)',
                'severity': severity,
                'description': 'Nikto web scanner identified multiple potential vulnerabilities',
                'impact': 'Web application may be exposed to various attacks',
                'recommendation': 'Review Nikto findings and apply necessary patches and configurations'
            })
    
    # Analyze curl security headers
    if 'curl' in results and results['curl'].get('success'):
        security = results['curl'].get('security_analysis', {})
        missing_count = len(security.get('missing', []))
        
        if missing_count >= 4:
            severity = 'High'
        elif missing_count >= 2:
            severity = 'Medium'
        elif missing_count > 0:
            severity = 'Low'
        else:
            severity = 'Low'
        
        if missing_count > 0:
            vulnerabilities.append({
                'title': f'Missing Security Headers ({missing_count} headers)',
                'severity': severity,
                'description': 'Important security headers are missing from HTTP responses',
                'impact': 'Increased risk of XSS, clickjacking, and other web attacks',
                'recommendation': 'Implement missing security headers in web server configuration'
            })
    
    return vulnerabilities

def determine_vuln_stage(vulnerabilities):
    """Determine overall vulnerability stage"""
    if not vulnerabilities:
        return 'Default'
    
    severity_weights = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }
    
    total_weight = sum(severity_weights.get(v.get('severity', 'Low'), 1) for v in vulnerabilities)
    
    if total_weight >= 8:
        return 'Critical'
    elif total_weight >= 5:
        return 'High'
    elif total_weight >= 3:
        return 'Medium'
    else:
        return 'Low'
