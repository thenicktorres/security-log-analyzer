import pandas as pd
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
import os


def export_csv(df, output_path):
    df.to_csv(output_path, index=False)
    print(f"[INFO] CSV report saved to {output_path}")


def generate_chart(df, chart_path):
    df['hour'] = df['timestamp'].dt.hour
    summary = df.groupby(['hour', 'status']).size().unstack(fill_value=0)

    plt.figure()
    summary.plot(kind='bar')
    plt.title("Failed vs Successful Logins by Hour")
    plt.xlabel("Hour of Day")
    plt.ylabel("Login Count")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()


def calculate_risk_level(brute_force_ips, multi_ip_users, anomalous_count):
    score = len(brute_force_ips) * 3 + len(multi_ip_users) * 2 + anomalous_count * 0.1

    if score > 20:
        return "HIGH"
    elif score > 10:
        return "MEDIUM"
    else:
        return "LOW"


def generate_pdf_report(df, brute_force_ips, multi_ip_users, anomalous_df, output_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_path, pagesize=letter)

    chart_path = "login_chart.png"
    generate_chart(df, chart_path)

    risk = calculate_risk_level(brute_force_ips, multi_ip_users, len(anomalous_df))

    content = []
    content.append(Paragraph("Security Log Analysis Report", styles['Title']))
    content.append(Spacer(1, 20))

    content.append(Paragraph(f"Risk Level: <b>{risk}</b>", styles['Normal']))
    content.append(Spacer(1, 20))

    content.append(Paragraph(f"Brute Force IPs Detected: {len(brute_force_ips)}", styles['Normal']))
    content.append(Paragraph(f"Multi-IP Targeted Accounts: {len(multi_ip_users)}", styles['Normal']))
    content.append(Paragraph(f"Anomalous Login Attempts: {len(anomalous_df)}", styles['Normal']))
    content.append(Spacer(1, 20))

    content.append(Image(chart_path, width=400, height=200))

    doc.build(content)
    os.remove(chart_path)

    print(f"[INFO] PDF report saved to {output_path}")