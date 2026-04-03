import pandas as pd

BUSINESS_START = 6   # 6 AM
BUSINESS_END = 21    # 9 PM


def load_to_dataframe(parsed_logs):
    df = pd.DataFrame(parsed_logs)
    if df.empty:
        return df
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df


def detect_bruteforce(df):
    alerts = []
    failed = df[df['status'] == 'Failed']

    for ip in failed['ip'].unique():
        ip_logs = failed[failed['ip'] == ip].sort_values("timestamp")
        ip_logs.set_index("timestamp", inplace=True)

        # Rolling 5-minute window
        counts = ip_logs['status'].rolling("5min").count()
        if any(counts > 5):
            alerts.append(ip)

    return alerts


def detect_anomalous_logins(df):
    return df[(df['timestamp'].dt.hour < BUSINESS_START) |
              (df['timestamp'].dt.hour >= BUSINESS_END)]


def detect_multi_ip_targeting(df):
    grouped = df.groupby('username')['ip'].nunique()
    return grouped[grouped > 1].index.tolist()


def summarize_suspicious_ips(df):
    failed_counts = df[df['status'] == 'Failed'].groupby('ip').size()
    return failed_counts.sort_values(ascending=False).head(5)