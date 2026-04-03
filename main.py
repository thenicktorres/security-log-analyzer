import argparse
import os
from parser import parse_log_file
from analyzer import (
    load_to_dataframe,
    detect_bruteforce,
    detect_anomalous_logins,
    detect_multi_ip_targeting,
    summarize_suspicious_ips
)
from report_gen import export_csv, generate_pdf_report


def main():
    parser = argparse.ArgumentParser(description="Python Security Log Analyzer")
    parser.add_argument("--input", required=True, help="Path to auth.log file")
    parser.add_argument("--format", choices=["csv", "pdf"], required=True)
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--year", type=int, help="Year for log timestamps")

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    parsed_logs = list(parse_log_file(args.input, args.year))
    if not parsed_logs:
        print("[WARNING] No valid log entries found.")
        return

    df = load_to_dataframe(parsed_logs)

    brute_force_ips = detect_bruteforce(df)
    anomalous_df = detect_anomalous_logins(df)
    multi_ip_users = detect_multi_ip_targeting(df)

    print("\nTop 5 Suspicious IPs:")
    print(summarize_suspicious_ips(df))

    flagged_events = df[
        df['ip'].isin(brute_force_ips) |
        df['username'].isin(multi_ip_users) |
        df.index.isin(anomalous_df.index)
    ]

    if args.format == "csv":
        export_csv(flagged_events, os.path.join(args.output_dir, "security_report.csv"))

    elif args.format == "pdf":
        generate_pdf_report(df, brute_force_ips, multi_ip_users, anomalous_df,
                            os.path.join(args.output_dir, "security_report.pdf"))


if __name__ == "__main__":
    main()