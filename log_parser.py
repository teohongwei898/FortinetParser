import pandas as pd
import os
import argparse
from glob import glob
import sys
import re

def extract_timezone(files):
    """Extract and format the timezone as UTC+X."""
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split()
                for part in parts:
                    if part.startswith('tz='):
                        raw_tz = part.split('=')[1].strip('"')  # Extract raw timezone (e.g., "+0800")
                        match = re.match(r"([+-])(\d{2})00", raw_tz)  # Extract hours (ignore last 2 digits)
                        if match:
                            sign, hours = match.groups()
                            return f"UTC{sign}{int(hours)}"  # Convert to "UTC+X" format
    return "UTC"  # Default if not found

def parse_vpn_user_log(files):
    data = []
    timezone = extract_timezone(files)

    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                log_entry = {}
                parts = line.strip().split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split("=", 1)
                        log_entry[key] = value.strip('"')  

                if 'user' in log_entry and 'remip' in log_entry and 'time' in log_entry:
                    data.append(log_entry)

    df = pd.DataFrame(data)
    if df.empty:
        print("No valid VPN user event logs found! Check log format.")
        return df, pd.DataFrame()

    df['Tunnel ID'] = pd.to_numeric(df.get('tunnelid', pd.NA), errors='coerce')

    time_col = f'Login Time ({timezone})'
    df[time_col] = df['date'] + " " + df['time']
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')

    df_filtered = df[df['action'].isin(['ssl-login-fail', 'tunnel-up'])].copy()

    df_filtered.rename(columns={
        'user': 'User',
        'remip': 'Remote IP',
        'action': 'Action',
        'reason': 'Reason'
    }, inplace=True)

    detailed_output = df_filtered[[time_col, 'Tunnel ID', 'User', 'Remote IP', 'Action', 'Reason']]

    summary_output = df_filtered.groupby(['Remote IP']).agg(
        Total_Failures=('Action', lambda x: (x == 'ssl-login-fail').sum()),
        Total_Success=('Action', lambda x: (x == 'tunnel-up').sum())
    ).reset_index()

    df_failed_logins = df_filtered[df_filtered['Action'] == 'ssl-login-fail'].copy()
    earliest_fails = df_failed_logins.groupby('Remote IP')[time_col].min().reset_index().rename(columns={time_col: 'Earliest_Fail'})
    latest_fails = df_failed_logins.groupby('Remote IP')[time_col].max().reset_index().rename(columns={time_col: 'Latest_Fail'})

    summary_output = summary_output.merge(earliest_fails, on='Remote IP', how='left')
    summary_output = summary_output.merge(latest_fails, on='Remote IP', how='left')

    return detailed_output, summary_output

def parse_forward_traffic_log(files):
    import numpy as np  # Just in case

    data = []
    timezone = extract_timezone(files)

    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                log_entry = {}
                parts = line.strip().split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split("=", 1)
                        log_entry[key] = value.strip('"') 

                if 'sessionid' in log_entry and 'srcip' in log_entry and 'dstip' in log_entry:
                    data.append(log_entry)

    df = pd.DataFrame(data)
    if df.empty:
        print("No valid traffic logs found! Check log format.")
        return df, pd.DataFrame()

    # Basic numeric conversions
    df['Session ID'] = pd.to_numeric(df['sessionid'], errors='coerce')
    df['Source Port'] = pd.to_numeric(df['srcport'], errors='coerce')
    df['Destination Port'] = pd.to_numeric(df['dstport'], errors='coerce')
    df['Protocol'] = pd.to_numeric(df['proto'], errors='coerce')
    df['Bytes Sent'] = pd.to_numeric(df.get('sentbyte', pd.NA), errors='coerce')
    df['Bytes Received'] = pd.to_numeric(df.get('rcvdbyte', pd.NA), errors='coerce')
    df['Duration (s)'] = pd.to_numeric(df.get('duration', pd.NA), errors='coerce')

    df[f'Start Time ({timezone})'] = df['date'] + " " + df['time']
    df[f'Start Time ({timezone})'] = pd.to_datetime(df[f'Start Time ({timezone})'], errors='coerce')

    df = df.sort_values(by=['Session ID', 'Source Port', f'Start Time ({timezone})'])

    # Cumulative max to get highest value per session group
    group_cols = ['Session ID', 'Source Port', 'Destination Port', 'srcip', 'dstip', 'Protocol']
    df['Bytes Sent'] = df.groupby(group_cols)['Bytes Sent'].cummax()
    df['Bytes Received'] = df.groupby(group_cols)['Bytes Received'].cummax()

    # Differences
    df['Sent Diff'] = df.groupby(group_cols)['Bytes Sent'].diff().fillna(0)
    df['Received Diff'] = df.groupby(group_cols)['Bytes Received'].diff().fillna(0)
    df['Sent Diff'] = df['Sent Diff'].clip(lower=0)
    df['Received Diff'] = df['Received Diff'].clip(lower=0)

    # MB conversions
    df['Sent Diff (MB)'] = df['Sent Diff'] / (1024 * 1024)
    df['Received Diff (MB)'] = df['Received Diff'] / (1024 * 1024)

    # Throughput (Bytes per second and Mbps)
    df['Bytes Sent/sec'] = df['Bytes Sent'] / df['Duration (s)']
    df['Bytes Received/sec'] = df['Bytes Received'] / df['Duration (s)']
    df['Throughput Sent (Mbps)'] = (df['Bytes Sent/sec'] * 8) / 1_000_000
    df['Throughput Received (Mbps)'] = (df['Bytes Received/sec'] * 8) / 1_000_000

    # Categorize session durations
    def categorize_duration(seconds):
        if pd.isna(seconds):
            return 'Unknown'
        elif seconds < 10:
            return 'Very Short (<10s)'
        elif seconds < 60:
            return 'Short (<1m)'
        elif seconds < 300:
            return 'Medium (<5m)'
        elif seconds < 1800:
            return 'Long (<30m)'
        else:
            return 'Very Long (>30m)'

    df['Session Length Category'] = df['Duration (s)'].apply(categorize_duration)

    # Session summary
    session_summary = df.groupby(group_cols).agg({
        f'Start Time ({timezone})': 'first',
        'Duration (s)': 'max',
        'Sent Diff': 'sum',
        'Received Diff': 'sum',
        'Sent Diff (MB)': 'sum',
        'Received Diff (MB)': 'sum',
        'Throughput Sent (Mbps)': 'mean',
        'Throughput Received (Mbps)': 'mean',
        'Session Length Category': 'first'
    }).reset_index()

    session_summary.rename(columns={
        'srcip': 'Source IP',
        'dstip': 'Destination IP',
        'Sent Diff': 'Total Bytes Sent',
        'Received Diff': 'Total Bytes Received',
        'Sent Diff (MB)': 'Total Sent (MB)',
        'Received Diff (MB)': 'Total Received (MB)',
        'Duration (s)': 'Duration (s)'
    }, inplace=True)

    detailed_output = session_summary[[f'Start Time ({timezone})', 'Session ID', 'Source IP', 'Destination IP', 'Source Port',
                                       'Destination Port', 'Protocol', 'Duration (s)', 'Total Bytes Sent', 'Total Sent (MB)',
                                       'Total Bytes Received', 'Total Received (MB)', 'Throughput Sent (Mbps)',
                                       'Throughput Received (Mbps)', 'Session Length Category']]

    summary_output = detailed_output.groupby(['Source IP', 'Destination IP']).agg({
        'Total Sent (MB)': 'sum',
        'Total Received (MB)': 'sum'
    }).reset_index()

    return detailed_output, summary_output

def main():
    parser = argparse.ArgumentParser(description="Fortinet Log Parser Tool")
    parser.add_argument('-t', '--type', choices=['forward_traffic', 'vpn_event'], required=True, help="Type of log file to process")
    parser.add_argument('-d', '--directory', required=False, help="Directory containing log files")
    parser.add_argument('-f', '--file', required=False, help="Single log file to process")
    parser.add_argument('-o', '--output', required=False, help="Output directory for the parsed XLSX file")

    args = parser.parse_args()

    log_type = args.type
    log_files = [args.file] if args.file else glob(os.path.join(args.directory, "*.log"))

    output_path = args.output if args.output else os.getcwd()

    output_file = os.path.join(output_path, f"{log_type}_output.xlsx")

    detailed_df, summary_df = parse_forward_traffic_log(log_files) if log_type == 'forward_traffic' else parse_vpn_user_log(log_files)

    with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
        detailed_df.to_excel(writer, sheet_name="Detailed Output", index=False)
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

    print(f"Parsed log saved to {output_file}")

if __name__ == "__main__":
    main()
