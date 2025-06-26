import pandas as pd
import os
import argparse
from glob import glob
import sys
import re
import chardet
import shutil

def detect_file_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read(4096)
    result = chardet.detect(raw_data)
    return result['encoding']

def convert_to_utf8(src_file):
    encoding = detect_file_encoding(src_file)
    utf8_file = src_file + ".utf8"
    with open(src_file, 'r', encoding=encoding, errors='ignore') as f_in:
        content = f_in.read()
    with open(utf8_file, 'w', encoding='utf-8') as f_out:
        f_out.write(content)
    return utf8_file

def ensure_utf8_files(file_list):
    utf8_files = []
    for f in file_list:
        print(f"Converting {f} to UTF-8...")
        utf8_path = convert_to_utf8(f)
        utf8_files.append(utf8_path)
    return utf8_files

def extract_timezone(files):
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split()
                for part in parts:  
                    if part.startswith('tz='):
                        raw_tz = part.split('=')[1].strip('"')
                        match = re.match(r"([+-])(\d{2})00", raw_tz)
                        if match:
                            sign, hours = match.groups()
                            return f"UTC{sign}{int(hours)}"
    return "UTC"

def deduplicate_files(files):
    unique_lines = set()
    # Place .tmp file next to the log files
    temp_file_dir = os.path.dirname(files[0]) if files else os.getcwd()
    temp_file = os.path.join(temp_file_dir, "deduplicated_logs.tmp")

    with open(temp_file, "w", encoding="utf-8") as output:
        for file_path in files:
            with open(file_path, "r", encoding="utf-8") as file:
                for line in file:
                    if line not in unique_lines:
                        unique_lines.add(line)
                        output.write(line)
    return temp_file

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
    df[time_col] = pd.to_datetime(df['date'] + " " + df['time'], errors='coerce')
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

def normalize_service(port, protocol):
    common_services = {
        80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 25: 'SMTP', 22: 'SSH', 21: 'FTP',
        110: 'POP3', 143: 'IMAP', 3306: 'MySQL', 3389: 'RDP', 1521: 'Oracle DB',
        500: 'IPSec', 123: 'NTP', 5060: 'SIP', 1723: 'PPTP'
    }
    try:
        port = int(port)
    except (ValueError, TypeError):
        return 'unknown'
    return common_services.get(port, 'unknown')

def process_forward_chunk(df, timezone):
    df['Session ID'] = pd.to_numeric(df['sessionid'], errors='coerce')
    df['Source Port'] = pd.to_numeric(df['srcport'], errors='coerce')
    df['Destination Port'] = pd.to_numeric(df['dstport'], errors='coerce')
    df['Protocol'] = pd.to_numeric(df['proto'], errors='coerce')
    df['Bytes Sent'] = pd.to_numeric(df.get('sentbyte', pd.NA), errors='coerce')
    df['Bytes Received'] = pd.to_numeric(df.get('rcvdbyte', pd.NA), errors='coerce')
    df['Duration (s)'] = pd.to_numeric(df.get('duration', pd.NA), errors='coerce')
    df[f'Log Time ({timezone})'] = pd.to_datetime(df['date'] + " " + df['time'], errors='coerce')
    df.sort_values(by=f'Log Time ({timezone})', inplace=True)
    group_cols = ['Session ID', 'srcip', 'dstip', 'Source Port', 'Destination Port', 'Protocol']
    session_summary = df.groupby(group_cols).tail(1).reset_index(drop=True)
    session_summary.rename(columns={
        'srcip': 'Source IP',
        'dstip': 'Destination IP',
        'service': 'Service',
        'Bytes Sent': 'Total Bytes Sent',
        'Bytes Received': 'Total Bytes Received'
    }, inplace=True)
    return session_summary

def parse_forward_traffic_log(files):
    timezone = extract_timezone(files)
    chunk_size = 500000  # Larger chunk size for fewer DataFrames
    all_buffers = []

    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            buffer = []
            for line in file:
                log_entry = {}
                parts = line.strip().split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split("=", 1)
                        log_entry[key] = value.strip('"')
                if 'sessionid' in log_entry and 'srcip' in log_entry and 'dstip' in log_entry:
                    log_entry['service'] = log_entry.get('service', 'unknown')
                    buffer.append(log_entry)
                if len(buffer) >= chunk_size:
                    df_chunk = pd.DataFrame(buffer)
                    all_buffers.append(df_chunk)
                    buffer.clear()
            # Process remaining lines
            if buffer:
                df_chunk = pd.DataFrame(buffer)
                all_buffers.append(df_chunk)

    # Combine all chunks into one big DataFrame
    full_df = pd.concat(all_buffers, ignore_index=True)

    # Do all numeric and time conversions once globally
    full_df['Session ID'] = pd.to_numeric(full_df['sessionid'], errors='coerce')
    full_df['Source Port'] = pd.to_numeric(full_df['srcport'], errors='coerce')
    full_df['Destination Port'] = pd.to_numeric(full_df['dstport'], errors='coerce')
    full_df['Protocol'] = pd.to_numeric(full_df['proto'], errors='coerce')
    full_df['Bytes Sent'] = pd.to_numeric(full_df.get('sentbyte', pd.NA), errors='coerce')
    full_df['Bytes Received'] = pd.to_numeric(full_df.get('rcvdbyte', pd.NA), errors='coerce')
    full_df['Duration (s)'] = pd.to_numeric(full_df.get('duration', pd.NA), errors='coerce')
    full_df[f'Log Time ({timezone})'] = pd.to_datetime(full_df['date'] + " " + full_df['time'], errors='coerce')

    # Sort all logs by time before grouping
    full_df.sort_values(by=f'Log Time ({timezone})', inplace=True)

    # Global groupby to keep only the latest log line for each session
    group_cols = ['Session ID', 'srcip', 'dstip', 'Source Port', 'Destination Port', 'Protocol']
    session_summary = full_df.groupby(group_cols).tail(1).reset_index(drop=True)

    # Rename columns for consistency
    session_summary.rename(columns={
        'srcip': 'Source IP',
        'dstip': 'Destination IP',
        'service': 'Service',
        'Bytes Sent': 'Total Bytes Sent',
        'Bytes Received': 'Total Bytes Received'
    }, inplace=True)

    # Build detailed output
    detailed_output = session_summary[[f'Log Time ({timezone})', 'Session ID', 'Source IP', 'Destination IP',
                                       'Source Port', 'Destination Port', 'Protocol', 'Service',
                                       'Duration (s)', 'Total Bytes Sent', 'Total Bytes Received']]

    # Build summary output (aggregate bytes + session counts per source-dest-service)
    summary_output = detailed_output.groupby(['Source IP', 'Destination IP', 'Service']).agg({
        'Total Bytes Sent': 'sum',
        'Total Bytes Received': 'sum',
        'Session ID': 'count'
    }).reset_index().rename(columns={'Session ID': 'Total Sessions'})

    # Add First and Last Log Time per group
    first_logs = detailed_output.groupby(['Source IP', 'Destination IP', 'Service'])[f'Log Time ({timezone})'].min().reset_index().rename(columns={f'Log Time ({timezone})': 'First Log Time'})
    last_logs = detailed_output.groupby(['Source IP', 'Destination IP', 'Service'])[f'Log Time ({timezone})'].max().reset_index().rename(columns={f'Log Time ({timezone})': 'Last Log Time'})

    # Merge into summary
    summary_output = summary_output.merge(first_logs, on=['Source IP', 'Destination IP', 'Service'], how='left')
    summary_output = summary_output.merge(last_logs, on=['Source IP', 'Destination IP', 'Service'], how='left')

    return detailed_output, summary_output


def main():
    parser = argparse.ArgumentParser(description="Fortinet Log Parser Tool")
    parser.add_argument('-t', '--type', choices=['forward_traffic', 'vpn_event'], required=True, help="Type of log file to process")
    parser.add_argument('-d', '--directory', required=False, help="Directory containing log files")
    parser.add_argument('-f', '--file', required=False, help="Single log file to process")
    parser.add_argument('-o', '--output', required=False, help="Output directory for the parsed CSV files")
    parser.add_argument('--dedup', action='store_true', help="Enable deduplication of log lines across files")
    args = parser.parse_args()

    # Get input files
    original_files = [args.file] if args.file else glob(os.path.join(args.directory, "*.log"))

    # Convert to UTF-8 and track created utf8 files
    utf8_files = ensure_utf8_files(original_files)
    log_files = utf8_files.copy()

    # Handle deduplication
    deduplicated_file = None
    if args.dedup:
        print("Deduplication enabled. Processing unique log lines only.")
        deduplicated_file = deduplicate_files(log_files)
        log_files = [deduplicated_file]

    # Parse logs based on type
    if args.type == 'forward_traffic':
        detailed_df, summary_df = parse_forward_traffic_log(log_files)
    else:
        detailed_df, summary_df = parse_vpn_user_log(log_files)

    # Output directory
    output_path = args.output if args.output else os.getcwd()
    os.makedirs(output_path, exist_ok=True)

    # Save detailed and summary CSVs
    detailed_file = os.path.join(output_path, f"{args.type}_detailed.csv")
    summary_file = os.path.join(output_path, f"{args.type}_summary.csv")
    detailed_df.to_csv(detailed_file, index=False)
    summary_df.to_csv(summary_file, index=False)

    print(f"Detailed log saved to {detailed_file}")
    print(f"Summary log saved to {summary_file}")

    # Cleanup temporary UTF-8 files
    for f in utf8_files:
        if os.path.exists(f):
            os.remove(f)

    # Cleanup deduplication .tmp file
    if args.dedup and deduplicated_file and os.path.exists(deduplicated_file):
        os.remove(deduplicated_file)



if __name__ == "__main__":
    main()
