

import json
import datetime
import os

def parse_json_logs(logs_dir):
    attacker_stats = {}
    for log in os.listdir(logs_dir):
        log_path = os.path.join(logs_dir, log)
        with open(log_path, 'r') as log_file:
            log_contents = log_file.readlines()
            attacker_stats = parse_json_log_file(log_contents, attacker_stats)
    return attacker_stats

def parse_json_log_file(logs, attacker_stats):
    parsed_logs = [json.loads(x.strip()) for x in logs]
    ip = parsed_logs[0]['peer_ip']
    session_id = parsed_logs[0]['session_id']
    proxy_ip = parsed_logs[0]['proxy_ip']
    country = parsed_logs[0]['country']
    city = 'N/A'
    if parsed_logs[0].get('city') is not None:
        city = parsed_logs[0]['city']
    version = parsed_logs[0]['version']
    action_logs = parsed_logs[1:]
    if attacker_stats.get(ip) is None:
        attacker_stats[ip] = {}
        attacker_stats[ip]["Session_Data"] = {}
        attacker_stats[ip]['Metadata'] = {
            'City' : city,
            'Country': country,
            'Version': version
        }
    this_attacker_log = attacker_stats[ip]["Session_Data"]
    if this_attacker_log.get(proxy_ip) is None:
        this_attacker_log[proxy_ip] = {}
    this_attacker_log[proxy_ip][session_id] = []
    for log in action_logs:
        if log['action'] == 'command':
            command = format_command(log)
            this_attacker_log[proxy_ip][session_id].append(command)
    return attacker_stats

def format_command(log):
    timestamp = format_time(log['timestamp'])
    outcome = log['outcome']
    command_string = log['command_string']
    command = {
        'Timestamp': timestamp,
        'Command': command_string,
        'Outcome': outcome
    }
    return command

def format_time(timestamp):
    yyyy = timestamp[0:4]
    MM =  timestamp[4:6]
    dd = timestamp[6:8]
    hh = timestamp[9:11]
    mm = timestamp[11:13]
    ss = timestamp[13:15]
    date_array = [yyyy, MM, dd, hh, mm, ss]
    date = datetime.datetime(*map(int, date_array))
    formatted_date = date.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_date
