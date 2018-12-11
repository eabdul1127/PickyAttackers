import argparse
import sys
import json
import os
import operator
import datetime
from dateutil import parser
from Session import Session
from Parser import *

last_cmds = {}  # Grouped + ungrouped divergences
ip_to_divergent_commands = {}
ss_cmds = {}  # Unique suspiciously short session commands, actual sessions generated in function
ss_sessions = set()
normalized_ss_cmds = {}
interesting_sessions = set()  # Unique sessions that meet the 'interesting' criteria
unique_ss_session_list = []
total_ss_session_list = []

## Logs information about the various logs to STDOUT
def log_statistics(attacker_stats):
    ### Unique attackers
    print('Unique Attackers: ' + str(len(attacker_stats.keys())))

    ### Multi Machine attackers
    ip_count, ip_list = log_multi_machine_attacker_ips(attacker_stats)
    print('Multi Machine Attackers: ' + str(ip_count))

    ### Total Session Count
    total_session_count = sum_attacker_sessions(attacker_stats)
    print('Total number of sessions: ' + str(total_session_count))


    attacker_stats = suspiciously_short(attacker_stats)
    ### Suspiciously short session count
    print('Unique suspiciously short sessions: ' + str(len(unique_ss_session_list)))
    print('Total suspiciously short sessions: ' + str(len(total_ss_session_list)))

    ### Suspiciously short session contents
    
    with open('suspiciously_short_sessions.txt', 'w+') as outfile:
        json.dump(list(ss_sessions), outfile, indent=2, separators=(',', ': '))
    print('Suspciciously short sessions >>> suspiciously_short_sessions.txt')
    
    ### Normalized suspiciosly short command counts
    with open('normalized_suspiciously_short_command_list.txt', 'w+') as outfile:
        normalized_ss_cmd_list= []
        for cmd in normalized_ss_cmds.keys():
            normalized_ss_cmd_list.append((cmd, normalized_ss_cmds[cmd]))
        normalized_ss_cmd_list.sort(key = operator.itemgetter(1), reverse=True)
        normalized_ss_cmd_list = map(lambda x: str(x[0]) + ',' + str(x[1]), normalized_ss_cmd_list)
        json.dump(list(normalized_ss_cmd_list), outfile, indent=2, separators=(',', ': '))
        
    print('Normalized Suspciciously short commands >>> normalized_suspiciously_short_command_list.txt')

    ### Divergent Commands
    with open('divergent_commands.txt', 'w+') as outfile:
        attacker_stats = differing_command_count(attacker_stats)
        last_cmd_list = []
        for ip in ip_to_divergent_commands.keys():
            num_sessions = sum(ip_to_divergent_commands[ip].values())
            for cmd in ip_to_divergent_commands[ip].keys():
                if last_cmds.get(cmd) is None:
                    last_cmds[cmd] = 0
                last_cmds[cmd] = last_cmds[cmd] + (ip_to_divergent_commands[ip][cmd]/num_sessions)
        entry_list = []
        for cmd in last_cmds.keys():
            last_cmd_list.append((cmd, last_cmds[cmd]))
        last_cmd_list.sort(key=operator.itemgetter(1), reverse=True)
        for cmd in last_cmd_list:
            entry_list.append(f'{cmd[0]},{cmd[1]}')

        all_entries_str = '\n'.join(entry_list)
        outfile.write(all_entries_str)
    print('Divergent commands >>> divergent_commands.txt')

    ### Past filter algorithm
    print('Unique Sessions that made it past filter algorithm: ' + str(len(interesting_sessions)))

    ### Need Mongo
    print('For count of sessions with differences Import logs into mongodb and query documents with non empty diffs array')
    print('For total sessions that made it past algorithm filter, import logs into mongodb and query documents with prefix_sym > 0 for all sesions')
    
    ### Session data
    with open('Attacker_logs.json', 'w+') as outfile:
        json.dump(attackerstats, outfile, indent=2, separators=(',', ': '))
        print('Parsed attaacker logs >>>  Attacker_logs.json')


# Extension Methods: Mutate the json to add extra staistics that result from
# further calculations on the data already contained

# Annotates the logs to denote how many unique machines each attacker has visited.
# Returns the number of attackers that have visited more than one
def log_multi_machine_attacker_ips(attacker_stats):
    multi_machine_attacker_count = 0
    multi_machine_attacer_list = []
    for ip in attacker_stats.keys():
        if len(attacker_stats[ip]["Session_Data"]) > 1:
            multi_machine_attacer_list.append(ip)
            multi_machine_attacker_count += 1
        attacker_stats[ip]["Unique Honeypots"] = len(
            attacker_stats[ip]["Session_Data"])
    return multi_machine_attacker_count, multi_machine_attacer_list
    # return attacker_stats

# Annotates the logs to denote how many sessions were done by each attacker in total
# Returns total number of sessions accross all attackers
def sum_attacker_sessions(attacker_stats):
    attacker_session_counts = {}
    session_list = []
    for ip in attacker_stats.keys():
        honeypot_sessions = attacker_stats[ip]["Session_Data"]
        session_count = 0
        for sensor in honeypot_sessions.keys():
            session_count += len(honeypot_sessions[sensor].keys())
            session_list += (list(honeypot_sessions[sensor].keys()))
        attacker_stats[ip]["Session Count"] = session_count
        attacker_session_counts[ip] = session_count
    return sum(attacker_session_counts.values())

# Annotates the logs to denote how many sessions were 'suspiciously short'
# returns mutated logs
def suspiciously_short(attacker_stats):
    session_strings = set()
    for ip in attacker_stats:
        most_executed = {}
        sensors = attacker_stats[ip]["Session_Data"]
        for sensor in sensors:
            sessions = sensors[sensor]
            if len(sessions) == 1: # what its supposed to be
                session = list(sessions.values())[0]
                if len(session) <= 3:
                    sensors[sensor]["suspiciously_short"] = True
                    cmd_list = []
                    for command in session:
                        cmd = command['Command']
                        cmd_list.append(cmd)
                        if ss_cmds.get(cmd) is not None:
                            ss_cmds[cmd] = ss_cmds[cmd] + 1
                        else:
                            ss_cmds[cmd] = 1
                        if most_executed.get(cmd) is not None:
                            most_executed[cmd] = most_executed[cmd] + 1
                        else:
                            most_executed[cmd] = 1

                    old_len = len(ss_sessions)
                    session_str = ','.join(cmd_list)
                    ss_sessions.add(session_str)
                    if len(ss_sessions) != old_len:
                        unique_ss_session_list.append((session, sensor))
                    total_ss_session_list.append((session, sensor))
        most_executed_list = []
        for cmd in most_executed.keys():
            most_executed_list.append((cmd, ss_cmds[cmd]))
        most_executed_list.sort(key = operator.itemgetter(1), reverse=True)
        cmds_to_add = len(most_executed_list) if len(most_executed_list) <= 3 else 3
        for i in range(cmds_to_add):
            cmd = most_executed_list[i][0]
            if normalized_ss_cmds.get(cmd) is not None:
                normalized_ss_cmds[cmd] = normalized_ss_cmds[cmd] + 1
            else:
                normalized_ss_cmds[cmd] = 1
    return attacker_stats

# Compares every unique pair of sessions among each other for a given attacker and returns the results for various comparison metrics
# Returns list of comparisons
def compare_sensor_commands(session_commands, ip):
    session_diff_list = []
    visited = set()
    for session_1 in session_commands.keys():
        for session_2 in session_commands.keys():
            if session_1 == session_2 or session_2 in visited:
                continue

            session_commands_1 = session_commands[session_1]
            session_commands_2 = session_commands[session_2]
            session_diffs = {"SessionI": session_1, "SessionJ": session_2}
            # Symmetric Difference
            sym_diff_length = len(
                sym_diff(session_commands_1, session_commands_2))
            session_diffs["Symmetric"] = sym_diff_length
            # Jaccard Similarity
            jac_diff = jaccard_similarity(session_commands_1, session_commands_2)
            session_diffs["Jaccard"] = jac_diff
            # Commands out of sequence
            commands_out_of_sequence = out_of_sequence(
                session_commands_1, session_commands_2)
            session_diffs["Sequence"] = commands_out_of_sequence
            # Length of shared pref// length of shorter session
            shared_prefix_length = len_of_shared_prefix(
                session_commands_1, session_commands_2)
            session_diffs["Prefix"] = shared_prefix_length
            # Prefix with first word counting true
            shared_prefix_length_first_word = len_of_shared_prefix_first_word(
                session_commands_1, session_commands_2)
            session_diffs["FirstWordPrefix"] = shared_prefix_length_first_word
            # Symmetric difference of different commands
            shared_prefix_sym = prefix_sym(
                session_commands_1, session_commands_2)
            session_diffs["Prefix_Sym"] = shared_prefix_sym

            if shared_prefix_sym > 0: 
                add_normalized_attacker_commands(session_commands_1, session_commands_2, ip)
            # Symmetric difference of different commands first word true
            shared_prefix_length_first_word_sym = prefix_sym_first_word(
                session_commands_1, session_commands_2)
            session_diffs["FirstWordPrefix_Sym"] = shared_prefix_length_first_word_sym
            if shared_prefix_length == 1 and commands_out_of_sequence == 0:
                continue

            session_diff_list.append(session_diffs)

            visited.add(session_1)
    return session_diff_list

def add_normalized_attacker_commands(sensor_1, sensor_2, ip): 
    if sensor_1 != sensor_2:
        shorter_command_list_len = min(len(sensor_1), len(sensor_2))
        prefix_size = int(len_of_shared_prefix(
            sensor_1, sensor_2) * shorter_command_list_len)

        last_cmd = sensor_1[prefix_size-1]
        if ip_to_divergent_commands.get(ip) is None:
            ip_to_divergent_commands[ip] = {}
        if ip_to_divergent_commands[ip].get(last_cmd) is not None:
            ip_to_divergent_commands[ip][last_cmd] = ip_to_divergent_commands[ip][last_cmd] + 1
        else:
            ip_to_divergent_commands[ip][last_cmd] = 1

# Populates a set of relational differences between an attackers given set of sessions based on various metrics
# Ex. Jaccard Similarity, Symmetric difference, Length of common prefix, Common prefix where the command is determined by its first word

def differing_command_count(attacker_stats):
    for ip in attacker_stats.keys():
        attacker_stats[ip]["Similarities"] = []
        sensor_to_commands = {}
        sensor_stats = attacker_stats[ip]["Session_Data"]
        for sensor in sensor_stats.keys():
            session_stats = sensor_stats[sensor]
            sensor_to_commands[sensor] = concat_sessions(session_stats)
        if attacker_stats[ip].get("Similarities"):
            del attacker_stats[ip]["Similarities"]
        sensor_diffs = compare_sensor_commands(sensor_to_commands, ip)
        if sensor_diffs:
            attacker_stats[ip]["Similarities"] = sensor_diffs
        else:
            del attacker_stats[ip]["Similarities"]
    return attacker_stats

# Concattonates sessions by the same attacker on the same machine together into a single master session
def concat_sessions(sessions):
    session_commands = []
    session_set = set()
    # Order Sessions By visit date
    for session in sessions.keys():
        if session == 'suspiciously_short':
            continue
        session_obj = Session(sessions[session])
        session_set.add(session_obj)
    session_list = list(map(lambda x: (x, parser.parse(
        x.commands[0]["Timestamp"])), list(session_set)))
    session_list.sort(key=operator.itemgetter(1))
    for session_obj_tuple in session_list:
        session_tuple = (session_obj_tuple[0].commands, session_obj_tuple[1])
        session_commands += [x["Command"] for x in session_tuple[0]]
    return session_commands

# Returns the symmetric difference of two sets of commands
def sym_diff(session_1, session_2):
    i_commands = set(session_1)
    j_commands = set(session_2)
    return (i_commands.symmetric_difference(j_commands))

# Returns the jaccard similarity of two sets of commands
def jaccard_similarity(session_1, session_2):
    i_commands = set(session_1)
    j_commands = set(session_2)
    return len(i_commands.intersection(j_commands)) / len(i_commands.union(j_commands))

# Returns the number of commands out of sequnce of two lists of commands
def out_of_sequence(session_1, session_2):
    shorter_command_list = min(len(session_1), len(session_2))
    diff_length = abs(len(session_1) - len(session_2))
    for index in range(shorter_command_list):
        if session_1[index] != session_2[index]:
            diff_length += 1
    return diff_length

# Returns the number of length of the shared prefix of commands for two lists of commands(session)
def len_of_shared_prefix(session_1, session_2):
    shorter_command_list_len = min(len(session_1), len(session_2))
    shared_prefix_len = 0
    identical_commands = True
    for index in range(shorter_command_list_len):
        if session_1[index] != session_2[index]:
            shared_prefix_len = index
            identical_commands = False
            break
    if identical_commands:
        shared_prefix_len = shorter_command_list_len
    return shared_prefix_len/shorter_command_list_len

# Returns the number of length of the shared prefix of commands for two lists of commands(session)
# Counts the commands with the same first word as the same command
def len_of_shared_prefix_first_word(session_1, session_2):
    shorter_command_list_len = min(len(session_1), len(session_2))
    shared_prefix_len = 0
    identical_commands = True
    for index in range(shorter_command_list_len):
        if not compare_first_word(session_1[index], session_2[index]):
            shared_prefix_len = index
            identical_commands = False
            break
    if identical_commands:
        shared_prefix_len = shorter_command_list_len
    return shared_prefix_len/shorter_command_list_len

# Custom algorithm filter
# If the length of the shared prefix of commands is greater than 2 and then 
# it returns the size of the symettric difference of commands after and including the first difference
# Else it returns -1
# Also keeps track of sessions that meet this criteria for future log work
def prefix_sym(session_1, session_2):
    shorter_command_list_len = min(len(session_1), len(session_2))
    prefix_size = int(len_of_shared_prefix(
        session_1, session_2) * shorter_command_list_len)
    last_cmd = session_1[prefix_size-1]

    if prefix_size > 2:
        sensor1_str = ''.join(session_1)
        sensor2_str = ''.join(session_2)
        interesting_sessions.add(sensor1_str)
        interesting_sessions.add(sensor2_str)
        post_session_1 = session_1[prefix_size:]
        post_session_2 = session_2[prefix_size:]
        if session_1 != session_2:
            if last_cmds.get(last_cmd) is not None:
                last_cmds[last_cmd] = last_cmds[last_cmd] + 1
            else:
                last_cmds[last_cmd] = 1
        return len(sym_diff(post_session_1, post_session_2))
    return -1

# Custom algorithm filter
# If the length of the shared prefix of commands is greater than 2 and then 
# it returns the size of the symettric difference of commands after and including the first difference
# Else it returns -1
# Counts the commands with the same first word as the same command
def prefix_sym_first_word(session_1, session_2):
    shorter_command_list_len = min(len(session_1), len(session_2))
    prefix_size = int(len_of_shared_prefix_first_word(
        session_1, session_2) * shorter_command_list_len)
    if prefix_size > 2:
        post_session_1 = session_1[prefix_size:]
        post_session_2 = session_2[prefix_size:]
        return len(sym_diff(post_session_1, post_session_2))
    return -1

# Returns true if the two strings have the same first word
def compare_first_word(cmd1, cmd2):
    cmd1_first_word = cmd1.split()[0]
    cmd2_first_word = cmd2.split()[0]
    return cmd1_first_word == cmd2_first_word

# Reorganizes logs to have attackers grouped by region + fingerprint instead of by ip
def reorganizeByCountry(attacker_stats):
    regrouped_stats = {}
    for ip in attacker_stats:
        location_id = ip
        if attacker_stats[ip]['Metadata']['Country']  != 'N/A':
            location_id = attacker_stats[ip]['Metadata']['Country']
        if attacker_stats[ip]['Metadata']['City'] != 'N/A':
            location_id = attacker_stats[ip]['Metadata']['City']

        new_key = str(location_id) + '_' + \
            str(attacker_stats[ip]["Metadata"]["Version"])
        merge_stats(regrouped_stats, attacker_stats[ip], new_key, ip)
    return regrouped_stats


def merge_stats(regrouped_stats, ip_stats, new_key, ip):
    if regrouped_stats.get(new_key) is None:
        regrouped_stats[new_key] = ip_stats
    else:
        merge_attackers(
            regrouped_stats[new_key]['Session_Data'], ip_stats['Session_Data'])
    if not regrouped_stats[new_key]['Metadata'].get('ips'):
        regrouped_stats[new_key]['Metadata']['ips'] = []
    regrouped_stats[new_key]['Metadata']['ips'].append(ip)


def merge_attackers(to_attacker, from_attacker):
    for sensor in from_attacker.keys():
        if to_attacker.get(sensor) is None:
            to_attacker[sensor] = from_attacker[sensor]
        else:
            sensor_obj = from_attacker[sensor]
            for session in sensor_obj.keys():
                to_attacker[sensor][session] = from_attacker[sensor][session]


if __name__ == "__main__":
    attackerstats = parse_json_logs(sys.argv[1])
    attackerstats = reorganizeByCountry(attackerstats) # Comment to group attackers by ip instead of region/fingerprint
    log_statistics(attackerstats)
