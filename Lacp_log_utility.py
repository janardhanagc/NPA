import os
import sys
import logging as log


def filter_analysis(file, rule):
    LACP_indices = list()
    with open(file) as f:
        lines = f.readlines()
    for line_no in range(len(lines)):
        if lines[line_no] == "DEBUG - LACP indices are\n":
            indices = lines[line_no+1][:-1].strip("[]")
            LACP_indices = list(map(int, indices.split(', ')))

    if len(rule) == 3:
        start = LACP_indices[LACP_indices.index(rule[0])-rule[1]]
        if start not in LACP_indices:
            start = 0
        end = LACP_indices[LACP_indices.index(rule[0])+rule[2]]
        if end not in LACP_indices:
            end = LACP_indices[-1]

    elif len(rule) == 2:
        start = rule[0]
        end = rule[1]

    new_lines = list()
    written = False
    line_no = 0
    while line_no < len(lines):
        if lines[line_no][:-1] == "DEBUG - Analysis of pkt #"+str(start)+" starts here":
            while lines[line_no][:-1] != "DEBUG - Analysis of pkt #"+str(end)+" ends here":
                new_lines.append(lines[line_no])
                line_no = line_no +1
            new_lines.append(lines[line_no])
            written = True
        if written == True:
            break
        line_no = line_no + 1
    file = file[:-1]
    path = file[:file.rfind('/')+1]
    file_name = file[file.rfind('/')+1:file.rfind('.')]
    output_file_name = file_name + "_filter_"+str(start)+"_to_"+str(end)+".log"
    print('New filtered analysis is stored in ',path,output_file_name,sep='')
    f = open(path+output_file_name, "w")
    f.writelines(new_lines)
    f.close()


file = sys.argv[1]
job = sys.argv[2]
rule = sys.argv[3]
print('rule is ', rule)
if job == 'filter':
    rule = rule[1:-1]
    if rule.count(',') == 1:
        start = int(rule[:rule.find(',')])
        end = int(rule[rule.find(',')+1:])
        filter_analysis(file,[start,end])

    elif rule.count(',') == 2:
        index = int(rule[:rule.find(',')])
        prev = int(rule[rule.find(',')+1:rule.rfind(',')])
        next = int(rule[rule.rfind(',')+1:])
        filter_analysis(file,[index, prev, next])
