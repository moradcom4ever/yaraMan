#!/usr/bin/env python3
import argparse
from array import *
import os
import os.path
import platform
from datetime import date
from os import listdir
from os.path import isfile, join

# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
ap.add_argument("-i", dest="input_file", help="IOC file to convert to Yara file", type=str)
ap.add_argument("-d", dest="directory", help="Path in which IOC file are exist", type=str)
args = ap.parse_args()
# check if options are not provided
if args.input_file is None and args.directory is None:
   ap.error("\n-----------------------------------------\nAt least one of \"-i\" or \"-d\" is required\n-----------------------------------------\n")
if args.input_file and args.directory:
   ap.error("\n-----------------------------------------\nChoose Only one of \"-i\" or \"-d\" options\n-----------------------------------------\n")

mk_dir = ""
rule_name = ""
rules_count = 0
ioc_path = ""
ioc_file = ""

# Check system and determine path char / or \
path_char = ""
if platform.system() == "Windows":
    path_char = "\\"
elif platform.system() == "Linux":
    path_char = "/"

current_path = os.path.dirname(__file__)
if args.directory:
    if (args.directory[-1] == "\\" or args.directory[-1] == "/"):
            args.directory = args.directory[:-1]
    if not os.path.exists("{}{}Converted_Yara".format(args.directory,path_char)):
        os.mkdir("{}{}Converted_Yara".format(args.directory,path_char))

print("---------------------------------------------------------")
print("")
print("                     yaraMan \n")
print("        Mandiant IOCe to Yara rule converter \n")
print("    Created by Morad Rawashdeh, May 2021, Version 1.0")
print("")
print("---------------------------------------------------------\n")

def run_script(file_name):
    ioc_file = file_name
    # check IOC file full path
    found = "false"
    for letter in ioc_file:
        if(letter == "\\" or letter == "/"): # if true, that means full directory is provided
            found = "true"
            break
    if found == "false": # if not in full path, use the current full path
        ioc_file = "{}{}{}".format(current_path,path_char,ioc_file)

    # Check if IOC file is exist
    real = os.path.isfile(ioc_file)
    if  real is False:
        print("IOC file not exist")
        quit()

    desc = ""
    condition = ""
    operator_value = ""
    strings_text = ""
    str_count = 1

    # Read IOC file line by line
    with open(ioc_file) as f:
        datafile = f.readlines()
        for i in range(len(datafile)):
            l = datafile[i]
            # find <short_description> and make it Yara rule name
            if "<short_description>" in l: 
                rule_name = l[l.find(">") + 1:l.find("</",l.find(">") + 1)]  # get the text inside quotations from operator section ((operator=""))
                rule_name = rule_name.replace(" ","_")
                rule_name = rule_name.replace("-","_")
                rule_name = rule_name.replace("(","")
                rule_name = rule_name.replace(")","")
            # find <description> and make it meta description inside yara file
            if "<description>" in l: 
                desc = l[l.find(">") + 1:l.find("</",l.find(">") + 1)]  # get the text inside quotations from operator section ((operator=""))
                desc = desc.replace("\\","\\\\")
                desc = desc.replace("\"","")
            # Get any line contains operator
            if "operator=\"" in l:
                operator_value = l[l.find("operator=\"") + 10:l.find("\"",l.find("operator=\"") + 10)]  # get the text inside quotations from operator section ((operator=""))
                operator_value = operator_value.lower()
                condition += "("
            # Get any line contains Context
            if "<Context" in l:
                search_value = l[l.find("search=\"") + 8:l.find("\"",l.find("search=\"") + 8)]  # get the text inside quotations from search section ((search=""))
                search_value = search_value.split("/")
                search_value = search_value[-1] # get the last element from the array
                l_next = datafile[i + 1]    # Go to the next line and get the value of content section
                if "<Content" in l_next:
                    content_value = l_next[l_next.find("\">") + 2:l_next.find("</",l_next.find("\">") + 2)]  # get the text inside content section ((<Content></Content>))
                    content_value = content_value.replace("\\","\\\\")
                    if "date" in l_next: # remove letter T and Z from date format
                        content_value = content_value.replace("T"," ")
                        content_value = content_value.replace("Z","")
                if search_value == 'Md5sum':
                    condition = condition + "hash.md5(0, filesize) == \"{}\" {}\n".format(content_value,operator_value)
                elif search_value == 'Sha256sum':
                    condition = condition + "hash.sha256(0, filesize) == \"{}\" {}\n".format(content_value,operator_value)
                elif search_value == 'Sha1sum':
                    condition = condition + "hash.sha1(0, filesize) == \"{}\" {}\n".format(content_value,operator_value)
                elif search_value == 'SizeInBytes':
                    condition = condition + "filesize == {} {}\n".format(content_value,operator_value)
                else:
                    strings_text += "$str{} = \"{}\"\n".format(str_count,content_value)
                    condition = condition + "$str{} {} ".format(str_count, operator_value)
                    str_count += 1
            # search for </Indicator> which means end of current operator
            if "</Indicator>" in l:
                condition = condition[:-4] # remove last operator from condition
                # filp the operator
                if operator_value == "or":
                    operator_value = "and"
                else:
                    operator_value = "or"
                condition = condition + ") {} ".format(operator_value)
    # remove last operator from condition
    condition = condition[:-4] 

    # delete first "(" and last ")" parantheses
    condition = condition.strip()
    condition = condition[1:-1]

    # colse opened file
    f.close()

    # Prepare Yara rule file
    ioc_path = os.path.dirname(ioc_file)
    yara_file = "{}{}Converted_Yara{}{}.yar".format(ioc_path, path_char , path_char, rule_name)
    f = open(yara_file,"w")
    f.write("import \"hash\"\n")
    f.write("rule " + rule_name + "{\n")
    f.write("\tmeta:\n")
    f.write("\t\tauthor = \"Morad Rawashdeh, NCSC\"\n")
    f.write("\t\tdate = \"{}\"\n".format(date.today().strftime("%d/%m/%Y")))
    f.write("\t\tdescription = \"{}\"\n".format(desc))
    f.write("\t\tversion = \"1.0\"\n")
    f.write("\t\treference = \"National Cyber Security Center, Jordan\"\n")
    f.write("\tstrings:\n")
    for l in strings_text.splitlines():
        f.write("\t\t{}\n".format(l))
    f.write("\tcondition:\n")
    for l in condition.splitlines():
        f.write("\t\t{}\n".format(l))
    f.write("}")

    print("")
    print("IOC file name :\t\t{}\n".format(ioc_file))
    print("Rule name :\t\t{}\n".format(rule_name))
    print("")


if args.input_file: # if options -i is provided
    rules_count = 1
    run_script(args.input_file)

if args.directory: # if options -d is provided
    all_files = ""
    for f in listdir(args.directory):
       if isfile(join(args.directory, f)):
           all_files += "{}{}{}\n".format(args.directory,path_char,f)
    for l in all_files.splitlines(): 
        # Check file extension
        extension = l.split(".")[-1]
        if extension != "ioc":
            continue
        run_script(l)
        rules_count+=1

# print output on console
print("")
print("---------------------------------------------------------")
print("")
print("Number of rules created: {}".format(rules_count))
print("")
print("---------------------------------------------------------")
print("")
print("Finished converting successfully")
print("File/s can be found inside \"Converted_Yara\" directory")
print("")
