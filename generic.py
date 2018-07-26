import csv
import re

## Retrieves all values from a selected column
def select_column(formatted_intel, column_index):
    col = []
    for row in formatted_intel:
        col.append(row[column_index])
    return col

## Generates a regular expression for trusted ip addresses
def trusted_ip_regex():
    ip_zepko = ["217\.41\.64\.92"]
    ip_reserved = ["0\.", "10\.", "100\.6[456789]\.","100\.[789][0-9]\.", "100\.1[01][0-9]\.", "100\.12[0-7]\.", "127\.", "169\.254\.", "172\.1[6789]\.", "172\.2[0-9]\.", "172\.3[01]\.", "192\.0\.0\.", "192\.0\.2\.", "192\.88\.99\.", "192\.168\.", "198\.1[89]\.", "198\.51\.100\.", "203\.0\.113\.", "22[456789]\.", "23[0-9]\.", "24[0-9]\.", "25[0-5]\."]
    ip_dns = ["209\.244\.0\.[34]", "64\.6\.6[45]\.6", "8\.8\.8\.8", "8\.8\.4\.4", "9\.9\.9\.9", "149\.112\.112\.112", "84\.200\.69\.80", "84\.200\.70\.40", "8\.26\.56\.26", "8\.20\.247\.20", "208\.67\.222\.222", "208\.67\.220\.220", "199\.85\.12[67]\.10", "81\.218\.119\.11", "209\.88\.198\.133", "195\.46\.39\.(39|40)", "69\.195\.152\.204", "23\.94\.60\.240", "208\.76\.50\.50", "208\.76\.51\.51", "216\.146\.35\.35", "216\.146\.36\.36", "37\.235\.1\.17[47]", "198\.101\.242\.72", "23\.253\.163\.53", "77\.88\.8\.[18]", "91\.239\.100\.100", "89\.233\.43\.71", "74\.82\.42\.42", "109\.69\.8\.51", "156\.154\.7[01]\.1", "1\.1\.1\.1", "1\.0\.0\.1", "45\.77\.165\.194", "185\.228\.16[89]\.9"]
    reg = ip_zepko + ip_reserved + ip_dns
    str = '|'.join(reg)
    return str

## Returns the indices of duplicates in a list
def find_dupes(ips_only_list):
    dupe_list = []
    ip_set = set(ips_only_list)
    for unique_ip in ip_set:
        temp = []
        for c,ip in enumerate(ips_only_list):
            if ip == unique_ip:
                temp.append(c)
        del temp[0]
        dupe_list += temp
    return dupe_list

## Returns the indices of trusted ips in a list
def find_trusted_ips(ips_only_list):
    trust_list = []
    reg = trusted_ip_regex()
    for c,ip in enumerate(ips_only_list):
        if(re.match(reg, ip)):
            trust_list.append(c)
    return trust_list

## Removes index list from intel
def remove_indices(formatted_intel, rm_index_list):
    rm_index_list.sort(reverse = True)
    for index in rm_index_list:
        print "Removing %s"%(formatted_intel[index])
        del formatted_intel[index]
    return formatted_intel
    
# Write intel to csv file
def write_to_csv(filename, completed_intel):
    print "[+]Creating CSV file"
    start, end, boundary = 0, 999, 999
    intelSize = len(completed_intel)
    while (intelSize > start):
        if(intelSize > boundary):
            set = completed_intel[start:end]
        else:
            set = completed_intel[start:]
        start += 1000
        end += 1000 
        boundary += 1000
        id = str(start)
        with open(filename + '_' + id + '.csv', 'w') as f:  
            writer = csv.writer(f)
            writer.writerows(set)
    print "[+]Complete\n"