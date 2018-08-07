import requests
import generic
import sys

def run_ip_spam_list():
    
    ##  Format raw intel into a list containing lists:
    ##  [[Field 1, Field 2, Field 3, Field 4],
    ##   [Field 1, Field 2, Field 3, Field 4]]
    response = requests.get('http://www.ipspamlist.com/public_feeds.csv')
    raw_intel = str(response.text).split("\n")
    for c,row in enumerate(raw_intel):
        raw_intel[c] = row.split(",")
    
    del raw_intel[-1] # Not needed
    del raw_intel[ 0] # Not needed
    
    # Takes the raw intel and removes duplicate entries
    ip_list = generic.select_column(raw_intel, 2)
    dupe_indices = generic.find_dupes(ip_list)
    no_dupes_intel_list = generic.remove_indices(raw_intel, dupe_indices)
    
    # Takes the duplicate free intel and removes reserved ip entries
    no_dupes_ip_only = generic.select_column(no_dupes_intel_list, 2)
    trusted_indices = generic.find_trusted_ips(no_dupes_ip_only)
    cleaned_intel = generic.remove_indices(no_dupes_intel_list, trusted_indices)
    
    # ['first_seen',          'last_seen',           'ip_address',      'category',     'attacks_count']
    # ['2018-07-25 04:44:24', '2018-07-25 04:44:24', '125.162.147.201', 'MS-DS Attack', '1']
    
    # Format cleaned intel into a CSV file
    completed_intel = []
    for entry in cleaned_intel:
        skip = False
        if(entry[3]=="MS-DS Attack"):
            target_collection = "inbox_ip_hacker"
            title = ("IP Address Associated With %s")%(entry[3]+"s")
            description = "IP of attacker detected targeting the Microsoft-DS file sharing port 445 (SMB). If exploited an attacker could transfer malicious content to remote machines. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="MS-SQL Attack"):
            target_collection = "inbox_ip_hacker"
            title = ("IP Address Associated With %s")%(entry[3]+"s")
            description = "IP of attacker detected targeting a Microsoft SQL server. A successful attack would allow full database access and could also be used to gain further system access. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="SIP"):
            target_collection = "inbox_ip_hacker"
            title = ("IP Address Associated With %s Attacks")%(entry[3])
            description = "IP of attacker detected targeting the SIP communication protocol. An attacker could attempt to obtain login credentials or launch a denial of service attack. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="Telnet"):
            target_collection = "inbox_ip_forcer"
            title = ("IP Address Associated With %s Attacks")%(entry[3])
            description = "IP of attacker attempting to connect to a honeypot through Telnet. In combination with a password list an attacker could brute force login credentials. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="SSH Brute Force"):
            target_collection = "inbox_ip_forcer"
            title = ("IP Address Associated With %s Attacks")%(entry[3])
            description = "IP of attacker attempting to brute force SSH connections. A successful brute force would provide the attacker with a shell on the target system. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="Unclassified"):
            skip = True
        elif(entry[3]=="Proxy Scan"):
            target_collection = "inbox_ip_internet_scanner"
            title = ("IP Address Associated With %s")%(entry[3]+"s")
            description = "IP of attacker detected scanning for proxy servers. Targeting a proxy would allow an attacker to inject code and modify data in transit. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="FTP"):
            target_collection = "inbox_ip_forcer"
            title = ("IP Address Associated With %s Attacks")%(entry[3])
            description = "IP of attacker targeting a FTP server. An attacker could brute force login credentials allowing the theft of files and also insert a malicious file. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="Mirai"):
            target_collection = "inbox_ip_hacker"
            title = ("IP Address Associated With Distributing %s")%(entry[3])
            description = "IP of attacker attempting to infect a honeypot with Mirai. Mirai typically gains access to devices through default credentials and turns the infected device into bot. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="VNC Attack"):
            target_collection = "inbox_ip_hacker"
            title = ("IP Address Associated With %s")%(entry[3]+"s")
            description = "IP of attacker detected targeting a VNC service. VNC allows a user to remotely control another computer and if exploited an attacker would gain access to the system. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="MySQL Attack"):
            target_collection = "inbox_ip_hacker"
            title = ("IP Address Associated With %s")%(entry[3]+"s")
            description = "IP of attacker detected targeting a MySQL database. Brute force attacks and SQL injections common methods which can be used to gain access to the database. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="RDP Attack"):
            target_collection = "inbox_ip_forcer"
            title = ("IP Address Associated With %s")%(entry[3]+"s")
            description = "IP of attacker attempting to brute force RDP connections. Gaining access via RDP allows an attacker to do anything within the accounts privileges. This intel was reported by IpSpamList and is updated every 24hrs."
        elif(entry[3]=="Postfix"):
            skip = True
            # Sort later
        elif(entry[3]=="Socks Scan"):
            skip = True
            # Sort later
        elif(entry[3]=="Netbios Attack"):
            skip = True
            # Sort later
        elif(entry[3]=="Comment Spam"):
            skip = True
            # Sort later
        elif(entry[3]=="Web Hacking"):
            skip = True
            # Sort later
        else:
            print("Unknown category: %s")%(entry[3])
            print("-- Update code --")
            sys.exit()
        
        if(skip == False):
            temp_list = []
            temp_list.append(target_collection)
            temp_list.append(entry[1])
            temp_list.append("")
            temp_list.append("")
            temp_list.append(title)
            temp_list.append(description)
            temp_list.append(entry[2])
            temp_list.append("Low")
            temp_list.append("ipspamlist.com")
            completed_intel.append(temp_list)
        skip = False
    
    generic.write_to_csv("IpSpamList", completed_intel)

run_ip_spam_list()
