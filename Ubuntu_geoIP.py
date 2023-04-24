"""
This script captures network traffic using the 'tshark' command and uses MaxMind's GeoIP2 databases to determine the location and other 
information about the source IP address of the captured traffic. It then prints this information to the console and copies it to the clipboard 
on the keyboard event of minus key and equal to key. It also generates a Google Maps link to the location, if available.

To use this script, first install the MaxMind GeoIP2 and pyperclip modules via pip. Then replace the 'cmd' variable in the script with the 
path to the 'tshark' executable on your system, and optionally modify it to specify a different network interface to capture traffic from. 
Run the script and it will continuously capture and analyze network traffic until interrupted.

This script was written by Mervin Abraham author.
"""

# pip3 install maxminddb-geolite2

import json
import sys
import time
from urllib import request
from geolite2 import geolite2
import socket, subprocess
import keyboard
import pyperclip
import logging
import maxminddb

# replace with the path to the tshark executable on your system
cmd = "/usr/bin/tshark"

# if ethernet try
# cmd = "/usr/bin/tshark -i eth0"

# you can list all your interfaces by running "tshark --list-interfaces"
# then if for instance you want to use the 4th try:
# cmd = "/usr/bin/tshark -i 4"

logging.basicConfig(filename='geolocation.log', filemode='w', level=logging.INFO, format='%(message)s')
logging.basicConfig(filename='geolocation_debug.log', filemode='w', level=logging.DEBUG, format='%(message)s')
logger = logging.getLogger()

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
my_ip = socket.gethostbyname(socket.gethostname())
city_reader = geolite2.reader()
asn_reader = maxminddb.open_database('GeoLite2-ASN.mmdb')


def get_ip_location(ip):
    city_data = city_reader.get(ip)
    asn_data = asn_reader.get(ip)

    try:
        country = city_data["country"]["names"]["en"]
    except:
        country = "Unknown"

    try:
        subdivision = city_data["subdivisions"][0]["names"]["en"]
    except:
        subdivision = "Unknown"    

    try:
        city = city_data["city"]["names"]["en"]
    except:
        city = "Unknown"

    try:
        postal_code = city_data["postal"]["code"]
    except:
        postal_code = "Unknown"

    try:
        asn = asn_data["autonomous_system_organization"]
    except:
        try:
            asn = city_data["traits"]["autonomous_system_organization"]
        except:
            asn = "Unknown"

    try:
        user_type = asn_data["user_type"]
    except:
        user_type = "Unknown"

    try:
        accuracy_radius = city_data["location"]["accuracy_radius"]
    except:
        accuracy_radius = "Unknown"

    try:
        latitude = city_data["location"]["latitude"]
    except:
        latitude = "Unknown"

    try:
        longitude = city_data["location"]["longitude"]
    except:
        longitude = "Unknown"

    try:
        time_zone = city_data["location"]["time_zone"]
    except:
        time_zone = "Unknown"
        
    try:
        subdivision_confidence = city_data["subdivisions"][1]
    except:
        subdivision_confidence = "Unknown"

    try:
        postal_code_confidence = city_data["postal"]["time_zone"]
    except:
        postal_code_confidence = "Unknown"

    try:
        user_count = city_data["traits"]["user_count"]
    except:
        try:
            user_count = asn_data["user_count"]
        except:
            user_count = "Unknown"

    return ( 
            country, 
            subdivision,
            subdivision_confidence, 
            city, 
            postal_code,
            postal_code_confidence, 
            asn, 
            user_type, 
            user_count,
            accuracy_radius, 
            latitude, 
            longitude, 
            time_zone
            )

minus_key = "U+2212"
plus_key = "U+003D"

def s1_copy():
    pyperclip.copy(s1)

def result_copy():
    pyperclip.copy(result)

def handler(event):
    if (event.event_type == keyboard.KEY_UP and event.scan_code == minus_key):
        s1_copy() # Works
    elif (event.event_type == keyboard.KEY_UP and event.scan_code == plus_key):
        result_copy()

count = 1
result = "Unknown, Unknown, Unknown, Unknown, Unknown, Unknown"
try:
    for line in iter(process.stdout.readline, b""):
        sys.stdout.flush()
        columns = str(line).split(" ")

        if "SKYPE" in columns or "UDP" in columns:
            
            # for different tshark versions
            if "->" in columns:
                src_ip = columns[columns.index("->") - 1]
            elif "\\xe2\\x86\\x92" in columns:
                src_ip = columns[columns.index("\\xe2\\x86\\x92") - 1]
            else:
                continue
                
            if str(src_ip).startswith("142.25"):
                continue
            if src_ip == my_ip:
                continue

            try:
                country, subdivision, subdivision_confidence, city, postal_code, postal_code_confidence, asn, user_type, user_count, accuracy_radius, latitude, longitude, time_zone = get_ip_location(src_ip)
                s1 = (country + ", " + subdivision + ", " + city + ", " + postal_code)
                
                if count == 1:
                    count -= 1
                    
                    print("\n\n----------------- Packet Sniffing GeoLocation -----------------\n\n")

                if s1 != "Unknown, Unknown, Unknown, Unknown, Unknown, Unknown":
                    if result != s1:
                        result = s1
                        result = (  
                            "Country: " + country + "\n" + 
                            "Subdivision: " + subdivision + "\n" + 
                            "Subdivision confidence: " + subdivision_confidence + "\n" + 
                            "City: " + city + "\n" + 
                            "Postal code: " + postal_code + "\n" + 
                            "Postal code confidence: " + postal_code_confidence + "\n" + 
                            "Data Provider: " + asn + "\n" + 
                            "User type: " + user_type + "\n" + 
                            "User count: " + user_count + "\n" + 
                            "Time zone: " + time_zone
                            )
                        print("_____________________________________________________________________________")
                        try:
                            keyboard.hook(handler)
                            keyboard.wait()
                        except:
                            logger.exception("An exception occurred while trying to copy the location to the clipboard")
                        try:
                            logger.info(s1)
                            print(result) 
                            print(s1)
                        except:
                            pass

                        if latitude != "Unknown" and longitude != "Unknown":
                            print("\nLongitude and Latitude : {}".format(accuracy_radius))
                            s2 = "https://www.google.com/maps/search/?api=1&query=" + str(latitude) + "%2C" + str(longitude)
                            logger.info("\n Longitude and Latitude : {}".format(accuracy_radius))
                            logger.info(s2)
                        if time_zone != "Unkown" and postal_code != "Unknown":
                            print("Time Zone: {}\nPostal Code: {} \nPostal Confidence: {}".format(str(time_zone) ,str(postal_code), postal_code_confidence))
                            s2 = "https://www.google.com/maps/search/?api=1&query=" + str(time_zone) + "%2C" + str(postal_code)
                            logger.info("Time Zone: {}\nPostal Code: {} \nPostal Confidence: {}".format(str(time_zone) ,str(postal_code), postal_code_confidence))
                            logger.info(s2)
                        if time_zone != "Unknown":
                            print("Time Zone: {}".format(time_zone))
                            s2 = "https://www.google.com/maps/search/?api=1&query=" + str(time_zone)
                            logger.info("Time Zone: {}".format(time_zone))
                            logger.info(s2)
                        if asn != "Unknown":
                            print("Network Provider: {}".format(asn))
                            s2 = "https://www.google.com/search?q=" + asn
                            logger.info("Network Provider: {}".format(asn))
                            logger.info(s2)
            except Exception as e:
                logger.debug(e)
except KeyboardInterrupt:
    sys.stdout.flush()
    process.kill()
    city_reader.close()
    asn_reader.close()
    print("Exiting.....")
    sys.exit(0)
