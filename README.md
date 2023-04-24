# Omegle-Geolocation

This script captures network traffic using the 'tshark' command and uses MaxMind's GeoIP2 databases to determine the location and other 
information about the source IP address of the captured traffic. It then prints this information to the console and copies it to the clipboard 
on the keyboard event of minus key and equal to key. It also generates a Google Maps link to the location, if available.

To use this script, first install the MaxMind GeoIP2 and pyperclip modules via pip. Then replace the 'cmd' variable in the script with the 
path to the 'tshark' executable on your system, and optionally modify it to specify a different network interface to capture traffic from. 
Run the script and it will continuously capture and analyze network traffic until interrupted.

This script was written by Mervin Abraham author.
