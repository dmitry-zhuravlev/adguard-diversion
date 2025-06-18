#!/usr/bin/env python3

import os
import re
import urllib.request

def convert_adguard_to_dnsmasq(input_content, output_file):
    """
    Convert AdGuard filter content to DNSMasq format and write to output file
    """
    with open(output_file, 'w') as outfile:
        # Write a header to the output file
        outfile.write('# Converted from AdGuard DNS filter to DNSMasq format\n')
        outfile.write('# Conversion date: ' + os.popen('date').read().strip() + '\n\n')
        
        for line in input_content.splitlines():
            line = line.strip()
            
            # Preserve comments (lines starting with !)
            if line.startswith('!'):
                outfile.write('# ' + line[1:] + '\n')
                continue
            
            # Skip empty lines
            if not line:
                outfile.write('\n')
                continue
            
            # Convert domain rules from ||domain.com^ to local=/domain.com/0.0.0.0
            # The regex matches the domain part between || and ^
            match = re.match(r'\|\|([a-zA-Z0-9.-]+)\^', line)
            if match:
                domain = match.group(1)
                # DNSMasq v2.86 or newer syntax for blocking domains
                outfile.write(f'local=/{domain}/0.0.0.0\n')
            else:
                # If the line doesn't match the expected format, add it as a comment
                outfile.write('# Unprocessed: ' + line + '\n')

def read_properties_file(file_path):
    """
    Read a properties file and return a dictionary of key-value pairs
    """
    properties = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                properties[key] = value
    return properties

def fetch_url_content(url):
    """
    Fetch content from a URL and return it as a string
    """
    with urllib.request.urlopen(url) as response:
        return response.read().decode('utf-8')

# Ensure the output directory exists
os.makedirs('format/diversion', exist_ok=True)

# Read the properties file
properties = read_properties_file('format/adguard/url.properties')

# Process each URL in the properties file
for key, url in properties.items():
    try:
        print(f"Processing {key}...")
        print(f"Fetching content from {url}...")
        content = fetch_url_content(url)
        
        # Use the key from the properties file for the output filename
        output_file = f'format/diversion/{key}.txt'
        print(f"Converting and saving to {output_file}...")
        convert_adguard_to_dnsmasq(content, output_file)
        
        print(f"Conversion complete for {key}")
    except Exception as e:
        print(f"Error processing {key}: {e}")

print("All conversions complete.")
