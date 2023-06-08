import requests
import json
import urllib3
import time
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "X-OTX-API-KEY": "Input Your Key",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Whale/3.20.182.14 Safari/537.36",
    "Connection": "close"
    }

def get_info(ip):
    url = f"http://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
    response = requests.post(url, headers=headers, verify=False)
    decoded_response = response.json()

    try:
        pulse_info = decoded_response['pulse_info']
        
        indicator = decoded_response['indicator']
        print(f'IP :              {indicator}')

        if 'country_code' in decoded_response:
            country_code = decoded_response['country_code']
            print(f'Country Code :    {country_code}')
        else:
            print(f'Country Code :    Not verified')

        pulse_count = pulse_info['count']
        print(f'Pulse Count :     {pulse_count}')

        adversary = pulse_info['related']['other']['adversary']
        if len(adversary) != 0:
            print(f"Adversary :       {','.join(adversary)}")
        malware_families = pulse_info['related']['other']['malware_families']
        if len(malware_families) != 0:
            print(f"Malwares :        {', '.join(malware_families)}")
        get_pulses_detail(pulse_count, pulse_info)
    except:
        print(f"An unexpected Error Occurred !\n")

def get_pulses_detail(pulse_count, pulse_info):
    if pulse_count != 0:
        total_tags = []

        for pulses in pulse_info['pulses']:
            if len(pulses['attack_ids']) != 0:                
                tmp_ids = []
                for ids in pulses['attack_ids']:
                    ids_name = ids['display_name']
                    tmp_ids.append(ids_name)
                    result_ids = ', '.join(tmp_ids)
                
            if len(pulses['tags']) != 0:
                tmp_tags = ', '.join(pulses['tags'])
                total_tags.extend(tmp_tags.split(', '))
                result_tags = ', '.join(sorted(set(total_tags)))
        
        if len(pulses['attack_ids']) != 0:
            print(f'* Related IDS :   {result_ids}')
        
        if len(set(total_tags)) != 0:
            print(f'* Tags Count :    {len(set(total_tags))}')
            print(f'* Related Tags :  {result_tags}\n')

def main():
    start_time = time.time()

    print("\n Checking...\n")

    if len(sys.argv) == 2:
        input_data = sys.argv[1]
        if not input_data.endswith('.txt'):
            get_info(input_data)
        else:
            with open(input_data, 'r') as f:
                lines = f.readlines()
            for line in lines:
                ip = line.strip()
                if ip:
                    get_info(ip)
    else:
        print("값을 입력하세요. \n")

    print(f'Total Time:       {round((time.time() - start_time), 2)} seconds')

if __name__ == '__main__':
    main()
