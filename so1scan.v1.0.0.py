import argparse, requests, socket, json, ipaddress, datetime, re
from colorama import Fore, init

def main():
    try:
        init()
        r = requests.get('https://gmail.com')
        if 'Content-Security-Policy' in r.headers:
            print(f'{Fore.GREEN}site has CSP')
        else:
            print(f'{Fore.RED}site is missing CSP')

        if 'Strict-Transport-Security' in r.headers:
            print(f'{Fore.GREEN}site has HSTS')
        else:
            print(f'{Fore.RED}site is missing HSTS')

        if 'Permissions-Policy' in r.headers:
            print(f'{Fore.GREEN}site has Permissions-Policy')
        else:
            print(f'{Fore.RED}site is missing Permissions-Policy')

        if 'X-Content-Type-Options' in r.headers:
            print(f'{Fore.GREEN}site has no sniff content type')
        else:
            print(f'{Fore.RED}site is missing no sniff content type')


        # print(r.headers)
    except Exception:
        pass



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\nExiting..')
