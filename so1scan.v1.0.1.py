import argparse, requests, socket, json, ipaddress, datetime, re, vt
from urllib.parse import urlparse
import dns.resolver
from colorama import Fore, init

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', '--domain', required=True)
        args = parser.parse_args()
        url = str(args.domain)
        domain = urlparse(url).netloc

        init()
        client = vt.Client('API KEY')


        print(f'Querying {url}')
        answers = dns.resolver.resolve(domain, 'A')
        ip = answers[0].to_text()
        print(f"IP address of {domain}:", ip)



        url_id = vt.url_id(url)
        url_vt = client.get_object(f"/urls/{url_id}")
        count = 0

        for i in url_vt.last_analysis_stats:
            count += url_vt.last_analysis_stats[i]

        print(f'MALICIOUS {url_vt.last_analysis_stats['malicious']}/{count} vendors')
        r = requests.get(url)
        print('Server:', r.headers.get('Server'))
        http_headers(r)
        client.close()



    except dns.resolver.NXDOMAIN:
        print(f'Domain {domain} not found')
        client.close()
    except Exception as e:
        print(e)
        client.close()




def http_headers(response):
    print(f'\nHTTP SECURITY HEADERS')
    csp = response.headers.get('Content-Security-Policy')
    if csp == None :
        print(f'{Fore.RED}NO CSP')
    elif 'unsafe-inline' in csp or 'unsafe-eval' in csp or '*' in csp:
        print(f'{Fore.YELLOW}WEAK CSP')
    else:
        print(f'{Fore.GREEN}OK CSP')

    hsts = response.headers.get('Strict-Transport-Security')
    if hsts == None:
        print(f'{Fore.RED}NO HSTS')
    else:
        print(f'{Fore.GREEN}OK HSTS')

    xframe = response.headers.get('X-Frame-Options')
    if xframe == None:
        print(f'{Fore.RED}NO X-FRAME')
    elif 'DENY' in xframe or 'SAMEORIGIN' in xframe:
        print(f'{Fore.GREEN}OK X-FRAME')
    else:
        print(f'{Fore.YELLOW}WEAK X-FRAME')

    cors = response.headers.get('Access-Control-Allow-Origin')
    if cors == None:
        print(f'{Fore.GREEN}NO CORS')

    elif response.headers.get('Access-Control-Allow-Credentials') == 'true':
        print(f'{Fore.RED}WEAK CORS')
    else:
        print(f'{Fore.YELLOW}ENABLED CORS')

    xcont = response.headers.get('X-Content-Type-Option')
    if xcont == 'nosniff':
        print(f'{Fore.GREEN}OK X-CONTENT-TYPE')
    else:
        print(f'{Fore.RED}BAD X-CONTENT-TYPE')

    ref_pol = response.headers.get('Referrer-Policy')
    if ref_pol == None:
        print(f'{Fore.RED}BAD REFERRER POLICY')

    elif not 'strict-origin-when-cross-origin' or not 'no-referrer' in ref_pol:
        print(f'{Fore.RED}BAD REFERRER POLICY')
    else:
        print(f'{Fore.GREEN}OK REFERRER POLICY')




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\nExiting..')
        client.close()
