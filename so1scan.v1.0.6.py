import argparse, requests, socket, json, ipaddress, datetime, re, vt, whois, json, csv, sys, os
from urllib.parse import urlparse
import dns.resolver
from colorama import Fore, init

def main():

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', '--domain', required=True, help='the domain you want to query')
        parser.add_argument('-f', '--file_type', choices=['json', 'txt'], help='file type of the output file')
        parser.add_argument('-n', '--name', help='location & file name of the file (results.txt or ~/Documents/proton.json)')
        parser.add_argument('-q', '--quiet', action='store_true', help='when enabled suppresses all terminal output ')
        args = parser.parse_args()
        url = str(args.domain)
        domain = urlparse(url).netloc


        if (args.name != None and args.file_type == None) or (args.name == None and args.file_type != None):
            print('error: --name and --file-type are required together!')
            return

        init()
        client = vt.Client('help') #vt api needed

        if args.quiet:
            sys.stdout = open(os.devnull, 'w')

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

        if args.file_type != None:
            if args.file_type == 'json':
                data = {
                    'Url':url,
                    'IP':ip,
                    'VT Score':f'{url_vt.last_analysis_stats['malicious']}/{count}',
                    'Server':r.headers.get('Server')
                    }
                with open(args.name, 'a') as f:
                    json.dump(data, f, indent=2)
            elif args.file_type == 'txt':
                data = f'Querying {url}\nIP address of {domain}: {ip}\nMALICIOUS {url_vt.last_analysis_stats['malicious']}/{count} vendors\nServer: {r.headers.get('Server')}'
                with open(args.name, 'a') as f:
                    f.write(data)
        http_headers(r, args)
        who_is(domain, args)
        client.close()



    except dns.resolver.NXDOMAIN:
        print(f'Domain {domain} not found')
        client.close()
    except vt.error.APIError:
        print('invalid API key, try again')
        client.close()
    except Exception as e:
        print(e)
        client.close()




def http_headers(response, args):
    print(f'\nHTTP SECURITY HEADERS')
    csp = response.headers.get('Content-Security-Policy')
    if csp == None :
        print(f'{Fore.RED}NO CSP')
        csp = 'NO CSP'
    elif 'unsafe-inline' in csp or 'unsafe-eval' in csp or '*' in csp:
        print(f'{Fore.YELLOW}WEAK CSP')
        csp = 'WEAK CSP'
    else:
        print(f'{Fore.GREEN}OK CSP')
        csp = 'OK CSP'

    hsts = response.headers.get('Strict-Transport-Security')
    if hsts == None:
        print(f'{Fore.RED}NO HSTS')
        hsts = 'NO HSTS'
    else:
        print(f'{Fore.GREEN}OK HSTS')
        hsts = 'OK HSTS'

    xframe = response.headers.get('X-Frame-Options')
    if xframe == None:
        print(f'{Fore.RED}NO X-FRAME')
        xframe = 'NO X-FRAME'
    elif 'DENY' in xframe or 'SAMEORIGIN' in xframe:
        print(f'{Fore.GREEN}OK X-FRAME')
        xframe = 'OK X-FRAME'
    else:
        print(f'{Fore.YELLOW}WEAK X-FRAME')

    cors = response.headers.get('Access-Control-Allow-Origin')
    if cors == None:
        print(f'{Fore.GREEN}NO CORS')
        cors = 'NO CORS'

    elif response.headers.get('Access-Control-Allow-Credentials') == 'true':
        print(f'{Fore.RED}WEAK CORS')
        cors = 'WEAK CORS'
    else:
        print(f'{Fore.YELLOW}ENABLED CORS')
        cors = 'ENABLED CORS'

    xcont = response.headers.get('X-Content-Type-Option')
    if xcont == 'nosniff':
        print(f'{Fore.GREEN}OK X-CONTENT-TYPE')
        xcont = 'OK X-CONTENT-TYPE'
    else:
        print(f'{Fore.RED}BAD X-CONTENT-TYPE')
        xcont = 'BAD X-CONTENT-TYPE'

    ref_pol = response.headers.get('Referrer-Policy')
    if ref_pol == None:
        print(f'{Fore.RED}BAD REFERRER POLICY')
        ref_pol = 'BAD REFERRER POLICY'

    elif not 'strict-origin-when-cross-origin' in ref_pol or not 'no-referrer' in ref_pol:
        print(f'{Fore.RED}BAD REFERRER POLICY')
        ref_pol = 'BAD REFERRER POLICY'
    else:
        print(f'{Fore.GREEN}OK REFERRER POLICY')
        ref_pol = 'OK REFERRER POLICY'

    if args.file_type != None:
        if args.file_type == 'json':
            data = {
                'CSP':csp,
                'HSTS':hsts,
                'XFRAME':xframe,
                'CORS':cors,
                'XCONT':xcont,
                'REF_POL':ref_pol,
                }
            with open(args.name, 'a') as f:
                json.dump(data, f, indent=2)
        else:
            with open(args.name, 'a') as f:
                f.write(f'\nHTTP HEADERS\n{csp}\n{hsts}\n{xframe}\n{cors}\n{xcont}\n{ref_pol}')



def who_is(domain, args):
    w = whois.whois(domain)
    print(f'\n{Fore.WHITE}WHOIS LOOKUP{Fore.CYAN}')
    print(f'Registrar: {w.registrar}')
    print(f'Country: {w.country}')
    print(f'City: {w.city}')
    print(f'Creation date: {w.creation_date[0]}')
    print(f'Expiring on: {w.expiration_date[0]}')
    print(f'Abuse email: {w.emails}')
    file_type = args.file_type
    if file_type != None:
        if file_type == 'json':
            cre_time = w.creation_date
            if isinstance(cre_time, list):
                cre_time = [d.isoformat() if isinstance(d, datetime.datetime) else str(d) for d in cre_time]
            elif isinstance(cre_time, datetime.datetime):
                cre_time = cre_time.isoformat()
            else:
                cre_time = str(cre_time)

            end_time = w.expiration_date
            if isinstance(end_time, list):
                end_time = [d.isoformat() if isinstance(d, datetime.datetime) else str(d) for d in end_time]
            elif isinstance(end_time, datetime.datetime):
                end_time = end_time.isoformat()
            else:
                end_time = str(end_time)

            data = {
                'Registrar': w.registrar,
                'Country': w.country,
                'City': w.city,
                'Creation date': cre_time[0],
                'Expiring on': end_time[0],
                'Abuse email': w.emails,
                    }
            with open(args.name, 'a') as f:
                json.dump(data, f, indent=2)
        elif file_type == 'txt':
            data = f'\nWHOIS\nRegistrar: {w.registrar}\nCountry: {w.country}\nCity: {w.city}\nCreation date: {w.creation_date[0]}\nExpiring on: {w.expiration_date[0]}\nAbuse email: {w.emails}'
            with open(args.name, 'a') as f:
                f.write(data)




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\nExiting..')
        client.close()
