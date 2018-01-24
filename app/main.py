#!/usr/bin/env python3

from os import environ
from json import loads
import requests
import subprocess
import logging
import uritools
import multiprocessing

def get_parameters():
    """
    This function retreive plugin parameters from your environment.
    raise RuntimeError if the parameters are not defined
    """
    try:
        return loads(environ['parameters'])
    except Exception as e:
        raise RuntimeError('Plugins failed to load configuration: %s' % e)

def details_search(details, host):
    r = []
    if details['heartbleed']:
        r.append({
            'severity': 7,
            'description': 'Heartbleed',
            'message': 'Heartbleed vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if details['poodle']:
        r.append({
            'severity': 7,
            'description': 'Poodle',
            'message': 'Poodle vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if details['supportsRc4']:
        r.append({
            'severity': 4,
            'description': 'RC4 ciphers',
            'message': 'RC4 supported ciphers for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if details['vulnBeast']:
        r.append({
            'severity': 4,
            'description': 'Beast',
            'message': 'Beast vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if details['poodleTls']:
        r.append({
            'severity': 7,
            'description': 'Poodle TLS',
            'message': 'poodleTls vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if not details['fallbackScsv']:
        r.append({
            'severity': 4,
            'description': 'No scsv fallback',
            'message': 'SCSV Fallback not enabled for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if not details['fallbackScsv']:
        r.append({
            'severity': 4,
            'description': 'No scsv fallback',
            'message': 'SCSV Fallback not enabled for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if details['rc4WithModern']:
        r.append({
            'severity': 6,
            'description': 'No scsv fallback',
            'message': 'RC4 cipher can be used with modern client',
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if details['openSSLLuckyMinus20'] == 2:
        r.append({
            'severity': 9,
            'description': 'No scsv fallback',
            'message': 'LuckyMinus20 attack possible on host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    return r

def detect_cipher_suites(cs, host):
    r = []
    for c in cs:
        if c.q == 0:
            r.append({
                'severity': 1,
                'description': 'Weak suite',
                'message': 'Weak cipher suite used {}'.format(c.name),
                'ressource': host,
                'values': {'foo': 'bar'}
            })
    return r

def detect_browser_compatibility(bq, host):
    r = []
    for b in bq:
        if b['errorCode'] == 0:
            r.append({
                'severity': 2,
                'description': 'browser SSL incompatibility',
                'resource': host,
                'message': 'Your configuration is currently not compatible with {}'.format(
                    ' '.join([b['client']['name'], b['client']['platform'], b['client']['version']])
                ),
                'values': {'foo': 'bar'}
            })
    return r

def detect_protocol(ptcs, host):
    r = []
    for p in ptcs:
        if p['name'] == 'TLS' and p['version'] in ['1.0', '1.1']:
            r.append({
                'severity': 3,
                'description': 'Weak protocol supported',
                'message': 'Host support {} {}'.format(p['name'], p['version']),
                'resource': host,
                'values': {'foo':'bar'}
            })
        elif p['name'] == 'SSL':
            r.append({
                'severity': 9,
                'description': 'Legacy SSL protocol supported',
                'message:': 'host {} support legacy protocol {} {}'.format(
                    host,
                    p['name'],
                    p['version']
                ),
                'resource': host,
                'values': {'foo':'bar'}
            })
    return r

def build_report(rep):
    alerts = []
    for r in rep:
        for endpoint in r['endpoints']:
            alerts += details_search(endpoint['details'])
            alerts += detect_browser_compatibility(endpoint['details']['sims'])
            alerts += detect_cipher_suites(endpoint['details']['suites'])
            alerts += detect_protocol(endpoint['details']['protocols'])
    return alerts

def emit_alert(alert, api_host, api_port):
    LOGGER = logging.getLogger('ssl')
    LOGGER.info('==========')
    LOGGER.info(json.dumps(alert))
    # r = requests.post('https://%s:%d/a' % (api_host, api_port),
    #                   json=payload,
    #                   verify=False)
    # if r.status_code != 200:
    #     LOGGER.error("Error while emiting alert")
    # else:
    #     LOGGER.info("Alert correctly emitted")

def analyse(host, api_host, api_port):
    LOGGER = logging.getLogger("ssl")
    p = subprocess.run(['/app/ssllabs-scan', '--quiet', host], stdout=subprocess.PIPE, check=True)
    try:
        rep = loads(p.stdout)
    except:
        LOGGER.info('Analyse has fail on %s' % resource)
    else:
        for alert in build_report(rep):
            emit_alert(alert, api_host, api_port)

def main():
    """
    main function trigger the binary and parse the output
    """

    # Retreive plugin parameters
    parameters = get_parameters()

    # Setup logging (Facultative)
    log_level = 'DEBUG' if bool(parameters.get('DEBUG')) is True else 'INFO'
    logging.basicConfig(level=getattr(logging, log_level))
    LOGGER = logging.getLogger("ssl")

    LOGGER.info('Starting to log from ssl plugin')
    LOGGER.debug('Launched with environ : %s' % environ['parameters'])
    # Loading system variables
    api_host, api_port = environ['API_HOST'], int(environ['API_PORT'])

    # API connection
    LOGGER.info('Contacting API at : "%s"', '%s:%d' % (api_host, api_port))
    #req = requests.get('https://%s:%d/r' % (api_host, api_port), stream=True, verify=False)
    domains = {}
    #for resource in req.iter_content(chunk_size=None):
    for resource in [b'https://www.assuranceendirect.com/mabite']:
        r = uritools.urisplit(str(resource, 'utf-8'))
        LOGGER.info('Received domain "%s"', r.host)
        if r.host in domains:
            LOGGER.info('domain %s already started')
            continue
        elif len(domains.keys()) >= 1:
            LOGGER.info('only one domain scan by analyse')
            continue
        domains[r.host] = multiprocessing.Process(target=analyse, args=(r.host, api_host, api_port))
        domains[r.host].start()
        LOGGER.info
    for i in domains.values():
        i.join()

if __name__ == '__main__':
    main()
