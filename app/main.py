#!/usr/bin/env python3

from os import environ
from json import loads, dumps
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
    if 'heartbleed' in details:
        r.append({
            'severity': 7,
            'description': 'SSL: Heartbleed vulnerability',
            'message': 'Heartbleed vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'poodle' in details:
        r.append({
            'severity': 7,
            'description': 'SSL: Poodle vulnerability',
            'message': 'Poodle vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'supportsRc4' in details:
        r.append({
            'severity': 4,
            'description': 'SSL: RC4 ciphers supported',
            'message': 'RC4 supported ciphers for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'vulnBeast' in details:
        r.append({
            'severity': 4,
            'description': 'SSL: Beast vulnerability',
            'message': 'Beast vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'poodleTls' in details and details['poodleTls'] == 2:
        r.append({
            'severity': 7,
            'description': 'SSL: Poodle TLS',
            'message': 'poodleTls vulnerable configuration for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'fallbackScsv' not in details:
        r.append({
            'severity': 4,
            'description': 'SSL: No scsv fallback',
            'message': 'SCSV Fallback not enabled for host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'rc4WithModern' in details:
        r.append({
            'severity': 6,
            'description': 'SSL: RC4 supported on new clients',
            'message': 'RC4 cipher can be used with modern client',
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    if 'openSSLLuckyMinus20' in details and details['openSSLLuckyMinus20'] == 2:
        r.append({
            'severity': 9,
            'description': 'SSL: LuckyMinus vulnerability',
            'message': 'LuckyMinus20 attack possible on host {}'.format(host),
            'ressource': host,
            'values': {'foo': 'bar'}
        })
    return r

def detect_cipher_suites(cs, host):
    LOGGER = logging.getLogger('ssl')
    r = []
    try:
        for c in cs['list']:
            if 'q' in c.keys():
                r.append({
                    'severity': 1,
                    'description': 'SSL: Weak cipher {}'.format(c.name),
                    'message': 'Weak cipher suite used {}'.format(c.name),
                    'ressource': host,
                    'values': {'foo': 'bar'}
                })
    except Exception as e:
        LOGGER.error(e)
        return []
    return r

def detect_browser_compatibility(bq, host):
    LOGGER = logging.getLogger('ssl')
    r = []
    try:
        for b in bq:
            if b['errorCode'] == 0:
                r.append({
                    'severity': 2,
                    'description': 'SSL: browser SSL incompatibility {}'.format(
                        ' '.join([b['client']['name'], b['client']['version']])
                    ),
                    'ressource': host,
                    'message': 'Your configuration is currently not compatible with {}'.format(
                        ' '.join([ b['client']['name'], b['client']['version'] ])
                    ),
                    'values': {'foo': 'bar'}
                })
    except Exception as e:
        LOGGER.error(e)
        pass
    return r

def detect_protocol(ptcs, host):
    LOGGER = logging.getLogger('ssl')
    r = []
    try:
        for p in ptcs:
            if p['name'] == 'TLS' and p['version'] in ['1.0', '1.1']:
                r.append({
                    'severity': 3,
                    'description': 'SSL: Weak protocol {} {}'.format(p['name'], p['version']),
                    'message': 'Host support {} {}'.format(p['name'], p['version']),
                    'ressource': host,
                    'values': {'foo':'bar'}
                })
            elif p['name'] == 'SSL':
                r.append({
                    'severity': 9,
                    'description': 'SSL: Legacy protocol {} {}'.format(
                        p['name'],
                        p['version']
                    ),
                    'message:': 'host {} support legacy protocol {} {}'.format(
                        host,
                        p['name'],
                        p['version']
                    ),
                    'ressource': host,
                    'values': {'foo':'bar'}
                })
    except Exception as e:
        LOGGER.error(e)
        return []
    return r

def build_report(rep, host):
    alerts = []
    for r in rep:
        for endpoint in r['endpoints']:
            alerts += details_search(endpoint['details'], host)
            alerts += detect_browser_compatibility(endpoint['details']['sims']['results'], host)
            alerts += detect_cipher_suites(endpoint['details']['suites'], host)
            alerts += detect_protocol(endpoint['details']['protocols'], host)
    return alerts

def emit_alert(alert, api_host, api_port):
    LOGGER = logging.getLogger('ssl')
    r = requests.post('https://%s:%d/a' % (api_host, api_port),
                      json=alert,
                      verify=False)
    LOGGER.info('code {} body {}'.format(r.status_code, r.content))
    if r.status_code != 200:
        LOGGER.error("Error while emiting alert")
    else:
        LOGGER.info("Alert correctly emitted")

def analyse(host, api_host, api_port):
    LOGGER = logging.getLogger("ssl")
    env_cpy = environ.copy()
    del env_cpy['http_proxy']
    del env_cpy['https_proxy']
    p = subprocess.Popen('/app/ssllabs-scan --quiet {}'.format(host).split(), stdout=subprocess.PIPE, env=env_cpy)
    try:
        j, _ = p.communicate()
        rep = loads(j.decode('ascii'))
    except:
        LOGGER.info('Analyse has fail on %s', host)
    else:
        for alert in build_report(rep, host):
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
    LOGGER.debug('Launched with environ : %s', environ['parameters'])
    # Loading system variables
    api_host, api_port = environ['API_HOST'], int(environ['API_PORT'])

    # API connection
    LOGGER.info('Contacting API at : "%s"', '%s:%d' % (api_host, api_port))
    req = requests.get('https://%s:%d/r' % (api_host, api_port), stream=True, verify=False)
    domains = {}
    for resource in req.iter_content(chunk_size=None):
        r = uritools.urisplit(str(resource, 'utf-8'))
        LOGGER.info('Received domain "%s"', r.host)
        if len(r.host) == 0:
            LOGGER.info('Empty domain received')
            continue
        if r.host in domains:
            LOGGER.info('domain %s already started', r.host)
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
