
import requests, json




# --------------Base things for all Prisma Cloud requests------------------
def cisa_ka(cve):
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    payload = ''
    # print(payload)
    headers = {
        'Content-Type': 'application/json'
    }
    r = requests.request("GET", url, headers=headers, data=payload, proxies=proxies, verify=False)
    # print(r)
    jR = json.loads(r.text.encode('utf8'))
    epss_exp = jR['vulnerabilities']
    exp_avail = False
    for item in epss_exp:
        if item['cveID'] == cve:
            exp_avail = True
            break
   return exp_avail


def cvss(cve_id):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}'.format(cve_id)
    payload = ''
    headers = {
        'Content-Type': 'application/json'
    }
    r = requests.request("GET", url, headers=headers, data=payload, proxies=proxies, verify=False)
    # print(r)

    jD = json.loads(r.text.encode('utf8'))
    jD1 = jD['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']
    cve_basescore = jD1['baseScore']
    cve_basesev = jD1['baseSeverity']
    return cve_basescore, cve_basesev


def epss(cve):
    url = 'https://api.first.org/data/v1/epss?cve={}'.format(cve)
    payload = ''
    headers = {
        'Content-Type': 'application/json'
    }
    r = requests.request("GET", url, headers=headers, data=payload, proxies=proxies, verify=False)
    jD = json.loads(r.text.encode('utf8'))
    epss_prob = jD['data'][0]['epss']
    return epss_prob


def bin_the_things(cvss_sev, epss_prob):

    #cvss
    if cvss_sev == "CRITICAL":
        cvss_bin = 4
    elif cvss_sev == "HIGH":
        cvss_bin = 3
    elif cvss_sev == "MEDIUM":
        cvss_bin = 2
    else:
        cvss_bin = 1
    #epss
    if epss_prob >= 0.7:
        epss_bin = 4
    elif epss_prob >= 0.3:
        epss_bin = 3
    elif epss_prob >= 0.1:
        epss_bin = 2
    else:
        epss_bin = 1
    return cvss_bin, epss_bin


def adjust_score(cvss_bin, epss_bin, exp_bin):
    if exp_bin == 4:
        w_avg = (cvss_bin + epss_bin + epss_bin + exp_bin)/4
    else:
        w_avg = (cvss_bin + epss_bin + epss_bin)/3
    if w_avg >= 3.5:
        f_sev = "Critical/Very High"
    elif w_avg >= 2.5:
        f_sev = "High"
    elif w_avg >= 1.5:
        f_sev = "Moderate"
    else:
        f_sev = "Low"
    return w_avg, f_sev


def main():
    # token = getToken()
    cve = input("Enter CVE:  ")
    cve = str.upper(cve)
    # cvss('CVE-2022-1471')
    cvss_score, cvss_sev = cvss(cve)
    print('CVE: {}'.format(cve), 'CVE Score: {}'.format(cvss_score), 'CVE Severity: {}'.format(cvss_sev), sep='\n')
    exp_avail = cisa_ka(cve)
    exp_bin = 0
    if exp_avail:
        exp_bin = 4
    print("Known Exploit Available:  {}".format(exp_avail))
    epss_prob = float(epss(cve))
    cvss_bin, epss_bin = bin_the_things(cvss_sev, epss_prob)
    print("CVSS Bin: {}".format(cvss_bin), "EPSS Bin:  {}".format(epss_bin))
    w_avg, f_sev = adjust_score(cvss_bin, epss_bin, exp_bin)
    print("Weighted Average Score:  {}".format(w_avg), "Final Severity:  {}".format(f_sev), sep='\n')


if __name__ == "__main__":
    main()
