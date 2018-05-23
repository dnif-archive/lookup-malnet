import yaml
import requests
import datetime
import os
import json
import sys


path = os.environ["WORKDIR"]

with open(path + "/lookup_plugins/malnet/dnifconfig.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)
    hdr = {'Authorization': 'Token {}'.format(cfg['lookup_plugin']['MALNET_API_KEY']) ,
           'Content-Type': 'application/json' }


def get_domain_events(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/events'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               ssid=[]
               nsid=[]
               for s in json_response:
                   if s['source']==True:
                       ssid.append(s['sid'])
                   else:
                       nsid.append(s['sid'])
               if len(ssid)>0:
                   i['$MNSourceSid']=list(set(ssid))
               if len(nsid)>0:
                   i['$MNNotSourceSid']=list(set(nsid))
            except Exception:
                pass
            try:
                ssig=[]
                nsig=[]
                for si in json_response:
                    if si['source'] == True:
                        ssig.append(si['signature'])
                    else:
                        nsig.append(si['signature'])
                if len(ssig)>0:
                    i['$MNSourceSignature'] = list(set(ssig))
                if len(nsig)>0:
                    i['$MNNotSourceSignature'] = list(set(nsig))
            except Exception:
                pass
    return inward_array

def get_domain_geolocation(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/geoloc'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                city = []
                for s in json_response:
                    city.append(s['city'])
                i['$MNCity'] = city
            except Exception:
                pass
            try:
                cntry = []
                for s in json_response:
                    cntry.append(s['country'])
                i['$MNCountry'] = cntry
            except Exception:
                pass
            try:
                cntry_cd = []
                for s in json_response:
                    cntry_cd.append(s['country_code'])
                i['$MNCountryCode'] = cntry_cd
            except Exception:
                pass
            try:
                ip = []
                for s in json_response:
                    ip.append(s['ip'])
                i['$MNIP'] = ip
            except Exception:
                pass
            try:
                lat = []
                for s in json_response:
                    lat.append(s['latitude'])
                i['$MNLatitude'] = lat
            except Exception:
                pass
            try:
                lon = []
                for s in json_response:
                    lon.append(s['longitude'])
                i['$MNLongitude'] = lon
            except Exception:
                pass

    return inward_array



def get_domain_ips(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/ips'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               ip=[]
               for s in json_response:
                   ip.append(s['ip'])
               i['$MNIP']=list(set(ip))
            except Exception:
                pass
    return inward_array


def get_domain_nameservers(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/nameservers'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               ns=[]
               for s in json_response:
                   ns.append(s['server'])
               i['$MNNameServers']=list(set(ns))
            except Exception:
                pass
    return inward_array


def get_domain_reputation(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/reputation'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                catscore = []
                for s in json_response:
                    if s['category'] != []:
                        catscore.append(str(s['category']) + ':' + str(s['score']))
                if len(catscore) > 0:
                    i['$MNCategoryScores'] = list(set(catscore))
            except Exception:
                pass
    return inward_array


def get_domain_malwaresample(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/samples'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               malware=[]
               for s in json_response:
                   if s['source']!=[]:
                       malware.append(s['source'])
               if len(malware)>0:
                   i['$MNMd5']=list(set(malware))
            except Exception:
                pass
    return inward_array


def get_domain_urls(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/urls'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                url=[]
                url= json_response
                if len(url)>0:
                    i['$MNURL'] = list(set(url))
            except Exception:
                pass
    return inward_array


def get_domain_whois(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/domains/'+str(i[var_array[0]])+'/whois'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               i['$MNDomain']= json_response['domain']
            except Exception:
               pass
            try:
               i['$MNRegistrantCreated']=json_response['registrant']['created']
            except Exception:
                pass
            try:
               i['$MNRegistrantEmail']=json_response['registrant']['email']
            except Exception:
                pass
            try:
               i['$MNRegistrantExpires']=json_response['registrant']['expires']
            except Exception:
                pass
            try:
               i['$MNRegistrantName']=json_response['registrant']['name']
            except Exception:
                pass
            try:
               i['$MNRegistrantUpdated']=json_response['registrant']['updated']
            except Exception:
                pass
            try:
               i['$MNRegistrarName']=json_response['registrar']['name']
            except Exception:
                pass
            try:
               i['$MNRegistrarCountry']=json_response['registrar']['country']
            except Exception:
                pass
            try:
               i['$MNRegistrarWebsite']=json_response['registrar']['website']
            except Exception:
                pass
    return inward_array


def get_ip_domains(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/domains'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               sdom=[]
               for s in json_response:
                   sdom.append(s['domain'])
               i['$MNDomain']=list(set(sdom))
            except Exception:
                pass
    return inward_array


def get_ip_events(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/events'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               ssid=[]
               nsid=[]
               for s in json_response:
                   if s['source']==True:
                       ssid.append(s['sid'])
                   else:
                       nsid.append(s['sid'])
               if len(ssid) > 0:
                   i['$MNSourceSid'] = list(set(ssid))
               if len(nsid) > 0:
                   i['$MNNotSourceSid'] = list(set(nsid))
            except Exception:
                pass
            try:
                ssig=[]
                nsig=[]
                for si in json_response:
                    if si['source'] == True:
                        ssig.append(si['signature'])
                    else:
                        nsig.append(si['signature'])
                if len(ssig) > 0:
                    i['$MNSourceSignature'] = list(set(ssig))
                if len(nsig) > 0:
                    i['$MNNotSourceSignature'] = list(set(nsig))
            except Exception:
                pass
    return inward_array

def get_ip_geolocation(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/geoloc'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               city=[]
               for s in json_response:
                   city.append(s['city'])
               i['$MNCity']=city
            except Exception:
                pass
            try:
                cntry = []
                for s in json_response:
                    cntry.append(s['country'])
                i['$MNCountry'] = cntry
            except Exception:
                pass
            try:
                cntry_cd = []
                for s in json_response:
                    cntry_cd.append(s['country_code'])
                i['$MNCountryCode'] = cntry_cd
            except Exception:
                pass
            try:
                ip = []
                for s in json_response:
                    ip.append(s['ip'])
                i['$MNIP'] = ip
            except Exception:
                pass
            try:
                lat = []
                for s in json_response:
                    lat.append(s['latitude'])
                i['$MNLatitude'] = lat
            except Exception:
                pass
            try:
                lon = []
                for s in json_response:
                    lon.append(s['longitude'])
                i['$MNLongitude'] = lon
            except Exception:
                pass
    return inward_array


def get_ip_reputation(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/reputation'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               catscore=[]
               for s in json_response:
                   if s['category']!=[]:
                       catscore.append(str(s['category'])+':'+str(s['score']))
               if len(catscore)>0:
                   i['$MNCategoryScores']=list(set(catscore))
            except Exception:
                pass
    return inward_array


def get_ip_malwaresample(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/samples'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               malware=[]
               for s in json_response:
                   if s['source']!=[]:
                       malware.append(s['source'])
               if len(malware)>0:
                   i['$MNMd5']=list(set(malware))
            except Exception:
                pass
    return inward_array


def get_ip_urls(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/urls'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                url=[]
                url= json_response
                if len(url)>0:
                    i['$MNURL'] = list(set(url))
            except Exception:
                pass
    return inward_array


def get_ip_urls(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/urls'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                url=[]
                url= json_response
                if len(url)>0:
                    i['$MNURL'] = list(set(url))
            except Exception:
                pass
    return inward_array


def get_ip_urls(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/ips/'+str(i[var_array[0]])+'/urls'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                url=[]
                url= json_response
                if len(url)>0:
                    i['$MNURL'] = list(set(url))
            except Exception:
                pass
    return inward_array


def get_malware_connections(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/samples/'+str(i[var_array[0]])+'/connections'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                url=[]
                url= json_response
                if len(url)>0:
                    i['$MNURL'] = list(set(url))
            except Exception:
                pass
    return inward_array


def get_hash_dns(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/samples/'+str(i[var_array[0]])+'/dns'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                addr=[]
                dom=[]
                dnsresdom=[]
                dnsqres=[]
                for dt in json_response:
                    if dt['record_type']=="A":
                        addr.append(dt['address'])
                        dom.append(dt['domain'])
                    else:
                        dnsqres.append(dt['answer'])
                        dnsresdom.append(dt['domain'])
                i['$MNDnsResponseIP']=list(set(addr))
                i['$MNDnsResponseDomain']= list(set(dom))
                i['$MNDnsResponseQuery']=list(set(dnsqres))
                i['$MNDnsResponseQueryDomain']=list(set(dnsresdom))
            except Exception:
                pass
    return inward_array


def get_hash_events(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/samples/'+str(i[var_array[0]])+'/events'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                sid=[]
                sig=[]
                for dt in json_response:
                    sid.append(dt['sid'])
                    sig.append(dt['signature_name'])
                i['$MNSid']=list(set(sid))
                i['$MNSignatures']= list(set(sig))
            except Exception:
                pass
    return inward_array


def get_hash_samples(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/samples/'+str(i[var_array[0]])
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$MNFileSize']=json_response['file_size']
                i['$MNFileType']=json_response['file_type']
                i['$MNMd5']=json_response['md5sum']
                i['$MNSubmitDate']=json_response['submit_date']
            except Exception:
                pass
    return inward_array


def get_hash_samples(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/samples/'+str(i[var_array[0]])
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$MNFileSize']=json_response['file_size']
                i['$MNFileType']=json_response['file_type']
                i['$MNMd5']=json_response['md5sum']
                i['$MNSubmitDate']=json_response['submit_date']
            except Exception:
                pass
    return inward_array


def get_hash_samples_http(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/samples/'+str(i[var_array[0]])+'/http'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$MNFileSize']=json_response['file_size']
                i['$MNFileType']=json_response['file_type']
                i['$MNMd5']=json_response['md5sum']
                i['$MNSubmitDate']=json_response['submit_date']
            except Exception:
                pass
    return inward_array


def get_repcategories(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/repcategories'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
               repcat=[]
               for repcat in json_response:
                   repcat.append(str(repcat['name'])+' : '+str(repcat['description']))
               i['$MNReputationCategories']=repcat
            except Exception:
                pass
    return inward_array,json_response


def get_domain_by_sid(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/sids/'+str(i[var_array[0]])+'/domains'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                dom=[]
                for dm in json_response:
                    dom.append(dm['domain'])
                i['$MNDomains']=list(set(dom))
            except Exception:
                pass
    return inward_array


def get_by_sid(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/sids/'+str(i[var_array[0]])
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$MNDescription']=json_response['description']
            except Exception:
                pass
            try:
                i['$MNImpact'] = json_response['impact']
            except Exception:
                pass
            try:
                i['$MNReferenceURLs']=json_response['reference_urls']
            except Exception:
                pass
            try:
                i['$MNSid']=json_response['sid']
            except Exception:
                pass
            try:
                i['$MNSignatureName']=json_response['sig_name']
            except Exception:
                pass
            try:
                i['$MNSnortText']=json_response['snort_text']
            except Exception:
                pass
            try:
                i['$MNSummary']=json_response['summary']
            except Exception:
                pass
            try:
                i['$MNSuricataText']=json_response['suricata_text']
            except Exception:
                pass
    return inward_array


def get_ip_by_sid(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/sids/'+str(i[var_array[0]])+'/ips'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                ips=[]
                for cip in json_response:
                    ips.append(cip['ip'])
                i['$MNIP']=list(set(ips))
            except Exception:
                pass
    return inward_array


def get_hash_by_sid(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://api.malnet.shadowdragon.io/sids/'+str(i[var_array[0]])+'/samples'
            try:
                res = requests.get(params,headers=hdr)
                json_response = res.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                hash=[]
                for hs in json_response:
                    hash.append(hs['source'])
                i['$MNHashes']=list(set(hash))
            except Exception:
                pass
    return inward_array
