## MalNet
  https://shadowdragon.io/product/malnet/
  
### Overview
Malware prevention requires analysis and mitigation of a complex combination of botnets, proxies, attack vectors, and command and control systems. Identifying and analyzing artifacts quickly is important for malware security, criminal investigations and to “stop the bleeding” with an attack in progress.

MalNet brings together the industry’s most extensive malware threat information from Proofpoint ET Intelligence to expedite investigations, response, and malware protection
 
##### Lookups integrated with MalNet

##### Retrieve domain related IDS events   
This endpoint retrieves the most recent IDS events that have been observed against the specified domain
- input : Domain to be queried.
```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_events $Domain
```
###### Sample Output 
![malnet_eventsfordomain](https://user-images.githubusercontent.com/37173181/39245269-e1fbbf84-48b0-11e8-9dae-ad5c03f501f4.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $MNSourceSid      | The SID that generated the IDS event for which the queried domain is source |
| $MNSourceSignature      | The signature name of the SID that generated the IDS event for which the queried domain is source |
| $MNNotSourceSid | The SID that generated the IDS event for which the queried domain is not source |
| $MNNotSourceSignature | The signature name of the SID that generated the IDS event for which the queried domain is not source |


#####  Retrieve domain geolocation information
This endpoint retrieves the geolocation details for the specified domain
- input : Domain to be queried.

```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_geolocation $Domain
```
##### Sample Output 
![malnet_domaingeoloc](https://user-images.githubusercontent.com/37173181/39246128-48de5c82-48b3-11e8-9f28-ccdaf38ece5d.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNIP     | An IP associated with the specified domain |
| $MNCountryCode | The two character ISO 3166-1 alpha-2 country code in which the IP was last observed |
| $MNCountry |The country in which the IP was last observed |
| $MNRegion |  A two character ISO-3166-2 or FIPS 10-4 code for the state or region associated with the IP |
| $MNCity |  The city or town name associated with the IP |
| $MNLatitude | The latitude associated with the IP |
| $MNLongitude  |The longitude associated with the IP |
 
##### Retrieve domain related IPs
This endpoint retrieves the most recent IPs that have been associated with the specified domain.
- input : Domain to be queried.

```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_ips $Domain
```
##### Sample Output 
![malnet_ipsfordomain](https://user-images.githubusercontent.com/37173181/39240566-c5eb3f18-48a1-11e8-81dc-e5d0453ea4f7.jpg)

The Lookup call returns output in the following structure for available data  

 | Fields        | Description  |
|:------------- |:-------------|
| $MNIP      | List of IPs that have been associated with the specified domain |

#####  Retrieve domain nameservers information  
This endpoint retrieves the nameserver information related to the specified domain
- input : Domain to be queried
```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_nameservers $Domain
```
##### Sample Output 
![malnet_nameserversfordomain](https://user-images.githubusercontent.com/37173181/39240619-f56d4632-48a1-11e8-82b6-dfe4d66c0205.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNNameServers  | The address of a nameserver associated with the domain |

#####  Retrieve current domain reputation  
This endpoint retrieves the current reputation scores in categories that are currently associated with the specified domain.
- input : Domain to be queried
```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_reputation $Domain
```
##### Sample Output 
![malnet_domainreputation](https://user-images.githubusercontent.com/37173181/39240671-1dd2a810-48a2-11e8-9e95-b75e93beaf43.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNCategoryScores  | The current reputation scores in categories that are currently associated with the specified domain |


#####  Retrieve malware samples for domain
  
This endpoint retrieves the most recent malware samples that communicated with the specified domain.
- input : Domain to be queried
```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_malwaresample $Domain
```
##### Sample Output 
![malnet_malwarehashfordomain](https://user-images.githubusercontent.com/37173181/39240801-79c2ed1a-48a2-11e8-81aa-0d2abfdfb47c.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNMd5  | The md5sum of the malware sample |

#####  Retrieve  domain malware requested URLs
  
This endpoint retrieves the most recent HTTP requests made by malware to the specified domain.
- input : Domain to be queried
```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_urls $Domain
```
##### Sample Output 
![malnet_urlsfordomain](https://user-images.githubusercontent.com/37173181/39240865-b2d6400c-48a2-11e8-80c0-084020dcde6f.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNURL  | The url string of the request with query parameter  |

#####  Retrieve domain whois information
This endpoint retrieves whois info for a single domain
- input : Domain to be queried.

```
_fetch $Domain from threatsample limit 1
>>_lookup malnet get_domain_whois $Domain
```
##### Sample Output 
![malnet_domainwhois](https://user-images.githubusercontent.com/37173181/39240937-eb2a8ab2-48a2-11e8-8138-1e9a470dca70.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNDomain     | The domain associated with the whois record. |
| $MNRegistrantCreated | Date the whois record was originally created. |
| $MNRegistrantEmail |Email address of the domain registrant |
| $MNRegistrantExpires |  Date the whois record will expire. |
| $MNRegistrantName |  Name of the domain registrant. |
| $MNRegistrantUpdated | Date the whois record was last updated |
| $MNLongitude  |The longitude associated with the IP |
| $MNRegistrarName | Name of the domain registrar |
| $MNRegistrarCountry | Home country of the domain registrar |
| $MNRegistrarWebsite |  Homepage for the domain registrar |


#####  Retrieve IP related domains  
This endpoint retrieves the most recent domains that have been associated with the specified IP.
- input : IP address to be queried
```
_fetch $SrcIP from threatsample limit 1
>>_lookup malnet get_ip_domains $SrcIP
```
##### Sample Output 
![malnet_domainsforip](https://user-images.githubusercontent.com/37173181/39241089-61ce8d6c-48a3-11e8-9661-dc29da41619a.jpg)

The Lookup call returns output in the following structure for available data
 | Fields        | Description  |
|:------------- |:-------------|
| $MNDomain  | List of domains associated with the queried IP  |


##### Retrieve IP related IDS events   
The  endpoint retrieves the most recent IDS events that have been observed against the specified IP
- input : IP address to be queried
```
_fetch $SrcIP from threatsample  limit 1
>>_lookup malnet get_ip_events $SrcIP
```
###### Sample Output 

![malnet_geteventsforip](https://user-images.githubusercontent.com/37173181/39245175-92a9d074-48b0-11e8-8c9e-286309827b3d.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $MNSourceSid      | The SID that generated the IDS event for which the queried IP is source |
| $MNSourceSignature      | The signature name of the SID that generated the IDS event for which the queried IP is source |
| $MNNotSourceSid | The SID that generated the IDS event for which the queried IP is not source |
| $MNNotSourceSignature | The signature name of the SID that generated the IDS event for which the queried IP is not source |

#####  Retrieve IP geolocation information
The domain for which you want to retrieve the geolocation
- input : IP address to be queried.

```
_fetch $SrcIP from threatsample limit 1
>>_lookup malnet get_ip_geolocation $SrcIP
```

##### Sample Output 
![malnet_ipgeoloc](https://user-images.githubusercontent.com/37173181/39241168-997e03dc-48a3-11e8-987d-c5b09bc16fa7.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNIP     | An IP associated with the specified domain |
| $MNCountryCode | The two character ISO 3166-1 alpha-2 country code in which the IP was last observed |
| $MNCountry |The country in which the IP was last observed |
| $MNRegion |  A two character ISO-3166-2 or FIPS 10-4 code for the state or region associated with the IP |
| $MNCity |  The city or town name associated with the IP |
| $MNLatitude | The latitude associated with the IP |
| $MNLongitude  |The longitude associated with the IP |
 
#####  Retrieve current IP reputation 
This endpoint retrieves the current reputation scores in categories that are currently associated with the specified IP.
- input : IP address to be queried
```
_fetch $SrcIP from threatsample limit 1
>>_lookup malnet get_ip_reputation $SrcIP
```
##### Sample Output 
![malnet_ipreputation](https://user-images.githubusercontent.com/37173181/39245225-bba9c36c-48b0-11e8-8570-f6a84a1ade8e.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNCategoryScores  | The current reputation scores in categories that are currently associated with the specified IP address |

#####  Retrieve malware samples for IP  
This endpoint retrieves the most recent malware samples that communicated with the specified IP.
- input : IP address to be queried
```
_fetch $SrcIP from threatsample limit 1
>>_lookup malnet get_ip_malwaresample $SrcIP
```
##### Sample Output 
![malnet_malwareforip](https://user-images.githubusercontent.com/37173181/39241319-1a45bd02-48a4-11e8-9deb-63891418360f.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNMd5  | The md5sum of the malware sample |

#####  Retrieve IP malware requested URLs
  
This endpoint retrieves the most recent HTTP requests made by malware to the specified IP address.
- input : Domain to be queried
```
_fetch $SrcIP from threatsample limit 1
>>_lookup malnet get_ip_urls $SrcIP
```
##### Sample Output 
![malnet_urlsforip](https://user-images.githubusercontent.com/37173181/39241359-3623df72-48a4-11e8-99b5-806c5b7df109.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNURL  | The url string of the request with query parameter  |

#####  Retrieve hash sample DNS lookups  
This endpoint retrieves the most recent DNS lookups an individual malware sample was observed to have made.
- input : Only MD5 and SHA256 hashes are supported
```
_fetch $Filehash from threatsample limit 1
>>_lookup malnet get_hash_dns $Filehash
```
##### Sample Output 
![malnet_dnsforhashsample](https://user-images.githubusercontent.com/37173181/39241773-a1874122-48a5-11e8-838b-9b2b069ed4f4.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNDnsResponseIP  | If the DNS response was an A record pointing to an IP, this field will contain the IP in question  |
| $MNDnsResponseDomain | The domain whose DNS record was being queried |
| $MNDnsResponseQuery | If the DNS response was not an A record pointing to an IP, this field will contain the DNS query response (e.g. the CNAME) |
| $MNDnsResponseQueryDomain |  The domain whose DNS record was being queried |

#####  Retrieve hash sample IDS events  
This endpoint retrieves the most recent IDS events an individual malware sample was observed to have triggered.
- input : Only MD5 and SHA256 hashes are supported
```
_fetch $Filehash from threatsample limit 1
>>_lookup malnet get_hash_events $Filehash
```
##### Sample Output 
![malnet_eventsforhash](https://user-images.githubusercontent.com/37173181/39241838-d35115de-48a5-11e8-9eec-e54bba09a590.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNSid  | The SID associated with the event  |
| $MNSignatures | The name of the signature associated with this SID |

#####  Retrieve hash sample details
  This endpoint retrieves metadata information for a single malware sample.
- input : Only MD5 and SHA256 hashes are supported
```
_fetch $Filehash from threatsample limit 1
>>_lookup malnet get_hash_samples $Filehash
```
##### Sample Output 
![malnet_malwaresampleforhash](https://user-images.githubusercontent.com/37173181/39241901-fb0d371a-48a5-11e8-8b43-13c4b6e22c6e.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNFileSize  | The size of the binary in bytes  |
| $MNFileType| The file type |
| $MNMd5 | The MD5 hash of the binary |
| $MNSubmitDate | The date and time the malware was originally submitted to Emerging Threats |

#####  Retrieve domains related to a particular Signature (SID)  
This endpoint retrieves the domains related to a particular Signature (SID).
- input : SID
```
_fetch $SID from threatsample limit 1
>>_lookup malnet get_domain_by_sid $SID
```
##### Sample Output 
![malnet_domainsforsid](https://user-images.githubusercontent.com/37173181/39241946-1a0f8bb8-48a6-11e8-9671-dd98368b4221.jpg)
The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNDomains  | List of domains related to a particular Signature (SID) |

#####  Retrieve signature details related to a particular Signature (SID)  
This endpoint retrieves metadata information for a single SID.
- input : SID
```
_fetch $SID from threatsample limit 1
>>_lookup malnet get_by_sid $SID
```
##### Sample Output 
![malnet_siddetails](https://user-images.githubusercontent.com/37173181/39242013-3b1f84ac-48a6-11e8-9f86-da323973d3b7.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNDescription  | Detailed description of the exploit being caught. |
| $MNImpact | What kinds of systems does this impact. |
| $MNReferenceURLs | Reference details of the signature |
| $MNSid | Signature ID that reflects request. |
| $MNSignatureName | Name of the signature requested. |
| $MNSnortText | Example of rule for Snort 2.9 .|
| $MNSummary | Summary of the information this alert is trying to convey. |
| $MNSuricataText | Example of the rule for Suricata. |

#####  Retrieve IP addresses related to a particular Signature (SID)  
This endpoint retrieves the IPs related to a particular Signature (SID).
- input : SID
```
_fetch $SID from threatsample limit 1
>>_lookup malnet get_ip_by_sid $SID
```
##### Sample Output 
![malnet_ipforsid](https://user-images.githubusercontent.com/37173181/39242249-1278de6c-48a7-11e8-8ddf-3111b6d38a94.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNIP  | List of IP address related to a particular Signature (SID) |

#####  Retrieve malware samples related to a particular Signature (SID)  
This endpoint retrieves the most recent malware samples that communicated with the specified SID.

- input : SID
```
_fetch $SID from threatsample limit 1
>>_lookup malnet get_hash_by_sid $SID
```
##### Sample Output 
![malnet_hashbysid](https://user-images.githubusercontent.com/37173181/39242337-5669ccb2-48a7-11e8-93d6-334b26b6384b.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $MNHashes  | List of hash for malware samples that communicated with the specified SID |


### Using the MalNet API and DNIF  
The MalNet API is found on github at 

  https://github.com/dnif/lookup-malnet

#### Getting started with MalNet API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-malnet.git malnet
```
4. #####   Move to the ‘/dnif/<Deployment-key/lookup_plugins/malnet/’ folder path and open dnifconfig.yml configuration file     
    
   Replace the tag:<Add_your_api_key_here> with your MalNet API key
```
lookup_plugin:
   MALNET_API_KEY: <Add_your_api_key_here>

```
