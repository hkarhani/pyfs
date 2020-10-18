#!/usr/bin/env python
import os
import sys
import re
import pandas as pd

import yaml
import json
import requests 
import datetime as dt 

import shutil

FSAPI_API_VERSION = "2.0"

def gethref(x):
    """Extracts href from _links field"""
    return x['self']['href']

def gettemplated(x):
    """Extracts templated from _links field"""
    return x['self']['templated']

class pyFS(object):
    """ForeScout WebAPI / DEX Web Services wrapper Class:
    Attributes:
        fsConfigFile: default is 'fsconfig.yml' file 
        Config file should Contain IP, WebAPI User / Pass, DEX Web Services Account User / Pass.
    """

    def __init__(self, fsConfigFile = 'fsconfig.yml'):
        """Initializes pyFS object with ip and credentials provided for both web-api and DEX web-services."""      
        try: 
            stream = open(fsConfigFile, "r")
            docs = yaml.load_all(stream, Loader=yaml.SafeLoader)
            
            for doc in docs:
                for k,v in doc.items():
                    if k.find('counterActIP')!=-1:
                        self.counterAct = v
                    if k.find('Web-API')!=-1:
                        self.user= v['User']
                        self.password= v['Password']
                    if k.find('DEX')!= -1:
                        self.DEXuser= v['User']
                        self.DEXpassword= v['Password']
            stream.close()
            self.baseAPI = 'https://%s/api'% self.counterAct 
            self.loginURL = '%s/login'% self.baseAPI
            self.loggedin = False
        
        except IOError as e:
            print(e)    
        except:
            print("Error Loading Yaml file! Failed")    
        
        self.cacheLogin = dt.timedelta(minutes=5)
        self.cacheTime1 = dt.timedelta(hours=1)
        self.cacheTime2 = dt.timedelta(hours=24)
        self.hostfields = None 
        self.endpoints = {}
        self.hosts = []
    
    def login(self):
        """Login to CounterACT WebAPIs while relogin automatically if needed."""
        if self.loggedin: 
            if (dt.datetime.now() - self.lastLogin) < self.cacheLogin:
                # No need to relogin during the previous cached Login (<5mins) 
                return True 
            
        r = requests.post(self.loginURL, {"username": self.user, "password": self.password}, verify=False)
        if r.status_code == 200: 
            # Login Successful - populate Authorization Header
            auth = r.content
            self.headers = {'Authorization': auth}
            self.lastLogin = dt.datetime.now()
            self.loggedin = True 
            return True
        else:
            # Error while logging in
            self.loggedin = False
            return False
        
    def postDEX(self, epip, _property, _value, debug=False): 
        """Posts via auth (result of initDEX) to CounterACT for Endpoint IP: 
            epip, using property: _property and value: _value."""
        
        postURL = "https://%s/fsapi/niCore/Hosts" % self.counterAct
        
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        
        post_data = """<?xml version='1.0' encoding='utf-8'?>
        <FSAPI TYPE="request" API_VERSION="%s">
          <TRANSACTION TYPE="update">
            <OPTIONS CREATE_NEW_HOST="true"/>
            <HOST_KEY NAME="ip" VALUE="%s"/>
            <PROPERTIES>
              <PROPERTY NAME="%s">
                <VALUE>%s</VALUE>
              </PROPERTY>
            </PROPERTIES>
          </TRANSACTION>
        </FSAPI>
        """ %(FSAPI_API_VERSION, epip, _property, _value)
        
        r = requests.post(postURL, headers=headers, auth=(self.DEXuser, self.DEXpassword), data=post_data, verify=False)
        
        if debug: 
            print(f"URL: {postURL}")
            print(f"Headers: {headers}")
            print(f"POST Data: {post_data}")
            print(f"Response: {r}")
            
        return r.status_code == 200, r.content.decode('utf-8')

    def postCDEX(self, epip, _property, _Obj, debug=False): 
        """Posts via auth (result of initDEX) to CounterACT for Endpoint IP: epip, using Composite property: _property and object: _Obj"""
        postURL = "https://%s/fsapi/niCore/Hosts" % self.counterAct
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        post_data_header = """<?xml version='1.0' encoding='utf-8'?>
        <FSAPI TYPE="request" API_VERSION="%s">
          <TRANSACTION TYPE="update">
            <OPTIONS CREATE_NEW_HOST="true"/>
            <HOST_KEY NAME="ip" VALUE="%s"/>
            <PROPERTIES>
              <TABLE_PROPERTY NAME="%s">
                <ROW>
        """ %(FSAPI_API_VERSION, epip, _property)
        
        post_data_footer = """
                  </ROW>
                </TABLE_PROPERTY> 
            </PROPERTIES>
          </TRANSACTION>
        </FSAPI>
        """

        post_data_cprop = ""; 
        for k,v in _Obj.items(): 
            post_data_cprop += """
                    <CPROPERTY NAME="%s"> 
                        <CVALUE>%s</CVALUE>
                    </CPROPERTY> 
                 
            """ %(k, v)

        post_data = post_data_header + post_data_cprop + post_data_footer
        r = requests.post(postURL, headers=headers,auth=(self.DEXuser, self.DEXpassword), data=post_data, verify=False)
        
        if debug: 
            print(f"URL: {postURL}")
            print(f"Headers: {headers}")
            print(f"POST Data: {post_data}")
            print(f"Response: {r}")
            
        return r.status_code == 200, r.content.decode('utf-8')
    
    def deleteDEX(self, epip, _property): 
        """Deletes a property from CounterACT for CounterACT for Endpoint IP: epip, using property: _property"""
        postURL = "https://%s/fsapi/niCore/Hosts" % self.counterAct
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        endpointip = '10.0.2.51'
        post_data = """<?xml version='1.0' encoding='utf-8'?>
        <FSAPI TYPE="request" API_VERSION="%s">
            <TRANSACTION TYPE="delete">
                <HOST_KEY NAME="ip" VALUE="%s"/>
                <PROPERTIES>
                    <PROPERTY NAME="%s" />
                </PROPERTIES>
            </TRANSACTION>
        </FSAPI>
        """ %(FSAPI_API_VERSION, epip, _property)
        r = requests.post(postURL, headers=headers,auth=(self.DEXuser, self.DEXpassword), data=post_data, verify=False)
        return r.status_code == 200, r.content.decode('utf-8')

    def deleteCDEX(self, epip, _property): 
        """Deletes Composite property from CounterACT for Endpoint IP: epip, using comp property: _property"""
        postURL = "https://%s/fsapi/niCore/Hosts" % self.counterAct
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        endpointip = '10.0.2.51'
        post_data = """<?xml version='1.0' encoding='utf-8'?>
        <FSAPI TYPE="request" API_VERSION="%s">
            <TRANSACTION TYPE="delete">
                <HOST_KEY NAME="ip" VALUE="%s"/>
                <PROPERTIES>
                    <TABLE_PROPERTY NAME="%s" />
                </PROPERTIES>
            </TRANSACTION>
        </FSAPI>
        """ %(FSAPI_API_VERSION, epip, _property)
        r = requests.post(postURL, headers=headers,auth=(self.DEXuser, self.DEXpassword), data=post_data, verify=False)
        return r.status_code == 200, r.content.decode('utf-8')
                                
    def addListValues(self, listName, value):
        if type(value) == type([]):
            _newValue = value
        else: 
            _newValue = [value]
         
        data_header ="""<?xml version='1.0' encoding='utf-8'?>
                <FSAPI API_VERSION="%s" TYPE="request">
                    <TRANSACTION TYPE="add_list_values">
                        <LISTS>
                            <LIST NAME="%s">""" % (FSAPI_API_VERSION, listName)
        
        data_footer = """</LIST>
                        </LISTS>
                    </TRANSACTION>
                </FSAPI>"""
        
        dataValues = ""
        
        for _val in _newValue: 
            dataValues += "<VALUE>%s</VALUE>" % (_val)
        
        post_data = data_header + dataValues + data_footer 
        
        postURL = "https://%s/fsapi/niCore/Lists" % self.counterAct
        headers = {'Content-Type': 'application/xml'}

        r = requests.post(postURL, headers=headers, auth=(self.DEXuser, self.DEXpassword), 
                              data=post_data, verify=False)
        
        return r.status_code == 200, r.content.decode('utf-8')
    
    def deleteListValues(self, listName, value):
        if type(value) == type([]):
            _newValue = value
        else: 
            _newValue = [value]
         
        data_header ="""<?xml version='1.0' encoding='utf-8'?>
                <FSAPI API_VERSION="%s" TYPE="request">
                    <TRANSACTION TYPE="delete_list_values">
                        <LISTS>
                            <LIST NAME="%s">""" % (FSAPI_API_VERSION, listName)
        
        data_footer = """</LIST>
                        </LISTS>
                    </TRANSACTION>
                </FSAPI>"""
        
        dataValues = ""
        
        for _val in _newValue: 
            dataValues += "<VALUE>%s</VALUE>" % (_val)
        
        post_data = data_header + dataValues + data_footer 
        
        postURL = "https://%s/fsapi/niCore/Lists" % self.counterAct
        headers = {'Content-Type': 'application/xml'}

        r = requests.post(postURL, headers=headers, auth=(self.DEXuser, self.DEXpassword), 
                              data=post_data, verify=False)
        
        return r.status_code == 200, r.content.decode('utf-8')
    
    def deleteAllListValues(self, listName):
         
        data_header ="""<?xml version='1.0' encoding='utf-8'?>
                <FSAPI API_VERSION="%s" TYPE="request">
                    <TRANSACTION TYPE="delete_all_list_values">
                        <LISTS>
                            <LIST NAME="%s">""" % (FSAPI_API_VERSION, listName)
        
        data_footer = """</LIST>
                        </LISTS>
                    </TRANSACTION>
                </FSAPI>"""
        
        post_data = data_header + data_footer 
        
        postURL = "https://%s/fsapi/niCore/Lists" % self.counterAct
        headers = {'Content-Type': 'application/xml'}

        r = requests.post(postURL, headers=headers, auth=(self.DEXuser, self.DEXpassword), 
                              data=post_data, verify=False)
        
        return r.status_code == 200, r.content.decode('utf-8')
    
    def getAllHostFields(self): 
        """Retrieves full list of hostfields from CounterACT webAPI."""
        if self.login(): 
            req = '%s/hostfields'% self.baseAPI
            resp = requests.get(req, headers=self.headers, verify=False)
            if resp.status_code == 200: 
                jresp = json.loads(resp.content.decode('utf-8'))
                self.hostfields = jresp[u'hostFields']
                self.hostfieldsTimeStamp = dt.datetime.now()
                return self.hostfields
            else: 
                return None 
        else: 
            return None 
    
    def generateHF(self, _format = 'json'):
        """Generates All HostFields as _format - default _format is json - Other options: csv, syslog (future: sql) """
        if _format == 'json': 
            return self.hostfields
        elif _format == 'csv':
            _header = 'name,label,type,description\n'
            _content = ''
            for hf in self.hostfields: 
                _content+='%s,%s,%s,%s\n' % (hf['name'], hf['label'], hf['type'], hf['description'])
            return _header + _content     
            
            
    
    def getHosts(self): 
        """Retrieves list of active hosts from Forescout webAPI and returns a pandas DataFrame."""
        
        if self.login(): 
            req = '%s/hosts'% self.baseAPI
            resp = requests.get(req, headers=self.headers, verify=False)
            if resp.status_code == 200: 
                #print(resp.content)
                jresp = json.loads(resp.content.decode('utf-8'))
                hosts = jresp[u'hosts']
                self.hostsTimeStamp = dt.datetime.now()
                # convert to Pandas
                self.hostsdf = pd.DataFrame(hosts)
                self.hosts = hosts
                self.hostsdf['href'] = self.hostsdf["_links"].apply(gethref)
                self.hostsdf['templated'] = self.hostsdf["_links"].apply(gettemplated)
                self.hostsdf.drop('_links', inplace=True, axis=1)
                return self.hostsdf 
            else: 
                return None 
        else: 
            return None 
    
    def checkHostField(self, prop):
        hfDF = self.getHFdf()
        
        if prop in hfDF['name'].values:
            return True 
        else: 
            return False
            
        
    def gethostsByProp(self, prop, val): 
        """Retrieves list of hosts with prop value equal to val from CounterACT webAPI."""
        if self.login(): 
            if self.checkHostField(prop):     
                req = '%s/hosts?%s=%s'% (self.baseAPI, prop, val)
                resp = requests.get(req, headers=self.headers, verify=False)
                if resp.status_code == 200: 
                    #print(resp.content)
                    jresp = json.loads(resp.content.decode('utf-8'))
                    hosts = jresp[u'hosts']
                    hostsdf = pd.DataFrame(hosts)
                    hostsdf['href'] = hostsdf["_links"].apply(gethref)
                    hostsdf['templated'] = hostsdf["_links"].apply(gettemplated)
                    hostsdf.drop('_links', inplace=True, axis=1)
                    return hostsdf  
                else: 
                    print("Error Return Status Code != 200.")
                    return False
            else:
                print(f"Error Property '{prop}' does not exist in Hostfields.")
                return False
        else: 
            print("Unable to Login!")
            return False 
        
    def gethostsByRules(self, rulesList): 
        """Retrieves list of hosts matching ruleIDs from CounterACT webAPI."""
        if self.login(): 
            req = '%s/hosts'% self.baseAPI
            req +='?matchRuleId=%s' %rulesList[0]
            if len(rulesList)>1: 
                for ruleId in rulesList[1:len(rulesList)]:
                    req +=',%s' % ruleId
                return req
            
            resp = requests.get(req, headers=self.headers, verify=False)
            if resp.status_code == 200: 
                jresp = json.loads(resp.content.decode('utf-8'))
                return jresp[u'hosts'] 
            else: 
                return None 
        else: 
            return None
        
    def getPolicies(self): 
        """Retrieves list of policies from CounterACT webAPI."""
        if self.login(): 
            req = '%s/policies'% self.baseAPI
            resp = requests.get(req, headers=self.headers, verify=False)
            if resp.status_code == 200: 
                jresp = json.loads(resp.content.decode('utf-8'))
                self.policies = jresp[u'policies']
                self.policiesTimeStamp = dt.datetime.now()
                return self.policies 
            else: 
                return False 
        else: 
            return False
    
    def getPolicyId(self, policyName):
        for pol in self.policies: 
            if pol[u'name'].find(policyName)!= -1: 
                return pol[u'policyId']
        return None
    
    def getRules(self, policyID):
        for pol in self.policies: 
            if pol[u'policyId'] == policyID: 
                return pol[u'rules']
        return None
    
    def getRuleId(self, ruleName, policyRules):
        for rule in policyRules:
            if rule[u'name'].find(ruleName) != -1: 
                return rule[u'ruleId']
        return None

    def gethostIDbyIP(self, hostip):
        """Retrieves hostID from CounterACT webAPI based on host IP."""
        if len(self.hosts) == 0: 
            self.getHosts()
        _ret = self.hostsdf[self.hostsdf['ip']==hostip]
        if len(_ret) == 1: 
            return _ret.hostId.values[0] 
        else: 
            return None
        return None 
    
    def gethostIDbyMAC(self, hostmac):
        """Retrieves hostID from CounterACT webAPI based on host MAC Address."""
        if len(self.hosts) == 0: 
            self.getHosts() 
        _ret = self.hostsdf[self.hostsdf['mac']==hostmac]
        if len(_ret) == 1: 
            return _ret.hostId.values[0] 
        else: 
            return None
        return None 
        
    def getHostByID(self, hostid): 
        """Retrieves host properties from CounterACT webAPI by hostID."""
        if self.login(): 
            req = '%s/hosts/%s'% (self.baseAPI, hostid)
            resp = requests.get(req, headers=self.headers, verify=False)
            if resp.status_code == 200: 
                jresp = json.loads(resp.content.decode('utf-8'))
                #self.hostsTimeStamp = dt.datetime.now()
                return True, jresp[u'host']
            else: 
                return False, None  
        else: 
            return False, None  
    
    def getHostByIP(self, hostip): 
        """Retrieves host properties from CounterACT webAPI by hostip."""
        if self.login(): 
            hostid = self.gethostIDbyIP(hostip)
            if hostid: 
                req = '%s/hosts/%s'% (self.baseAPI, hostid)
                resp = requests.get(req, headers=self.headers, verify=False)
                if resp.status_code == 200: 
                    jresp = json.loads(resp.content.decode('utf-8'))
                    #self.hostsTimeStamp = dt.datetime.now()
                    return True, jresp[u'host']
                else: 
                    return False, None
            else: 
                return False, None
        else: 
            return False, None
    
    def nameFix(self, _name, fixName = True, debug=False):
        if not fixName: 
            return _name 
        
        specialCharacters = ['.','-', ' ']
        _nameFix = _name
        for _char in specialCharacters:        
            if _name.find(_char) != -1: 
                _nameFix = _nameFix.replace(_char, "_")
        if debug: 
            if not re.match(r'^[\d\_\w]+$', _nameFix):
                print(_nameFix)
        return _nameFix
    
    def getHFdf(self): 
        if not self.hostfields:    
            self.getAllHostFields()
        df = pd.DataFrame(self.hostfields)
        df.drop('_links', axis=1, inplace=True)
        return df
    
    def getHFfilter(self, _filter=None, useLabel=False, useDescription=False):
        df = self.getHFdf()
        if not _filter: 
            return df 
        else: 
            if not useLabel and not useDescription: 
                return df[df['name'].str.contains(_filter, case=False)]
            ndf = df.dropna()
            df1 = ndf['name'].str.contains(_filter, case=False)
            df2 = ndf['label'].str.contains(_filter, case=False)
            df3 = ndf['description'].str.contains(_filter, case=False)
            return ndf[df1 | (useLabel & df2) | (useDescription & df3)]
    
    def matchHF(self, _filter):
        df = self.getHFdf()
        seldf = df[df['name']==_filter]
        if len(seldf) == 1: 
            return seldf.iloc[0]
        else: 
            return None 
    
    def describeProps(self, props):
        dfProps = pd.DataFrame()
        for prop in list(props['fields'].keys()):
            dfProps = dfProps.append(self.matchHF(prop))
        return dfProps
    
    def detailProps(self, props):
        hostDF = pd.DataFrame()
        if 'fields' not in list(props.keys()):
            print("Not a valid Properties object! no fields key!")
            return None 
        
        fields = props['fields']
        for prop in list(fields.keys()): 
            propDF = self.matchHF(prop)
            if self.getHFtype(prop) == 'string':
                if type(fields[prop]) == type([]):
                    for subProp in fields[prop]:
                        if type(subProp) == type({}):
                            instancePropDF = propDF.copy()
                            instancePropDF['timestamp'] = subProp['timestamp']
                            instancePropDF['value'] = subProp['value']
                            hostDF = hostDF.append(instancePropDF)
                elif type(fields[prop]) == type({}):
                    propDF['timestamp'] = fields[prop]['timestamp']
                    propDF['value'] = fields[prop]['value']
                    hostDF = hostDF.append(propDF)
            else: 
                if type(fields[prop]) == type({}):
                    propDF['timestamp'] = fields[prop]['timestamp']
                    propDF['value'] = fields[prop]['value']
                    hostDF = hostDF.append(propDF)
        
        return hostDF

    
    def getHFtype(self, _filter):
        df = self.getHFdf()
        seldf = df[df['name']==_filter]
        if len(seldf) == 1: 
            return seldf['type'].iloc[0]
        else: 
            print(f"field Name: {_filter} not found!")
            return ""
    
    def getHFlabel(self, _filter):
        df = self.getHFdf()
        seldf = df[df['name']==_filter]
        if len(seldf) == 1: 
            return seldf['label'].iloc[0]
        else: 
            print(f"field Name: {_filter} not found!")
            return ""
        
    def getHFdescription(self, _filter):
        df = self.getHFdf()
        seldf = df[df['name']==_filter]
        if len(seldf) == 1: 
            return seldf['description'].iloc[0]
        else: 
            print(f"field Name: {_filter} not found!")
            return ""
        
    def getHFAVP(self, _filter = None, fixName = True, useLabel=False, useDescription=False, usedf= False, debug=False):
        df = self.getHFdf()
        obj = {}
        if not _filter: 
            for _name in df['name']:
                obj[self.nameFix(_name, fixName)] = '{%s}'%_name
        else:
            _dfFiltered = df[df['name'].str.contains(_filter, case=False)]
            if len(_dfFiltered)!= 0: 
                for _name in _dfFiltered['name']: 
                    obj[self.nameFix(_name, fixName)] = '{%s}'%_name
            if debug: 
                print(f'Object Length: {len(obj)} - with filtered Data on name')
            if useLabel: 
                ndf = df.dropna()
                _dfFiltered = ndf[ndf['label'].str.contains(_filter, case=False)]
                if len(_dfFiltered) != 0: 
                    for _name in _dfFiltered['name']:
                        obj[self.nameFix(_name, fixName)] = '{%s}'%_name
                    if debug: 
                        print(f'Object Length: {len(obj.keys())} - with filtered Data on Label')
            if useDescription: 
                ndf = df.dropna()
                _dfFiltered = ndf[ndf['description'].str.contains(_filter, case=False)]
                if len(_dfFiltered) !=0: 
                    for _name in _dfFiltered['name']:
                        obj[self.nameFix(_name, fixName)] = '{%s}'%_name  
                    if debug: 
                        print(f'Object Length: {len(obj.keys())} - with filtered Data on Description')
        if not usedf: 
            return obj
        else: 
            cObj = {'key': list(obj.keys()), 'value':[v for k,v in obj.items()]}
            return pd.DataFrame(cObj)

    def getHostByMAC(self, hostmac): 
        """Retrieves host properties from CounterACT webAPI by hostmac."""
        if self.login(): 
            hostid = self.gethostIDbyMAC(hostmac)
            if hostid: 
                req = '%s/hosts/%s'% (self.baseAPI, hostid)
                resp = requests.get(req, headers=self.headers, verify=False)
                if resp.status_code == 200: 
                    jresp = json.loads(resp.content.decode('utf-8'))
                    #self.hostsTimeStamp = dt.datetime.now()
                    return True, jresp[u'host']
                else: 
                    return False, None
            else: 
                return False, None
        else: 
            return False, None
    
    def getHost(self, ip=None, mac=None, hostId=None):
        """Retrieve Host Properties by: ip, mac or hostId. Eliminates the usage of individual functions"""
        if not ip and not mac and not hostId:
            print("Either ip, mac of hostId are needed to get Host details..")
            return None 
        if hostId: 
            result, props = self.getHostByID(hostId)
        elif mac: 
            result, props = self.getHostByMAC(mac)
        elif ip: 
            result, props = self.getHostByIP(ip)

        if result: 
            hostDF = self.detailProps(props)
            return hostDF
        else: 
            print("Error in retreiving host information..")
            return None 