#/usr/bin/env python
from bs4 import BeautifulSoup
import MySQLdb
import os
import sys
import paramiko
import json
import random
import requests
import json
import logging
import stripe
import string
import datetime, timedelta
import time
import re
import urllib
import smtplib
from email.mime.text import MIMEText
from pyzabbix import ZabbixAPI
unifi_site_list = 'a'
live_mode = True
log = logging.getLogger(__name__)
PYTHON_VERSION = sys.version_info[0]

pid = str(os.getpid())
pidfile = "/tmp/mydaemon.pid"

if os.path.isfile(pidfile):
    print "%s already exists, exiting" % pidfile
    sys.exit()

file(pidfile, 'w').write(pid)

def pw_gen(size=16, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
  return ''.join(random.choice(chars) for _ in range(size))

def user_gen(size=4, chars=string.ascii_lowercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

try:
    # Ugly hack to force SSLv3 and avoid
    # urllib2.URLError: <urlopen error [Errno 1] _ssl.c:504:
    # error:14077438:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert internal error>
    import _ssl
    _ssl.PROTOCOL_SSLv23 = _ssl.PROTOCOL_TLSv1
except:
    pass

try:
    # Updated for python certificate validation
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context
except:
    pass

import sys
PYTHON_VERSION = sys.version_info[0]

if PYTHON_VERSION == 2:
    import cookielib
    import urllib2
elif PYTHON_VERSION == 3:
    import http.cookiejar as cookielib
    import urllib3
    import ast

log = logging.getLogger(__name__)

class Cloudflare_DNS(object):
  def __init__(self, zone, email, api_key, dns_type, dns_name, content, delete_id):
    self.dns_type = dns_type
    self.dns_name = dns_name
    self.zone = zone
    self.email = email
    self.api_key = api_key
    self.content = content
    self.delete_id = delete_id
    self.url = 'https://api.cloudflare.com/client/v4/zones/' + self.zone + '/dns_records'
    self.headers = {'Content-Type': 'application/json', 'X-Auth-Key': self.api_key, 'X-Auth-Email': self.email}

  def get_records(self):
    r = requests.get(self.url + '/', headers=self.headers, params={'per_page':1000})
    json_data = json.loads(r.text)
    return json_data

  def create_record(self):
    self.payload = {'type': self.dns_type, 'name': self.dns_name, 'content': self.content}
    r = requests.post(self.url, data=json.dumps(self.payload), headers=self.headers)
    json_data = json.loads(r.text)
    try:
      if json_data["result"]["id"]:
        print "success"
        # I store the ID in a database so that I can retrieve it later when I want to delete it
    except:
      print "fail"
    print json_data

  def delete_record(self):
    r = requests.delete(self.url + '/' + self.delete_id, headers=self.headers)
    json_data = json.loads(r.text)
    if json_data["success"] == True:
      print "success"
    else:
      print "fail"
    print json_data

class APIError(Exception):
    pass


class Controller:

    """Interact with a UniFi controller.

    Uses the JSON interface on port 8443 (HTTPS) to communicate with a UniFi
    controller. Operations will raise unifi.controller.APIError on obvious
    problems (such as login failure), but many errors (such as disconnecting a
    nonexistant client) will go unreported.

    >>> from unifi.controller import Controller
    >>> c = Controller('192.168.1.99', 'admin', 'p4ssw0rd')
    >>> for ap in c.get_aps():
    ...     print 'AP named %s with MAC %s' % (ap['name'], ap['mac'])
    ...
    AP named Study with MAC dc:9f:db:1a:59:07
    AP named Living Room with MAC dc:9f:db:1a:59:08
    AP named Garage with MAC dc:9f:db:1a:59:0b

    """

    def __init__(self, host, username, password, port=8443, version='v4', site_id='default'):
        """Create a Controller object.

        Arguments:
            host     -- the address of the controller host; IP or name
            username -- the username to log in with
            password -- the password to log in with
            port     -- the port of the controller host
            version  -- the base version of the controller API [v2|v3|v4]
            site_id  -- the site ID to connect to (UniFi >= 3.x)

        """

        self.host = host
        self.port = port
        self.version = version
        self.username = username
        self.password = password
        self.site_id = site_id
        self.url = 'https://' + host + ':' + str(port) + '/'
        self.api_url = self.url + self._construct_api_path(version)

        log.debug('Controller for %s', self.url)

        cj = cookielib.CookieJar()
        if PYTHON_VERSION == 2:
            self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        elif PYTHON_VERSION == 3:
            self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

        self._login(version)

    def __del__(self):
        if self.opener != None:
            self._logout()

    def _jsondec(self, data):
        if PYTHON_VERSION == 3:
            data = data.decode()
        obj = json.loads(data)
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        return obj

    def _read(self, url, params=None):
        if PYTHON_VERSION == 3:
            if params is not None:
                params = ast.literal_eval(params)
                #print (params)
                params = urllib.parse.urlencode(params)
                params = params.encode('utf-8')
                res = self.opener.open(url, params)
            else:
                res = self.opener.open(url)
        elif PYTHON_VERSION == 2:
            res = self.opener.open(url, params)
        return self._jsondec(res.read())

    def _construct_api_path(self, version):
        """Returns valid base API path based on version given

           The base API path for the URL is different depending on UniFi server version.
           Default returns correct path for latest known stable working versions.

        """

        V2_PATH = 'api/'
        V3_PATH = 'api/s/' + self.site_id + '/'

        if(version == 'v2'):
            return V2_PATH
        if(version == 'v3'):
            return V3_PATH
        if(version == 'v4'):
            return V3_PATH
        else:
            return V2_PATH

    def _login(self, version):
        log.debug('login() as %s', self.username)

        params = {'username': self.username, 'password': self.password}
        login_url = self.url

        if version == 'v4':
            login_url += 'api/login'
            params = json.dumps(params)
        else:
            login_url += 'login'
            params.update({'login': 'login'})
            if PYTHON_VERSION is 2:
                params = urllib.urlencode(params)
            elif PYTHON_VERSION is 3:
                params = urllib.parse.urlencode(params)

        if PYTHON_VERSION is 3:
            params = params.encode("UTF-8")
        time_check = 0
        while time_check < 10:
            time_check += 1
            try:
              self.opener.open(login_url, params).read()
            except Exception as e:
              print e
              print login_url
              print "trying to log in again"
              time.sleep(1)

    def _logout(self):
        log.debug('logout()')
        try:
          self.opener.open(self.url + 'logout').read()
        except:
          print "couldnt log out... oh well"

    def get_alerts(self):
        """Return a list of all Alerts."""

        return self._read(self.api_url + 'list/alarm')

    def get_alerts_unarchived(self):
        """Return a list of Alerts unarchived."""

        js = json.dumps({'_sort': '-time', 'archived': False})
        params = urllib.urlencode({'json': js})
        return self._read(self.api_url + 'list/alarm', params)

    def get_statistics_last_24h(self):
        """Returns statistical data of the last 24h"""

        return self.get_statistics_24h(time())

    def get_statistics_24h(self, endtime):
        """Return statistical data last 24h from time"""

        js = json.dumps(
            {'attrs': ["bytes", "num_sta", "time"], 'start': int(endtime - 86400) * 1000, 'end': int(endtime - 3600) * 1000})
        params = urllib.urlencode({'json': js})
        return self._read(self.api_url + 'stat/report/hourly.system', params)

    def get_events(self):
        """Return a list of all Events."""

        return self._read(self.api_url + 'stat/event')

    def get_aps(self):
        """Return a list of all AP:s, with significant information about each."""

        #Set test to 0 instead of NULL
        params = json.dumps({'_depth': 2, 'test': 0})
        return self._read(self.api_url + 'stat/device', params)

    def get_clients(self):
        """Return a list of all active clients, with significant information about each."""

        return self._read(self.api_url + 'stat/sta')

    def get_users(self):
        """Return a list of all known clients, with significant information about each."""

        return self._read(self.api_url + 'list/user')

    def get_user_groups(self):
        """Return a list of user groups with its rate limiting settings."""

        return self._read(self.api_url + 'list/usergroup')

    def get_wlan_conf(self):
        """Return a list of configured WLANs with their configuration parameters."""

        return self._read(self.api_url + 'list/wlanconf')

    def _run_command(self, command, params={}, mgr='sitemgr'):
        log.debug('_run_command(%s)', command)
        params.update({'cmd': command})
        if PYTHON_VERSION == 2:
            return self._read(self.api_url + 'cmd/' + mgr, urllib.urlencode({'json': json.dumps(params)}))
        elif PYTHON_VERSION == 3:
            return self._read(self.api_url + 'cmd/' + mgr, urllib.parse.urlencode({'json': json.dumps(params)}))

    def _mac_cmd(self, target_mac, command, mgr='stamgr'):
        log.debug('_mac_cmd(%s, %s)', target_mac, command)
        params = {'mac': target_mac}
        self._run_command(command, params, mgr)

    def block_client(self, mac):
        """Add a client to the block list.

        Arguments:
            mac -- the MAC address of the client to block.

        """

        self._mac_cmd(mac, 'block-sta')

    def unblock_client(self, mac):
        """

Remove a client from the block list.

        Arguments:
            mac -- the MAC address of the client to unblock.

        """

        self._mac_cmd(mac, 'unblock-sta')

    def disconnect_client(self, mac):
        """Disconnect a client.

        Disconnects a client, forcing them to reassociate. Useful when the
        connection is of bad quality to force a rescan.

        Arguments:
            mac -- the MAC address of the client to disconnect.

        """

        self._mac_cmd(mac, 'kick-sta')

    def restart_ap(self, mac):
        """Restart an access point (by MAC).

        Arguments:
            mac -- the MAC address of the AP to restart.

        """

        self._mac_cmd(mac, 'restart', 'devmgr')

    def restart_ap_name(self, name):
        """Restart an access point (by name).

        Arguments:
            name -- the name address of the AP to restart.

        """

        if not name:
            raise APIError('%s is not a valid name' % str(name))
        for ap in self.get_aps():
            if ap.get('state', 0) == 1 and ap.get('name', None) == name:
                self.restart_ap(ap['mac'])

    def archive_all_alerts(self):
        """Archive all Alerts
        """
        js = json.dumps({'cmd': 'archive-all-alarms'})
        params = urllib.urlencode({'json': js})
        answer = self._read(self.api_url + 'cmd/evtmgr', params)

    def create_backup(self):
        """Ask controller to create a backup archive file, response contains the path to the backup file.

        Warning: This process puts significant load on the controller may
                 render it partially unresponsive for other requests.
        """

        js = json.dumps({'cmd': 'backup'})
        params = urllib.urlencode({'json': js})
        answer = self._read(self.api_url + 'cmd/system', params)

        return answer[0].get('url')

    def get_backup(self, target_file='unifi-backup.unf'):
        """Get a backup archive from a controller.

        Arguments:
            target_file -- Filename or full path to download the backup archive to, should have .unf extension for restore.

        """
        download_path = self.create_backup()

        opener = self.opener.open(self.url + download_path)
        unifi_archive = opener.read()

        backupfile = open(target_file, 'w')
        backupfile.write(unifi_archive)
        backupfile.close()

    def authorize_guest(self, guest_mac, minutes, up_bandwidth=None, down_bandwidth=None, byte_quota=None, ap_mac=None):
        """
        Authorize a guest based on his MAC address.

        Arguments:
            guest_mac     -- the guest MAC address : aa:bb:cc:dd:ee:ff
            minutes       -- duration of the authorization in minutes
            up_bandwith   -- up speed allowed in kbps (optional)
            down_bandwith -- down speed allowed in kbps (optional)
            byte_quota    -- quantity of bytes allowed in MB (optional)
            ap_mac        -- access point MAC address (UniFi >= 3.x) (optional)
        """
        cmd = 'authorize-guest'
        js = {'mac': guest_mac, 'minutes': minutes}

        if up_bandwidth:
            js['up'] = up_bandwidth
        if down_bandwidth:
            js['down'] = down_bandwidth
        if byte_quota:
            js['bytes'] = byte_quota
        if ap_mac and self.version != 'v2':
            js['ap_mac'] = ap_mac

        return self._run_command(cmd, params=js)

    def unauthorize_guest(self, guest_mac):
        """
        Unauthorize a guest based on his MAC address.

        Arguments:
            guest_mac -- the guest MAC address : aa:bb:cc:dd:ee:ff
        """
        cmd = 'unauthorize-guest'
        js = {'mac': guest_mac}

        return self._run_command(cmd, params=js)

    def create_super_admin(self, username, email, password):
        cmd = 'create-admin'
        js = {"email": email, "name": username, "requires_new_password": "true",
          "role": "admin", "x_password": password, "permissions": []}
        r = self._run_command(cmd, params=js)
        print r
        print r[0]["_id"]
        admin_id = r[0]["_id"]
        cmd = 'grant-super-admin'
        js = {"admin": admin_id}
        return self._run_command(cmd, params=js)

    def get_admins(self):
        cmd = 'get-admins'
        r = self._run_command(cmd)
        return r

    def create_site_and_admin(self, desc, username, email, password):
        cmd = 'add-site'
        js = {"desc": desc}
        r = self._run_command(cmd, params=js)
        print r
        print r[0]["_id"]
        site_id = r[0]["_id"]
        site_name = r[0]["name"]
        site_list = [site_id, site_name]
        cmd = 'create-admin'
        js = {"email": email, "name": username, "requires_new_password": True,
              "role": "admin", "x_password": password, "permissions": ["API_DEVICE_ADOPT", "API_DEVICE_RESTART"]}
        log.debug('_run_command(%s)', cmd)
        js.update({'cmd': cmd})
        time_check = 0
	
        while time_check < 30:
            time_check += 1
            try:
                this_url = self.url + 'api/s/' + site_name + '/cmd/sitemgr'
                print this_url
                print json.dumps(js)
                res = self._read(this_url, urllib.urlencode({'json': json.dumps(js)}))
                time.sleep(1)
		print res
		
                break
            except Exception as e:
                print e
		
                print "failed to load admin creation page"
                time.sleep(1)
        data = res
        admin_id = data[0]["_id"]
        cmd = 'grant-super-admin'
        print admin_id
        print "ADMIN ID !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        js = {"admin": admin_id,"role":"nobody","permissions":["API_STAT_DEVICE_ACCESS_SUPER_SITE_PENDING"]}
        log.debug('_run_command(%s)', cmd)
        js.update({'cmd': cmd})
        time_check = 0
        while time_check < 10:
	    time.sleep(1)
            time_check += 1
            try:
                this_url = self.url + 'api/s/' + site_name + '/cmd/sitemgr'
                print this_url
                print json.dumps(js)
                res = self._read(this_url, urllib.urlencode({'json': json.dumps(js)}))
                print res
                return site_list
                break
            except Exception as e:
                print e
		
                print "failed to load admin creation page"
                time.sleep(1)

    def delete_admin(self, admin_id):
        cmd = 'revoke-admin'
        js = {"admin": admin_id}
        r = self._run_command(cmd, params=js)
        return r

    def delete_site(self, site_id):
        cmd = 'delete-site'
        js = {"site": site_id}
        r = self._run_command(cmd, params=js)
        return r

try:
    # Open database connection
    db = MySQLdb.connect("localhost","redacted","redacted","redacted" )

    # prepare a cursor object using cursor() method
    cursor = db.cursor()
    ###
    ### Begin creating new packages:
    ###
    sql = "SELECT * FROM vultr_check"
    vultr_check = []
    try:
       # Execute the SQL command
       cursor.execute(sql)
       # Fetch all the rows in a list of lists.
       results = cursor.fetchall()
       for row in results:
          this_list = []
          id_no = int(row[0])
          customer_id = int(row[1])
          product_id = int(row[2])
          status = str(row[3])
          wp_edd_sub_id = int(row[4])
          server_ip = row[5]
          server_name = row[6]
          admin_pw = row[7]
          site_id = row[8]
          site_name = row[9]
          zabbix_host_id = row[15]
          this_list.append(id_no)
          this_list.append(customer_id)
          this_list.append(product_id)
          this_list.append(status)
          this_list.append(wp_edd_sub_id)
          this_list.append(server_ip)
          this_list.append(server_name)
          this_list.append(admin_pw)
          this_list.append(site_id)
          this_list.append(site_name)
          this_list.append(zabbix_host_id)
          vultr_check.append(this_list)
          
    except Exception as e:
       print "Error: " + str(e)

    print vultr_check

    sql = "SELECT * FROM wp_edd_subscriptions where status = 'active'"
    wp_edd_subscriptions = []
    try:

       # Execute the SQL command
       cursor.execute(sql)
       # Fetch all the rows in a list of lists.
       results = cursor.fetchall()
       for row in results:
          this_list = []
          id_no = int(row[0])
          customer_id = int(row[1])
          product_id = int(row[8])
          this_list.append(id_no)
          this_list.append(customer_id)
          this_list.append(product_id)
          wp_edd_subscriptions.append(this_list)

    except Exception as e:
       print "Error: " + str(e)

    for active_sub in wp_edd_subscriptions:
        end_flag = 0
        for vultr_created in vultr_check:
            if active_sub[0] == vultr_created[4]:
                print active_sub
                print "Already built!"
                # This particular subscription has already been built, so skip it
                end_flag = 1
                break
        if end_flag != 1:
            # If the subscription has not already been built, do this:
            # Check to see what type of sub it is, if it is a multi-site then build it, else if it is a micro/single, check it:
            if active_sub[2] == 5948:
                # Build a new UniFi Video server
                print "Building a server for "
                print active_sub

                # Get number to append to hostname aka v0xxx.hostifi.net
                sql = "SELECT * FROM vultr_options where id = 1"

                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      last_vps_no = int(row[3])
                      
                except Exception as e:
                   print "Error: " + str(e)

                vps_no = last_vps_no + 1
                server_name = "v0" + str(vps_no)

                # Now update VPS number to +=1 
                sql = "UPDATE vultr_options SET last_vps_number = last_vps_number + 1 WHERE id = 1"
                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Commit your changes in the database
                   db.commit()
                except:
                   # Rollback in case there is any error
                   db.rollback()

                # Vultr - create new Debian 9 server
                url = 'https://api.vultr.com/v1/server/create'
                payload = {'hostname': server_name + '.hostifi.net', 'label': server_name + '.hostifi.net', 'DCID': '1',
                       'VPSPLANID': 'redacted', 'OSID': '244',
                       'SSHKEYID': 'redacted,redacted'}

                r = requests.post(url, data=payload, headers={"API-Key": "redacted"})

                print r.text
                print r.status_code
                json_obj = json.loads(r.text)
                subid = json_obj["SUBID"]

                time_check = 0
                server_success = 0
                # Checking if setup was successful
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  if json_obj[subid]:
                    print r.text
                    server_success = 1
                    break
                  else:
                    time.sleep(1)
                if server_success == 1:
                  print "Server setup successfully"
                else:
                  print "Server setup failed for " + str(subid)

                time_check = 0
                server_status = 0
                # Checking if server has finished being provisioned
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  print json_obj[subid]["status"]
                  if json_obj[subid]["status"] == "active":
                    print r.text
                    server_status = 1
                    break
                  else:
                    time.sleep(1)

                if server_status == 1:
                  print "Server is running"
                else:
                  print "Server never started running for " + str(subid)

                # Sleep for a bit just to make sure the server is really done setting up before SSHing in
                time.sleep(60)

                # Get IP of our new server
                url = 'https://api.vultr.com/v1/server/list'
                r = requests.get(url, headers={"API-Key": "redacted"})
                json_obj = json.loads(r.text)
                print json_obj
                server_ip = json_obj[subid]["main_ip"]

                # Set A record at Cloudflare
                zone_id = 'redacted'
                account_email = 'redacted'
                account_api = 'redacted'

                cf = Cloudflare_DNS(zone_id, account_email, account_api, "A", server_name + ".hostifi.net", server_ip,
                          'this-doesnt-matter-but-must-be-set')
                r = cf.create_record()

                # SSH in and install UniFi Controller
                k = paramiko.RSAKey.from_private_key_file("redacted", password="redacted")
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                times_tried = 0
                while times_tried < 10:
                    try:
                        c.connect(hostname=server_ip, username="root", pkey=k)
                        break
                    except Exception as e:
                        print e
                        time.sleep(3)
                        times_tried += 1
                        print "Try again .."
                log_file = "/var/log/unifi/unifi_lets_encrypt.log"
                domain =  server_name + ".hostifi.net"
                domain_prefix = server_name
                script_name = "unifi-video-ssl.sh"
                unifi_install_dir = "/var/lib/unifi"
                num_digits = 32
                myhex = os.urandom(num_digits / 2).encode('hex')
                print "PSK:"
                print myhex
                commands = [
                  'wget https://dl.ubnt.com/firmwares/ufv/v3.9.9/unifi-video.Debian7_amd64.v3.9.9.deb', 'dpkg -i unifi-video.Debian7_amd64.v3.9.9.deb', 'apt --fix-broken install -y',
                  "apt-get update -y", "apt-get install ncdu -y",
                  "apt-get upgrade -y", 'apt --fix-broken install -y', 'domain=' + server_name + ".hostifi.net",
                  'touch /var/swap.img', 'chmod 600 /var/swap.img', 'dd if=/dev/zero of=/var/swap.img bs=1024k count=1024', 'mkswap /var/swap.img', 'swapon /var/swap.img', 
                  'echo "/var/swap.img    none    swap    sw    0    0" >> /etc/fstab', 'apt-get install -y apache2', 'echo "deb http://ftp.debian.org/debian stretch-backports main" | tee -a /etc/apt/sources.list',
                  'apt-get update -y', 'apt-get install python-certbot-apache -t stretch-backports -y', 'certbot --apache --email rchase@hostifi.net --agree-tos --no-eff-email --domain ' + server_name + ".hostifi.net" + ' --no-redirect',
                  'crontab -l | { cat; echo "0 4 * * * /usr/bin/certbot renew"; } | crontab -', "update-rc.d apache2 disable", "service apache2 stop", 
'echo "ufv.custom.certs.enable=true" >> /var/lib/unifi-video/system.properties',"""cat <<EOM >/root/unifi-video-ssl.sh #!/bin/bash
service unifi-video stop
openssl pkcs12 -export -in /etc/letsencrypt/live/""" + domain + """/fullchain.pem -inkey /etc/letsencrypt/live/""" + domain + """/privkey.pem -out /etc/letsencrypt/live/""" + domain + """/cert_and_key.p12 -name newcert -CAfile /etc/letsencrypt/live/""" + domain + """/chain.pem -caname root -password pass:ubiquiti;
keytool -importkeystore -destkeystore /var/lib/unifi-video/keystore -deststorepass ubiquiti -srckeystore /etc/letsencrypt/live/""" + domain + """/cert_and_key.p12 -srcstorepass ubiquiti -srcstoretype PKCS12
keytool -delete -keystore /var/lib/unifi-video/keystore -storepass ubiquiti -alias airvision
keytool -changealias -keystore /var/lib/unifi-video/keystore -storepass ubiquiti -alias newcert -destalias airvision
service unifi-video restart
EOM""", "chmod +x /root/unifi-video-ssl.sh", "/bin/bash /root/unifi-video-ssl.sh", "apt-get install zabbix-agent -y", 'echo "Hostname=' + domain + '" > /etc/zabbix/zabbix_agentd.conf',
'echo "LogFileSize=10" >> /etc/zabbix/zabbix_agentd.conf', 'crontab -l | { cat; echo "0 4 * * * /bin/bash /root/unifi-video-ssl.sh"; } | crontab -', 'echo "LogFile=/var/log/zabbix-agent/zabbix_agentd.log" >> /etc/zabbix/zabbix_agentd.conf', 'echo "PidFile=/var/run/zabbix/zabbix_agentd.pid" >> /etc/zabbix/zabbix_agentd.conf', 'echo "ServerActive=zabbix.locklinnetworks.com" >> /etc/zabbix/zabbix_agentd.conf', 'echo "Server=127.0.0.1,zabbix.locklinnetworks.com" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSConnect=psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSAccept=psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSPSKIdentity=' + domain_prefix + '-psk01" >> /etc/zabbix/zabbix_agentd.conf',  'echo "TLSPSKFile=/etc/zabbix/zabbix_agentd.psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "' + myhex + '" >> /etc/zabbix/zabbix_agentd.psk', 'systemctl start zabbix-agent',
'systemctl enable zabbix-agent', 'reboot']
                time.sleep(5)
                for command in commands:
                    time.sleep(1)
                    print command
                    print "Executing {}".format(command)
                    stdin, stdout, stderr = c.exec_command(command)
                    print stdout.read()
                    print "Errors"
                    print stderr.read()
                c.close()

                unifi_status = 0
                time_check = 0
                # Sleep while UniFi Video finishes installing
                while time_check < 500:
                    try:
                        url = 'https://' + server_ip + ':7443'
                        r = requests.get(url, verify=False)
                        print r.status_code
                        if r.status_code == 200:
                            if "starting up" not in r.text:
                                print r.text
                                print r.status_code
                                unifi_status = 1
                                break
                            else:
                                time.sleep(1)
                                time_check += 1
                        else:
                            print "waiting"
                            time_check += 1
                            time.sleep(1)
                    except Exception as e:
                        print e
                        print "Failed to load"
                        time.sleep(1)
                if unifi_status == 1:
                    print "UniFi Video installed successfully"
                else:
                    print "UniFi Video install failed"

                time.sleep(30)
                # Kill the wizard
                time_check = 0
                headers = {'content-type':'application/json'}
                session = requests.Session()
                # Create super admin for the user

                # Get username and email address for this subscription:
                customer_id = active_sub[1] 
                 # Get WP user id
                sql = "SELECT * FROM wp_edd_customers where id = %s"

                try:
                    # Execute the SQL command
                    cursor.execute(sql, [customer_id])
                    # Fetch all the rows in a list of lists.
                    results = cursor.fetchall()
                    for row in results:
                        wp_user_id = row[1]
                                
                except Exception as e:
                    print "Error: " + str(e)
                user_id = wp_user_id

                # Get Stripe customer id
                sql = "SELECT * FROM wp_edd_customermeta where customer_id = %s"
                is_broken = 0
                try:
                    # Execute the SQL command
                    cursor.execute(sql, [customer_id])
                    # Fetch all the rows in a list of lists.
                    results = cursor.fetchall()
                    for row in results:
                        print "ROW @@@@@@@@@@@@@@@@@@@"
                        print row
                        if "cus" in row[3]:
                            customer_email_id = row[3]
                        else:
                            print "something broke here !"
                            continue
 
                except Exception as e:
                    print "Error: " + str(e)
                if is_broken == 1:
                    continue   
                if live_mode == True:
                    stripe.api_key = "redacted"
                else:
                    stripe.api_key = "redacted"
                try:
                    wp_email = stripe.Customer.retrieve(customer_email_id)["email"]
                except:
                    # Get Stripe customer id
                    sql = "SELECT * FROM wp_users where id = %s"
                    is_broken = 0

                    # Execute the SQL command
                    cursor.execute(sql, [user_id])
                    # Fetch all the rows in a list of lists.
                    results = cursor.fetchall()
                    for row in results:
                        print "ROW @@@@@@@@@@@@@@@@@@@"
                        print row
                        wp_email = row[4]

                print wp_email
                if not wp_email:
                  wp_email = "support@hostifi.net"

                # Get WP user id
                sql = "SELECT * FROM wp_edd_customers where id = %s"

                try:
                   # Execute the SQL command
                   cursor.execute(sql, [customer_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_user_id = row[1]
                      
                except Exception as e:
                    print "Error: " + str(e)
                   
                # Get WP username
                sql = "SELECT * FROM wp_users where id = %s"

                try:
                   # Execute the SQL command
                   cursor.execute(sql, [wp_user_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_username = row[3]
                      wp_username = re.sub(r'\W+', '', wp_username)
                      wp_username = re.sub(r'_', '', wp_username)
                      # Truncate to 20 charz
                      wp_username = (wp_username[:20]) if len(wp_username) > 20 else wp_username
                      
                except Exception as e:
                   print "Error: " + str(e)

                unifi_pw = pw_gen()
                print "made it here"
                print wp_username
                print unifi_pw
                while time_check < 500:

                  try:
                    url = 'https://' + server_ip + ':7443/api/2.0/wizard'
                    payload = {"mode":"MASTER","systemName":"NVR","language":"English","timezone":"America/New_York","name": wp_username,"username": wp_username,"email": wp_email, "password": unifi_pw,"cameraPassword":""}
                    print payload
                    print "payload^"
                    # POST with JSON

                    r = session.post(url, data=json.dumps(payload), headers=headers, verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        if "starting up" not in r.text:
                            print r.text
                            print r.status_code
                            break
                        else:
                            print "sleeping 1 zxzx"
                            time.sleep(1)
                            time_check += 1

                    else:
                        print "sleeping 1"
                        print r.text
                        print r.status_code
                        time.sleep(1)
                        time_check += 1
                  except:
                    time_check += 1
                    print "Failed to kill the wizard"
                    time.sleep(1)

                time.sleep(30)
                # Login
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':7443/api/2.0/login'
                    payload = {"email": wp_email,"password": unifi_pw}

                    # POST with JSON
                    r = session.post(url, data=json.dumps(payload), headers=headers, verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print r.text
                        print r.status_code
                        break
                    else:
                        print "sleeping xxx +1"
                        time_check +=1
                        time.sleep(1)
                  except:
                    print "Failed"
                    time.sleep(1)

                time.sleep(1)
                # Get "bootstrap" settings
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':7443/api/2.0/bootstrap'
                    # POST with JSON

                    r = session.get(url, headers=headers, verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print "Bootstrap info: "
                        print r.text
                        print r.status_code
                        json_data = r.json()
                        print "server id"
                        server_id = json_data["data"][0]["settings"]["_id"]
                        print server_id
                        print "admin id"
                        admin_id = json_data["data"][0]["adminUserGroupId"]
                        print admin_id
                        break
                    else:
                        time.sleep(1)
                        time_check += 1
                  except:
                    print "Failed to load bootstrap"
                    time.sleep(1)

                time.sleep(1)
                # Set timezone, camera password
                time_check = 0
                cam_pw = pw_gen()
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':7443/api/2.0/setting/' + server_id
                    payload = {"systemSettings":{"cameraPassword":str(cam_pw),"defaultLanguage":"English","disableUpdateCheck":False,"disableStatsGathering": True,"disableDiscovery": True,"googleMapsApiKey": None,"timeZone":"America/New_York"},"emailSettings":{"publicHost": None,"emailAddress": None,"host": None,"port":0,"useSsl": False,"requiresAuthentication": False,"enabled": False,"username": None},"alertSettings":{"motionEmailCoolDownMs":0},"livePortSettings":{"rtspPort":7447,"rtmpPort":1935,"rtmpsPort":7444,"rtspEnabled": False,"rtmpEnabled": False,"rtmpsEnabled": False},"_id":server_id}


                    # POST with JSON
                    r = session.put(url, data=json.dumps(payload), headers=headers, verify=False)
                    print 
                    # Response, status etc
                    if r.status_code == 200:
                        print "Settings configured"
                        print r.text
                        print r.status_code
                        break
                    else:
                        print "sleeping 1"
                        print r.text
                        print r.status_code
                        time.sleep(1)
                        time_check += 1
                  except:
                    print "Failed to do settings"
                    time.sleep(1)

                time.sleep(1)
                # Set 10GB free space
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':7443/api/2.0/server/' + server_id
                    payload = {"name": "NVR", "recordingSettings":{"storagePath":"/usr/lib/unifi-video/data/videos","mbToRetain":10240,"timeToRetain":0}}
                    # POST with JSON

                    r = session.put(url, data=json.dumps(payload), headers=headers, verify=False)
                    if r.status_code == 200:
                        print "Set 10gb free space:"
                        # Response, status etc
                        print r.text
                        print r.status_code
                        break
                    else:
                        print r.text
                        print r.status_code
                        print "sleeping 1"
                        time.sleep(1)
                        time_check +=1
                  except:
                    print "Failed to set 10gb free space"
                    time.sleep(1)

                # Get Updates
                r = session.get('https://' + server_ip + ':7443/api/2.0/firmware?forcecheck=true', verify=False, headers=headers)

                print "Get updates:"
                print r.text
                print r.status_code

                # Create a Admin
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':7443/api/2.0/user'
                    ssh_pw = pw_gen()

                    payload = {"enableLocalAccess":True,"userGroup":{"canOptInForEmail":True,"canUseExternalApi":True,"groupType":"ADMIN","name":"Administrator","_id": admin_id},"account":{"email":"redacted","username":"redacted","name":"redacted","password":"redacted","language":"English"},"motionAlertSchedules":{}}

                    # POST with JSON

                    r = session.post(url, data=json.dumps(payload), headers=headers, verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print "User created"
                        print r.text
                        print r.status_code
                        break
                    else:
                        time.sleep(1)
                        time_check +=1
                  except Exception as e:
                    print e
                    print "Failed to load creds"
                    time.sleep(1)


                # Save server setup info back to vultr_check
                server_ip = '0.0.0.0'
                not_important = "0"
                sql = """INSERT INTO vultr_check(customer_id, product_id, status, wp_edd_sub_id, server_ip, server_name, admin_pw, unifi_site_id, unifi_site_name, username, email, zabbix_host_id, ssl_server_name) \
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                try:
                   print wp_email
                   print "ABOVE ^^^^^^^^^^^^^^^"
                   # Execute the SQL command
                   cursor.execute(sql, (customer_id, active_sub[2], server_status, active_sub[0], server_ip, server_name + '.hostifi.net', unifi_pw, not_important, not_important, wp_username, wp_email, zabbix_host_id, server_name + '.hostifi.net'))
                   # Commit your changes in the database
                   db.commit()
                except:
                   # Rollback in case there is any error
                   db.rollback()

                # Send setup trigger notification email
                smtp_ssl_host = 'redacted'  # smtp.mail.yahoo.com
                smtp_ssl_port = 465
                username = 'redacted'
                password = 'redacted'
                sender = 'redacted'
                targets = ['support@hostifi.net', wp_email]
                msg_txt = 'Thanks for checking out HostiFi!\nYour server has finished installing. Login at https://hostifi.net/user to find your temporary password, as well as instructions on how to get started migrating from an existing UniFi Video server or adding a new camera.\n\nUsername: ' + wp_username + '\n' + 'Server: https://' + domain + ':7443\n\nIf you need any help just reply to this email, and we will get back to you shortly\n\n'
                msg = MIMEText(msg_txt)
                msg['Subject'] = 'UniFi Video server ready'
                msg['From'] = sender
                msg['To'] = ', '.join(targets)

                server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
                server.login(username, password)
                server.sendmail(sender, targets, msg.as_string())
                server.quit()
            elif active_sub[2] == 2922 or active_sub[2] == 17405 or active_sub[2] == 17408 or active_sub[2] == 17412 or active_sub[2] == 17410 or active_sub[2] == 5324 or active_sub[2] == 5327 or active_sub[2] == 6098 or active_sub[2] == 6096 or active_sub[2] == 6092:
                # Build a new multi-site sub
                print "Building a server for "
                print active_sub

                # Get number to append to hostname aka multi0xx.hostifi.net
                sql = "SELECT * FROM vultr_options where id = 1"

                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      last_vps_no = int(row[3])
                      
                except Exception as e:
                   print "Error: " + str(e)

                vps_no = last_vps_no + 1
                server_name = "m0" + str(vps_no)

                # Now update VPS number to +=1 
                sql = "UPDATE vultr_options SET last_vps_number = last_vps_number + 1 WHERE id = 1"
                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Commit your changes in the database
                   db.commit()
                except:
                   # Rollback in case there is any error
                   db.rollback()

                # Vultr - create new Debian 9 server
                url = 'https://api.vultr.com/v1/server/create'
                payload = {'hostname': server_name + '.hostifi.net', 'label': server_name + '.hostifi.net', 'DCID': '1',
                       'VPSPLANID': 'redacted', 'OSID': '244',
                       'SSHKEYID': 'redacted,redacted'}

                r = requests.post(url, data=payload, headers={"API-Key": "redacted"})

                print r.text
                print r.status_code
                json_obj = json.loads(r.text)
                subid = json_obj["SUBID"]

                time_check = 0
                server_success = 0
                # Checking if setup was successful
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  if json_obj[subid]:
                    print r.text
                    server_success = 1
                    break
                  else:
                    time.sleep(1)
                if server_success == 1:
                  print "Server setup successfully"
                else:
                  print "Server setup failed for " + str(subid)

                time_check = 0
                server_status = 0
                # Checking if server has finished being provisioned
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  print json_obj[subid]["status"]
                  if json_obj[subid]["status"] == "active":
                    print r.text
                    server_status = 1
                    break
                  else:
                    time.sleep(1)

                if server_status == 1:
                  print "Server is running"
                else:
                  print "Server never started running for " + str(subid)

                # Sleep for a bit just to make sure the server is really done setting up before SSHing in
                time.sleep(60)

                # Get IP of our new server
                url = 'https://api.vultr.com/v1/server/list'
                r = requests.get(url, headers={"API-Key": "redacted"})
                json_obj = json.loads(r.text)
                print json_obj
                server_ip = json_obj[subid]["main_ip"]

                # Set A record at Cloudflare
                zone_id = 'redacted'
                account_email = 'redacted'
                account_api = 'redacted'

                cf = Cloudflare_DNS(zone_id, account_email, account_api, "A", server_name + ".hostifi.net", server_ip,
                          'this-doesnt-matter-but-must-be-set')
                r = cf.create_record()

                # SSH in and install UniFi Controller
                k = paramiko.RSAKey.from_private_key_file("redacted", password="redacted")
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                times_tried = 0
                while times_tried < 10:
                    try:
                        c.connect(hostname=server_ip, username="root", pkey=k)
                        break
                    except Exception as e:
                        print e
                        time.sleep(3)
                        times_tried += 1
                        print "Try again .."
                log_file = "/var/log/unifi/unifi_lets_encrypt.log"
                domain =  server_name + ".hostifi.net"
                domain_prefix = server_name
                script_name = "unifi-ssl.sh"
                unifi_install_dir = "/var/lib/unifi"
                num_digits = 32
                myhex = os.urandom(num_digits / 2).encode('hex')
                print "PSK:"
                print myhex
                commands = [
                  "apt-get update -y", "apt-get install apt-transport-https", "echo 'deb http://www.ubnt.com/downloads/unifi/debian stable ubiquiti' | tee /etc/apt/sources.list.d/100-ubnt-unifi.list",
                  "wget -O /etc/apt/trusted.gpg.d/unifi-repo.gpg https://dl.ubnt.com/unifi/unifi-repo.gpg", "apt-get update -y", "apt-get install ncdu -y",
                  "apt-get install unifi -y", 'domain=' + server_name + ".hostifi.net", 'unifi_install_dir="/var/lib/unifi"', 'log_file="/var/log/unifi/unifi_lets_encrypt.log"',
                  'touch /var/swap.img', 'chmod 600 /var/swap.img', 'dd if=/dev/zero of=/var/swap.img bs=1024k count=1024', 'mkswap /var/swap.img', 'swapon /var/swap.img', 
                  'echo "/var/swap.img    none    swap    sw    0    0" >> /etc/fstab', 'apt-get install -y apache2', 'echo "deb http://ftp.debian.org/debian stretch-backports main" | tee -a /etc/apt/sources.list',
                  'apt-get update -y', 'apt-get install python-certbot-apache -t stretch-backports -y', 'certbot --apache --email rchase@hostifi.net --agree-tos --no-eff-email --domain ' + server_name + ".hostifi.net" + ' --no-redirect',
                  'crontab -l | { cat; echo "0 4 * * * /usr/bin/certbot renew"; } | crontab -', """cat <<EOM >/root/unifi-ssl.sh #!/bin/bash
#################################
# Let's Encrpyt UniFi Controller v0.2
# Add Let's Encrypt certificates to UniFi Controller
######################################################
# CHANGELOG
##################################
# v0.1 @ 2018-05-18
# -> inital creation
# v0.2 @ 2018-05-25
# -> copy old keystore back if keytool convert fails
# -> check if Let's Encrypt certificate even exist
##################################
# AUTHOR
##################################
# Name: Gen Lee
# Contact: gen@digifi.ee
######################################################
script_name="Lets Encrypt UniFi Controller v0.2"

domain=""" + server_name + ".hostifi.net" + """
unifi_install_dir="/var/lib/unifi"

log_file="/var/log/unifi/unifi_lets_encrypt.log"
log () {
        if [ "$1" ]; then
                echo -e "[$(date)] - $1" >> """ + log_file + """
        fi
}

[[ -f """ + log_file + """ ]] || touch "/var/log/unifi/unifi_lets_encrypt.log"
[[ -n """ + unifi_install_dir + """ ]] || unifi_install_dir="/var/lib/unifi" 2>> "/var/log/unifi/unifi_lets_encrypt.log"
[ -d """ + unifi_install_dir + """/letsencrypt ] || mkdir """ + unifi_install_dir + """/letsencrypt 2>> "/var/log/unifi/unifi_lets_encrypt.log"
log "Started """ + script_name + """"
[[ -f /etc/letsencrypt/live/""" + domain + """/fullchain.pem ]] || log "Lets Encrypt certificates for """ + domain + """ dont exist or you dont have enough permissions... exiting" || exit 0
openssl pkcs12 -export -in /etc/letsencrypt/live/""" + domain + """/fullchain.pem -inkey /etc/letsencrypt/live/""" + domain + """/privkey.pem -out """ + unifi_install_dir + """/letsencrypt/""" + domain + """.p12 -name unifi -passout pass:aircontrolenterprise 2>> """ + log_file + """
if [ $? -ne 0 ]; then { log "Error occoured while creating PKCS12 certficate"; exit 0; } fi
cp """ + unifi_install_dir + """/keystore """ + unifi_install_dir + """/keystore.old 2>> """ + log_file + """
keytool -noprompt -importkeystore -deststorepass aircontrolenterprise -destkeypass aircontrolenterprise -destkeystore """ + unifi_install_dir + """/keystore -srckeystore """ + unifi_install_dir + """/letsencrypt/""" + domain + """.p12 -srcstoretype PKCS12 -srcstorepass aircontrolenterprise -srcalias unifi -destalias unifi
if [ $? -ne 0 ]; then { cp """ + unifi_install_dir + """/keystore.old """ + unifi_install_dir + """/keystore; log "Error occoured while creating keystore, copied back old keystore... exiting"; exit 0; } fi
chmod 600 """ + unifi_install_dir + """/keystore && chown unifi:unifi """ + unifi_install_dir + """/keystore 2>> "/var/log/unifi/unifi_lets_encrypt.log"
log "Restarting UniFi service"
systemctl restart unifi 2>> """ + log_file + """
log "Finished """ + script_name + """"
EOM""", "chmod +x /root/unifi-ssl.sh", "/bin/bash /root/unifi-ssl.sh", "update-rc.d apache2 disable", "service apache2 stop", "apt-get install zabbix-agent -y", 'echo "Hostname=' + domain + '" > /etc/zabbix/zabbix_agentd.conf',
'echo "LogFileSize=10" >> /etc/zabbix/zabbix_agentd.conf', 'crontab -l | { cat; echo "0 4 * * * /bin/bash /root/unifi-ssl.sh"; } | crontab -', 'echo "LogFile=/var/log/zabbix-agent/zabbix_agentd.log" >> /etc/zabbix/zabbix_agentd.conf', 'echo "PidFile=/var/run/zabbix/zabbix_agentd.pid" >> /etc/zabbix/zabbix_agentd.conf', 'echo "ServerActive=zabbix.locklinnetworks.com" >> /etc/zabbix/zabbix_agentd.conf', 'echo "Server=127.0.0.1,zabbix.locklinnetworks.com" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSConnect=psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSAccept=psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSPSKIdentity=' + domain_prefix + '-psk01" >> /etc/zabbix/zabbix_agentd.conf',  'echo "TLSPSKFile=/etc/zabbix/zabbix_agentd.psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "' + myhex + '" >> /etc/zabbix/zabbix_agentd.psk', 'systemctl start zabbix-agent',
'systemctl enable zabbix-agent', 'reboot']
                time.sleep(5)
                for command in commands:
                  time.sleep(1)
                  print command
                  print "Executing {}".format(command)
                  stdin, stdout, stderr = c.exec_command(command)
                  print stdout.read()
                  print "Errors"
                  print stderr.read()
                c.close()

                unifi_status = 0
                time_check = 0
                # Sleep while UniFi finishes installing
                while time_check < 500:
                  try:
                    url = 'https://' + server_ip + ':8443'
                    r = requests.get(url, verify=False)
                    print r.status_code
                    if r.status_code == 200:
                        if "starting up" not in r.text:
                            print r.text
                            print r.status_code
                            unifi_status = 1
                            break
                        else:
                            time.sleep(1)
                            time_check += 1
                    else:
                      print "waiting"
                      time_check += 1
                      time.sleep(1)
                  except:
                    print "Failed to load"
                    time.sleep(1)
                if unifi_status == 1:
                  print "UniFi installed successfully"
                else:
                  print "UniFi install failed"

                time.sleep(30)
                # Default setup to get rid of wizard on new servers --
                # Set default admin account
                time_check = 0
                while time_check < 500:

                  try:
                    url = 'https://' + server_ip + ':8443/api/cmd/sitemgr'
                    payload = {'cmd': 'add-default-admin', 'email': 'redacted', 'name': 'redacted',
                           'x_password': 'redacted'}

                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)

                    # Response, status etc

                    print "Default admin:"
                    if r.status_code == 200:
                        if "starting up" not in r.text:
                            print r.text
                            print r.status_code
                            break
                        else:
                            time.sleep(1)
                            time_check += 1

                    else:
                        time.sleep(1)
                        time_check += 1
                  except:
                    time_check += 1
                    print "Failed to load admin setup"
                    time.sleep(1)

                time.sleep(30)
                # Set country
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':8443/api/set/setting/country'
                    payload = {'code': '840'}

                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print "Country: "
                        print r.text
                        print r.status_code
                        break
                    else:
                        time_check +=1
                        time.sleep(1)
                  except:
                    print "Failed to load country"
                    time.sleep(1)

                time.sleep(1)
                # Set locale
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':8443/api/set/setting/locale'
                    payload = {'timezone': 'America/New_York'}

                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print "Locale: "
                        print r.text
                        print r.status_code
                        break
                    else:
                        time.sleep(1)
                        time_check += 1
                  except:
                    print "Failed to load locale"
                    time.sleep(1)

                time.sleep(1)
                # Set backup
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':8443/api/set/setting/super_mgmt'
                    payload = {"autobackup_enabled": 'true', "autobackup_cron_expr": "0 0 1 * *", "autobackup_timezone": "UTC",
                           "autobackup_days": '30'}

                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print "Backup stuff:"
                        print r.text
                        print r.status_code
                        break
                    else:
                        time.sleep(1)
                        time_check += 1
                  except:
                    print "Failed to load backup stuff"
                    time.sleep(1)

                time.sleep(1)
                # Set device SSH creds
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':8443/api/set/setting/mgmt'
                    ssh_pw = pw_gen()

                    payload = {'x_ssh_username': "redacted", 'x_ssh_password': ssh_pw}

                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)

                    # Response, status etc
                    if r.status_code == 200:
                        print "SSH creds: "
                        print r.text
                        print r.status_code
                        break
                    else:
                        time.sleep(1)
                        time_check +=1
                  except Exception as e:
                    print e
                    print "Failed to load ssh creds"
                    time.sleep(1)

                time.sleep(1)
                # Set installed
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':8443/api/cmd/system'
                    payload = {'cmd': "set-installed"}
                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)
                    if r.status_code == 200:
                        print "Set installed:"
                        # Response, status etc
                        print r.text
                        print r.status_code
                        break
                    else:
                        time.sleep(1)
                        time_check +=1
                  except:
                    print "Failed to load set installed"
                    time.sleep(1)

                # Create super admin for the user

                # Get username and email address for this subscription:
                print "active sub 1"
                print active_sub[1]
                customer_id = str(active_sub[1])
                print "customer id"
                print customer_id
                # Get WP user id
                sql = "SELECT * FROM wp_edd_customers where id = '" + customer_id + "'"

                try:
                    print "Running sql"
                    # Execute the SQL command
                    cursor.execute(sql)
                    # Fetch all the rows in a list of lists.
                    results = cursor.fetchone()
                    print "Results:"
                    print results

                    wp_user_id = results[1]
                                
                except Exception as e:
                    print "Error: " + str(e)
                user_id = wp_user_id



                # Get Stripe customer id
                sql = "SELECT * FROM wp_edd_customermeta where customer_id = %s"
                is_broken = 0
                try:
                   # Execute the SQL command
                   cursor.execute(sql, [customer_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      print "ROW @@@@@@@@@@@@@@@@@@@"
                      print row
                      if "cus" in row[3]:
                        customer_email_id = row[3]
                      else:
                        print "something broke here !"
                        continue
 
                except Exception as e:
                   print "Error: " + str(e)
                if is_broken == 1:
                  continue   
                if live_mode == True:
                  stripe.api_key = "redacted"
                else:
                  stripe.api_key = "redacted"
                try:
                    wp_email = stripe.Customer.retrieve(customer_email_id)["email"]
                except:
                    # Get Stripe customer id
                    sql = "SELECT * FROM wp_users where id = " + str(user_id)
                    is_broken = 0
                    # Execute the SQL command
                    cursor.execute(sql)
                    # Fetch all the rows in a list of lists.
                    results = cursor.fetchall()
                    for row in results:
                      print "ROW @@@@@@@@@@@@@@@@@@@"
                      print row
                      wp_email = row[4]
                # Get WP user id
                sql = "SELECT * FROM wp_edd_customers where id = " + str(customer_id)

                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_user_id = row[1]
                      
                except Exception as e:
                   print "Error: " + str(e)
                   
                # Get WP username
                sql = "SELECT * FROM wp_users where id = " + str(wp_user_id)

                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_username = row[3]
                      wp_username = re.sub(r'\W+', '', wp_username)
                      wp_username = re.sub(r'_', '', wp_username)
                      # Truncate to 20 charz
                      wp_username = (wp_username[:20]) if len(wp_username) > 20 else wp_username
                      
                except Exception as e:
                   print "Error: " + str(e)

                unifi_pw = pw_gen()
                c = Controller(server_ip, 'redacted', 'redacted')
                tries = 0
                while tries < 10:
                    try:
                        c.create_super_admin(wp_username, wp_email, unifi_pw)
                        break
                    except Exception as e:
                        print e
                        time.sleep(1)
                        print "ERROR ^"
                        tries += 1


                # Save server setup info back to vultr_check
                server_ip = '0.0.0.0'
                not_important = "0"
                sql = """INSERT INTO vultr_check(customer_id, product_id, status, wp_edd_sub_id, server_ip, server_name, admin_pw, unifi_site_id, unifi_site_name, username, email, zabbix_host_id, ssl_server_name) \
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                try:
                   print wp_email
                   print "ABOVE ^^^^^^^^^^^^^^^"
                   # Execute the SQL command
                   cursor.execute(sql, (customer_id, active_sub[2], server_status, active_sub[0], server_ip, server_name + '.hostifi.net', unifi_pw, not_important, not_important, wp_username, wp_email, zabbix_host_id, server_name + '.hostifi.net'))
                   # Commit your changes in the database
                   db.commit()
                except:
                   # Rollback in case there is any error
                   db.rollback()

                # Send setup trigger notification email
                smtp_ssl_host = 'redacted'  # smtp.mail.yahoo.com
                smtp_ssl_port = 465
                username = 'redacted'
                password = 'redacted'
                sender = 'redacted'
                targets = ['support@hostifi.net', wp_email]
                msg_txt = 'Thanks for checking out HostiFi!\nYour server has finished installing. Login at https://hostifi.net/user to find your temporary password, as well as instructions on how to get started adding a new device or migrating existing sites.\n\nUsername: ' + wp_username + '\n' + 'Server: https://' + domain + ':8443\n\nIf you need any help just reply to this email, and we will get back to you shortly\n\n'
                msg = MIMEText(msg_txt)
                msg['Subject'] = 'UniFi server ready'
                msg['From'] = sender
                msg['To'] = ', '.join(targets)

                server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
                server.login(username, password)
                server.sendmail(sender, targets, msg.as_string())
                server.quit()
            elif active_sub[2] == 5500 or active_sub[2] == 6213 or active_sub[2] == 6215 or active_sub[2] == 6211 or active_sub[2] == 17420 or active_sub[2] == 17418 or active_sub[2] == 17416 or active_sub[2] == 17414:

                # Build a new UNMS server
                print "Building a UNMS server for "
                print active_sub

                # Get number to append to hostname aka multi0xx.hostifi.net
                sql = "SELECT * FROM vultr_options where id = 1"

                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      last_vps_no = int(row[3])
                      
                except Exception as e:
                   print "Error: " + str(e)

                vps_no = last_vps_no + 1
                server_name = "n0" + str(vps_no)

                # Now update VPS number to +=1 
                sql = "UPDATE vultr_options SET last_vps_number = last_vps_number + 1 WHERE id = 1"
                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Commit your changes in the database
                   db.commit()
                except:
                   # Rollback in case there is any error
                   db.rollback()

                # Vultr - create new Debian 9 server
                url = 'https://api.vultr.com/v1/server/create'
                payload = {'hostname': server_name + '.hostifi.net', 'label': server_name + '.hostifi.net', 'DCID': '1',
                       'VPSPLANID': 'redacted', 'OSID': '244',
                       'SSHKEYID': 'redacted,redacted'}

                r = requests.post(url, data=payload, headers={"API-Key": "redacted"})

                print r.text
                print r.status_code
                json_obj = json.loads(r.text)
                subid = json_obj["SUBID"]

                time_check = 0
                server_success = 0
                # Checking if setup was successful
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  if json_obj[subid]:
                    print r.text
                    server_success = 1
                    break
                  else:
                    time.sleep(1)
                if server_success == 1:
                  print "Server setup successfully"
                else:
                  print "Server setup failed for " + str(subid)

                time_check = 0
                server_status = 0
                # Checking if server has finished being provisioned
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  print json_obj[subid]["status"]
                  if json_obj[subid]["status"] == "active":
                    print r.text
                    server_status = 1
                    break
                  else:
                    time.sleep(1)

                if server_status == 1:
                  print "Server is running"
                else:
                  print "Server never started running for " + str(subid)

                # Sleep for a bit just to make sure the server is really done setting up before SSHing in
                time.sleep(60)

                # Get IP of our new server
                url = 'https://api.vultr.com/v1/server/list'
                r = requests.get(url, headers={"API-Key": "redacted"})
                json_obj = json.loads(r.text)
                print json_obj
                server_ip = json_obj[subid]["main_ip"]

                # Set A record at Cloudflare
                zone_id = 'redacted'
                account_email = 'redacted'
                account_api = 'redacted'

                cf = Cloudflare_DNS(zone_id, account_email, account_api, "A", server_name + ".hostifi.net", server_ip,
                          'this-doesnt-matter-but-must-be-set')
                r = cf.create_record()

                # SSH in and install UniFi Controller
                k = paramiko.RSAKey.from_private_key_file("redacted", password="redacted")
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                times_tried = 0
                while times_tried < 10:
                    try:
                        c.connect(hostname=server_ip, username="root", pkey=k)
                        break
                    except Exception as e:
                        print e
                        time.sleep(3)
                        times_tried += 1
                        print "Try again .."

                log_file = "/var/log/unifi/unifi_lets_encrypt.log"
                domain =  server_name + ".hostifi.net"
                domain_prefix = server_name
                script_name = "unifi-ssl.sh"
                unifi_install_dir = "/var/lib/unifi"
                num_digits = 32
                myhex = os.urandom(num_digits / 2).encode('hex')
                print "PSK:"
                print myhex
                commands = [
                  "apt-get update -y", "curl -fsSL https://unms.com/v1/install > /tmp/unms_inst.sh && chmod +x /tmp/unms_inst.sh && bash /tmp/unms_inst.sh --unattended > /tmp/unms_install.log","apt-get update -y", "apt-get install ncdu -y",
                  "apt-get upgrade -y",
                  'touch /var/swap.img', 'chmod 600 /var/swap.img', 'dd if=/dev/zero of=/var/swap.img bs=1024k count=1024', 'mkswap /var/swap.img', 'swapon /var/swap.img', 
                  'echo "/var/swap.img    none    swap    sw    0    0" >> /etc/fstab']
                time.sleep(5)
                for command in commands:
                  time.sleep(1)
                  print command
                  print "Executing {}".format(command)
                  stdin, stdout, stderr = c.exec_command(command)
                  print stdout.read()
                  print "Errors"
                  print stderr.read()
                c.close()

                unifi_status = 0
                time_check = 0
                # Sleep while UNMS finishes installing
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':443'
                    r = requests.get(url, verify=False)
                    print r.status_code
                    if r.status_code == 200:
                        if "starting up" not in r.text:
                            print r.text
                            print r.status_code
                            unifi_status = 1
                            break
                        else:
                            time.sleep(1)
                            time_check += 1
                    else:
                      print "waiting"
                      time.sleep(1)
                  except:
                    print "Failed to load"
                    time.sleep(1)
                if unifi_status == 1:
                  print "UNMS installed successfully"
                else:
                  print "UNMS install failed"

                time.sleep(30)
                # Default setup to get rid of wizard on new servers --
                # Set default admin account
                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'https://' + server_ip + ':443/v2.1/nms/setup'
                    payload = {"user": {"timezone": "America/New_York", "username": "hostifi", "email": "support@hostifi.net",
                    "password": "redacted"}, "smtp": {"type": "nosmtp", "tlsAllowUnauthorized": False, "customSmtpAuthEnabled": False,
                    "customSmtpHostname": None, "customSmtpPort": 25, "customSmtpUsername": None,
                    "customSmtpPassword": None, "customSmtpSender": None, "gmailPassword": None, "gmailUsername": None,
                    "customSmtpSecurityMode": "Plain text"}, "hostname": domain, "useLetsEncrypt": True, "eulaConfirmed": True}

                    # POST with JSON

                    r = requests.post(url, data=json.dumps(payload), verify=False)

                    # Response, status etc

                    print "Default admin:"
                    print r.text
                    print r.status_code
                    break
                  except:
                    print "Failed to load admin setup"
                    time.sleep(1)

                time.sleep(1)
                
                # Create super admin for the user

                # Get username and email address for this subscription:
                customer_id = active_sub[1]


                # Get Stripe customer id
                sql = "SELECT * FROM wp_edd_customermeta where customer_id = %s"
                is_broken = 0
                try:
                   # Execute the SQL command
                   cursor.execute(sql, [customer_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      print "ROW @@@@@@@@@@@@@@@@@@@"
                      print row
                      if "cus" in row[3]:
                        customer_email_id = row[3]
                      else:
                        print "something broke here !"
                        continue
 
                except Exception as e:
                   print "Error: " + str(e)
                if is_broken == 1:
                  continue   
                if live_mode == True:
                  stripe.api_key = "redacted"
                else:
                  stripe.api_key = "redacted"
                try:
                    wp_email = stripe.Customer.retrieve(customer_email_id)["email"]
                except:
                    # Get Stripe customer id
                    sql = "SELECT * FROM wp_users where id = %s"
                    is_broken = 0

                # Execute the SQL command
                cursor.execute(sql, [customer_email_id])
                # Fetch all the rows in a list of lists.
                results = cursor.fetchall()
                for row in results:
                    print "ROW @@@@@@@@@@@@@@@@@@@"
                    print row
                    wp_email = row[4]
                # Get WP user id
                sql = "SELECT * FROM wp_edd_customers where id = %s"

                try:
                   # Execute the SQL command
                   cursor.execute(sql, [customer_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_user_id = row[1]
                      
                except Exception as e:
                   print "Error: " + str(e)
                   
                # Get WP username
                sql = "SELECT * FROM wp_users where id = %s"

                try:
                   # Execute the SQL command
                   cursor.execute(sql, [wp_user_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_username = row[3]
                      wp_username = re.sub(r'\W+', '', wp_username)
                      wp_username = re.sub(r'_', '', wp_username)
                      # Truncate to 20 charz
                      wp_username = (wp_username[:20]) if len(wp_username) > 20 else wp_username
                except Exception as e:
                   print "Error: " + str(e)
                tries = 0
                while tries < 10:
                    try:
                        unms_pw = pw_gen()
                        url = 'https://' + domain + '/v2.1/user/login'
                        payload = {"sessionTimeout":1800000,"username":"hostifi","password":"redacted"}

                        r = requests.post(url, data=payload, verify=False)
                        print r.text
                        headers = {'x-auth-token': r.headers["x-auth-token"]}
                        url = 'https://' + domain + '/v2.1/users'
                        payload = {"username": wp_username,"email": wp_email,"password": unms_pw,"role":"admin"}
                        r = requests.post(url, data=payload, headers=headers, verify=False)
                        print r.text
                        tries = 11
                    except Exception as e:
                        print e
                        time.sleep(1)
                        tries += 1
                        print "trying again .... zz"

                # Save server setup info back to vultr_check
                server_ip = '0.0.0.0'
                not_important = "0"
                sql = """INSERT INTO vultr_check(customer_id, product_id, status, wp_edd_sub_id, server_ip, server_name, admin_pw, unifi_site_id, unifi_site_name, username, email, zabbix_host_id, ssl_server_name) \
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                try:
                   print wp_email
                   print "ABOVE ^^^^^^^^^^^^^^^"
                   # Execute the SQL command
                   cursor.execute(sql, (customer_id, active_sub[2], server_status, active_sub[0], server_ip, domain_prefix + '.hostifi.net', unms_pw, not_important, not_important, wp_username, wp_email, zabbix_host_id, domain_prefix + '.hostifi.net'))
                   # Commit your changes in the database
                   db.commit()
                except Exception as e:
                   print e
                   print "DB ERROR ^^^"
                   # Rollback in case there is any error
                   db.rollback()
                # Send setup trigger notification email
                smtp_ssl_host = 'redacted'  # smtp.mail.yahoo.com
                smtp_ssl_port = 465
                username = 'redacted'
                password = 'redacted'
                sender = 'redacted'
                targets = ['support@hostifi.net', wp_email]
                msg_txt = 'Thanks for checking out HostiFi!\nYour server has finished installing. Login at https://hostifi.net/user to find your temporary password, as well as instructions on how to get started adding a new device or migrating existing sites.\n\nUsername: ' + wp_username + '\n' + 'Server: https://' + domain + '\n\nIf you need any help just reply to this email, and we will get back to you shortly\n\n'
                msg = MIMEText(msg_txt)
                msg['Subject'] = 'UNMS server ready'
                msg['From'] = sender
                msg['To'] = ', '.join(targets)

                server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
                server.login(username, password)
                server.sendmail(sender, targets, msg.as_string())
                server.quit()

            elif active_sub[2] == 5565:
                # Build a new UCRM server
                print "Building a UCRM server for "
                print active_sub

                # Get number to append to hostname aka multi0xx.hostifi.net
                sql = "SELECT * FROM vultr_options where id = 1"

                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      last_vps_no = int(row[3])
                      
                except Exception as e:
                   print "Error: " + str(e)

                vps_no = last_vps_no + 1
                server_name = "u0" + str(vps_no)

                # Now update VPS number to +=1 
                sql = "UPDATE vultr_options SET last_vps_number = last_vps_number + 1 WHERE id = 1"
                try:
                   # Execute the SQL command
                   cursor.execute(sql)
                   # Commit your changes in the database
                   db.commit()
                except:
                   # Rollback in case there is any error
                   db.rollback()

                # Vultr - create new Debian 9 server
                url = 'https://api.vultr.com/v1/server/create'
                payload = {'hostname': server_name + '.hostifi.net', 'label': server_name + '.hostifi.net', 'DCID': '1',
                       'VPSPLANID': 'redacted', 'OSID': '244',
                       'SSHKEYID': 'redacted,redacted'}

                r = requests.post(url, data=payload, headers={"API-Key": "redacted"})

                print r.text
                print r.status_code
                json_obj = json.loads(r.text)
                subid = json_obj["SUBID"]

                time_check = 0
                server_success = 0
                # Checking if setup was successful
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  if json_obj[subid]:
                    print r.text
                    server_success = 1
                    break
                  else:
                    time.sleep(1)
                if server_success == 1:
                  print "Server setup successfully"
                else:
                  print "Server setup failed for " + str(subid)

                time_check = 0
                server_status = 0
                # Checking if server has finished being provisioned
                while time_check < 500:
                  time_check += 1
                  url = 'https://api.vultr.com/v1/server/list'
                  r = requests.get(url, headers={"API-Key": "redacted"})
                  json_obj = json.loads(r.text)
                  print json_obj[subid]["status"]
                  if json_obj[subid]["status"] == "active":
                    print r.text
                    server_status = 1
                    break
                  else:
                    time.sleep(1)

                if server_status == 1:
                  print "Server is running"
                else:
                  print "Server never started running for " + str(subid)

                # Sleep for a bit just to make sure the server is really done setting up before SSHing in
                time.sleep(60)

                # Get IP of our new server
                url = 'https://api.vultr.com/v1/server/list'
                r = requests.get(url, headers={"API-Key": "redacted"})
                json_obj = json.loads(r.text)
                print json_obj
                server_ip = json_obj[subid]["main_ip"]

                # Set A record at Cloudflare
                zone_id = 'redacted'
                account_email = 'redacted'
                account_api = 'redacted'

                cf = Cloudflare_DNS(zone_id, account_email, account_api, "A", server_name + ".hostifi.net", server_ip,
                          'this-doesnt-matter-but-must-be-set')
                r = cf.create_record()

                # SSH in and install UniFi Controller
                k = paramiko.RSAKey.from_private_key_file("redacted", password="redacted")
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                times_tried = 0
                while times_tried < 10:
                    try:
                        c.connect(hostname=server_ip, username="root", pkey=k)
                        break
                    except Exception as e:
                        print e
                        time.sleep(3)
                        times_tried += 1
                        print "Try again .."

                log_file = "/var/log/unifi/unifi_lets_encrypt.log"
                domain =  server_name + ".hostifi.net"
                domain_prefix = server_name
                script_name = "unifi-ssl.sh"
                unifi_install_dir = "/var/lib/unifi"
                num_digits = 32
                myhex = os.urandom(num_digits / 2).encode('hex')
                print "PSK:"
                print myhex
                commands = [
                  "apt-get update -y", "apt-get install curl -y", "apt-get install ncdu -y",
                  "apt-get upgrade -y", 'curl -fsSL https://raw.githubusercontent.com/Ubiquiti-App/UCRM/master/setup-swap.sh > /tmp/setup-swap.sh', 'curl -fsSL https://raw.githubusercontent.com/Ubiquiti-App/UCRM/master/install.sh > /tmp/install.sh', 'curl -fsSL https://raw.githubusercontent.com/Ubiquiti-App/UCRM/master/install-cloud.sh > /tmp/install-cloud.sh', "bash /tmp/install-cloud.sh --username redacted --password 'redacted' > /tmp/install-output",
"apt-get install zabbix-agent -y", 'echo "Hostname=' + domain + '" > /etc/zabbix/zabbix_agentd.conf',
'echo "LogFileSize=10" >> /etc/zabbix/zabbix_agentd.conf', 'echo "LogFile=/var/log/zabbix-agent/zabbix_agentd.log" >> /etc/zabbix/zabbix_agentd.conf', 'echo "PidFile=/var/run/zabbix/zabbix_agentd.pid" >> /etc/zabbix/zabbix_agentd.conf', 'echo "ServerActive=zabbix.locklinnetworks.com" >> /etc/zabbix/zabbix_agentd.conf', 'echo "Server=127.0.0.1,zabbix.locklinnetworks.com" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSConnect=psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSAccept=psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "TLSPSKIdentity=' + domain_prefix + '-psk01" >> /etc/zabbix/zabbix_agentd.conf',  'echo "TLSPSKFile=/etc/zabbix/zabbix_agentd.psk" >> /etc/zabbix/zabbix_agentd.conf', 'echo "' + myhex + '" >> /etc/zabbix/zabbix_agentd.psk', 'systemctl start zabbix-agent',
'systemctl enable zabbix-agent', 'reboot']
                time.sleep(5)
                for command in commands:
                  time.sleep(1)
                  print command
                  print "Executing {}".format(command)
                  stdin, stdout, stderr = c.exec_command(command)
                  print stdout.read()
                  print "Errors"
                  print stderr.read()
                c.close()

                unifi_status = 0
                time_check = 0
                # Sleep while UCRM finishes installing
                while time_check < 500:
                  time_check += 1
                  try:
                    url = 'http://' + server_ip
                    r = requests.get(url)
                    print r.status_code
                    if r.status_code == 200:
                        if "starting up" not in r.text:
                            print r.text
                            print r.status_code
                            unifi_status = 1
                            break
                        else:
                            time.sleep(1)
                            time_check += 1
                    else:
                      print "waiting"
                      time.sleep(1)
                  except:
                    print "Failed to load"
                    time.sleep(1)
                if unifi_status == 1:
                  print "UCRM installed successfully"
                else:
                  print "UCRM install failed"

                time.sleep(30)
                # Default setup to get rid of wizard on new servers --
                # Set default admin account

                # Create super admin for the user
                # Get username and email address for this subscription:
                customer_id = active_sub[1]

                # Get Stripe customer id
                sql = "SELECT * FROM wp_edd_customermeta where customer_id = %s"
                is_broken = 0
                try:
                   # Execute the SQL command
                   cursor.execute(sql, [customer_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      print "ROW @@@@@@@@@@@@@@@@@@@"
                      print row
                      if "cus" in row[3]:
                        customer_email_id = row[3]
                      else:
                        print "something broke here !"
                        continue
 
                except Exception as e:
                   print "Error: " + str(e)
                if is_broken == 1:
                  continue   
                if live_mode == True:
                  stripe.api_key = "redacted"
                else:
                  stripe.api_key = "redacted"

                try:
                    wp_email = stripe.Customer.retrieve(customer_email_id)["email"]
                except:
                    # Get Stripe customer id
                    sql = "SELECT * FROM wp_users where id = %s"
                    is_broken = 0

                    # Execute the SQL command
                    cursor.execute(sql, [customer_email_id])
                    # Fetch all the rows in a list of lists.
                    results = cursor.fetchall()
                    for row in results:
                        print "ROW @@@@@@@@@@@@@@@@@@@"
                        print row
                        wp_email = row[4]

                # Get WP user id
                sql = "SELECT * FROM wp_edd_customers where id = %s"

                try:
                   # Execute the SQL command
                   cursor.execute(sql, [customer_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_user_id = row[1]
                      
                except Exception as e:
                   print "Error: " + str(e)
                   
                # Get WP username
                sql = "SELECT * FROM wp_users where id = %s"

                try:
                   # Execute the SQL command
                   cursor.execute(sql, [wp_user_id])
                   # Fetch all the rows in a list of lists.
                   results = cursor.fetchall()
                   for row in results:
                      wp_username = row[3]
                      wp_username = re.sub(r'\W+', '', wp_username)
                      wp_username = re.sub(r'_', '', wp_username)
                      # Truncate to 20 charz
                      wp_username = (wp_username[:20]) if len(wp_username) > 20 else wp_username
                except Exception as e:
                   print "Error: " + str(e)

                time_check = 0
                while time_check < 500:
                  time_check += 1
                  try:
                    # Log in to UCRM
                    tries = 0
                    session = requests.Session()
                    url = 'http://' + server_ip + '/login'
                    url2 = 'http://' + server_ip + '/login-check'
                    r = session.get(url)
                    print r.text
                    soup = BeautifulSoup(r.text, 'lxml')
                    try:
                        value = soup.find('input', {'name': '_csrf_token'}).get('value')
                    except:
                        pass
                    print value

                    headers7 = r.headers
                    print session.cookies
                    print session

                    form_data = {"_csrf_token": value, "_username": "redacted", "_password": "redacted", "_submit=": ""}
                    r = session.post(url2,data=form_data,headers={"Referer": "http://" + server_ip +"/login"})
                    print r.text
                    print r.status_code
                    print form_data

                    # Get JWT
                    r = session.get("http://" + server_ip +"/get-jwt")
                    resp = json.loads(r.text)
                    print resp["token"]
                    print session.cookies
                    session.cookies["jwt"] = resp["token"]
                    print session.cookies
                    print "COOKIES"
                    break
                  except:
                    print "Failed to load admin setup"
                    time.sleep(1)
                    
                # Kill the Wizard Part 1
                url9 = "http://" + server_ip + "/wizard/account"
                r = session.get(url9)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'account_form[_token]'}).get('value')
                except:
                    pass
                form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "account_form[username]": "redacted", "account_form[password]": "redacted", "account_form[email]": "support@hostifi.net", "account_form[firstName]": "", "account_form[lastName]": "", "account_form[timezone]": "America/New_York", "account_form[locale]": "en_US",  "account_form[_token]": value}
                r = session.post(url9,data=form_data)

                print r.status_code
                print form_data

                # Kill the Wizard Part 2
                url10 = "http://" + server_ip + "/wizard/organization"
                r = session.get(url10)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'wizard_organization[_token]'}).get('value')
                except:
                    pass
                form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "wizard_organization[_token]": value, "wizard_organization[pricingTaxCoefficientPrecision]": "", "wizard_organization[pricingMode]": "1", "wizard_organization[organization][invoiceNumberLength]": "6", "wizard_organization[organization][invoiceInitNumber]": "2942", "wizard_organization[organization][invoiceNumberPrefix]": "", "wizard_organization[organization][invoiceMaturityDays]": "14", "wizard_organization[organization][currency]": "33", "wizard_organization[organization][website]": "", "wizard_organization[organization][phone]": "", "wizard_organization[organization][email]": wp_email, "wizard_organization[organization][zipCode]": "49503", "wizard_organization[organization][state]": "22", "wizard_organization[organization][country]": "249", "wizard_organization[organization][city]": "Grand Rapids", "wizard_organization[organization][street2]": "", "wizard_organization[organization][street1]": "303 Monroe Ave NW", "wizard_organization[organization][taxId]": "", "wizard_organization[organization][registrationNumber]": "", "wizard_organization[organization][name]": wp_username}
                r = session.post(url10,data=form_data)

                print r.status_code
                print form_data

                # Kill the Wizard Part 3
                url11 = "http://" + server_ip + "/wizard/lets-start"
                r = session.get(url11)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'wizard_finishing[_token]'}).get('value')
                except:
                    pass
                form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "wizard_finishing[_token]": value, "wizard_finishing[feedbackEmail]": "support@hostifi.net", "wizard_finishing[feedbackAllowed]": "no", "wizard_finishing[sendAnonymousStatistics]": "1"}
                r = session.post(url11,data=form_data)
                print r.status_code
                print form_data

                # Settings - domain, IP
                url4 = "http://" + server_ip + "/system/settings/application"
                r = session.get(url4)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'setting_application[_token]'}).get('value')
                except:
                    pass
                form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "setting_application[serverFqdn]": domain, "setting_application[serverIp]": server_ip, "setting_application[serverPort]": "80", "setting_application[serverSuspendPort]": "81", "setting_application[siteName]": "", "setting_application[mapboxToken]": "", "setting_application[googleApiKey]": "",  "setting_application[clientIdType]": "1", "setting_application[clientIdNext]": "", "setting_application[errorReporting]": "1", "setting_application[exportPageSize]": "letter", "setting_application[invoicePageSize]": "letter", "setting_application[paymentReceiptPageSize]": "letter", "setting_application[_token]": value}
                r = session.post(url4,data=form_data)

                print r.status_code
                print form_data

                # Create API User
                url5 = "http://" + server_ip + "/system/security/app-keys/new"
                r = session.get(url5)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'app_key[_token]'}).get('value')
                except:
                    pass

                print value

                form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "app_key[name]": "hostifi", "app_key[type]": "TYPE_WRITE", "app_key[_token]": value}
                r = session.post(url5,data=form_data)
                print r.text
                print r.status_code

                # Change backup settings to backup everything
                url6 = "http://" + server_ip + "/system/tools/backup"
                r = session.get(url6)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'optionsForm[_token]'}).get('value')
                except:
                    pass

                print value

                form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "optionsForm[backupIncludeDownloads]": "1", "optionsForm[backupIncludePlugins]": "1", "optionsForm[backupIncludeInvoiceTemplates]": "1", "optionsForm[backupIncludeDocuments]": "1", "optionsForm[backupIncludePlugins": "1", "optionsForm[backupIncludeTicketAttachments]": "1", "optionsForm[backupIncludeWebroot]": "1", "optionsForm[backupIncludeSslCertificates]": "1", "optionsForm[backupIncludeMedia]": "1", "optionsForm[backupIncludeQuoteTemplates]": "1", "optionsForm[backupIncludePaymentReceiptTemplates]": "1", "optionsForm[_token]": value}
                r = session.post(url6,data=form_data)
                print r.text
                print r.status_code
                time.sleep(1)
                
                
                tries = 0
                while tries < 10:
                    try:
                        # MAKE USER
                        ucrm_pw = pw_gen()
                        url8 = "http://" + server_ip +"/system/security/users/new"
                        r = session.get(url8)
                        print r.text
                        soup = BeautifulSoup(r.text, 'lxml')
                        try:
                            value = soup.find('input', {'name': 'user[_token]'}).get('value')
                        except:
                            pass

                        print value

                        form_data = {"fakeusernameremembered": "", "fakepasswordremembered": "", "user[username]": wp_username, "user[email]": wp_email, "user[isActive]": "1", "user[firstName]": "", "user[lastName]": "", "user[locale]": "en_US", "user[group]": "1", "user[plainPassword]": ucrm_pw, "user[_token]": value}
                        r = session.post(url8,data=form_data)
                        print r.text
                        print r.status_code
                        tries = 11
                    except Exception as e:
                        print e
                        time.sleep(1)
                        tries += 1
                        print "trying again .... zz"

                # Do Let's Encrypt
                url7 = "http://" + server_ip + "/system/tools/ssl-certificate"
                r = session.get(url7)
                print r.text
                soup = BeautifulSoup(r.text, 'lxml')
                try:
                    value = soup.find('input', {'name': 'letsEncryptForm[_token]'}).get('value')
                except:
                    pass

                print value

                form_data = {"letsEncryptForm[_token]": value, "letsEncryptForm[email]": "support@hostifi.net", "letsEncryptForm[enableButton]": ""}
                r = session.post(url7,data=form_data)
                print r.text
                print r.status_code

                # Wait for SSL to be installed
                time.sleep(15)

                # Save server setup info back to vultr_check
                server_ip = '0.0.0.0'
                not_important = "0"
                sql = """INSERT INTO vultr_check(customer_id, product_id, status, wp_edd_sub_id, server_ip, server_name, admin_pw, unifi_site_id, unifi_site_name, username, email, zabbix_host_id, ssl_server_name) \
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                try:
                   print wp_email
                   print "ABOVE ^^^^^^^^^^^^^^^"
                   # Execute the SQL command
                   cursor.execute(sql, (customer_id, active_sub[2], server_status, active_sub[0], server_ip, domain_prefix + '.hostifi.net', ucrm_pw, not_important, not_important, wp_username, wp_email, zabbix_host_id, domain_prefix + '.hostifi.net'))
                   # Commit your changes in the database
                   db.commit()
                except Exception as e:
                   print e
                   print "DB ERROR ^^^"
                   # Rollback in case there is any error
                   db.rollback()
                # Send setup trigger notification email
                smtp_ssl_host = 'mail.locklinnetworks.com'  # smtp.mail.yahoo.com
                smtp_ssl_port = 465
                username = 'redacted'
                password = 'redacted'
                sender = 'support@hostifi.net'
                targets = ['support@hostifi.net', wp_email]
                msg_txt = 'Thanks for checking out HostiFi!\nYour server has finished installing. Login at https://hostifi.net/user to find your temporary password, as well as instructions on how to get started adding a new device or migrating from an existing server.\n\nUsername: ' + wp_username + '\n' + 'Server: ' + domain + '\n\nIf you need any help just reply to this email, and we will get back to you shortly\n\n'
                msg = MIMEText(msg_txt)
                msg['Subject'] = 'UCRM server ready'
                msg['From'] = sender
                msg['To'] = ', '.join(targets)

                server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
                server.login(username, password)
                server.sendmail(sender, targets, msg.as_string())
                server.quit()

            else:
                end_flag_2 = 0
                # Check if user already has an active micro/single plan created, if not, build it:
                for vultr_created_2 in vultr_check:
                    if vultr_created_2[1] == active_sub[1]:
                        if vultr_created_2[2] == active_sub[2]:
                            # We found an existing micro/single plan, time to error out:
                            print "Error, this user already has a micro or single plan"

                            # Should we write an error message to vultr_errors or is there already one there?
                            sql = "SELECT * FROM vultr_errors"
                            vultr_errors = []
                            try:
                                # Execute the SQL command
                                cursor.execute(sql)
                                # Fetch all the rows in a list of lists.
                                results = cursor.fetchall()
                                for row in results:
                                    wp_edd_sub_id_no = row[3]
                                    vultr_errors.append(wp_edd_sub_id_no)

                            except Exception as e:
                                print "Error: " + str(e)
                            if active_sub[0] not in vultr_errors:
                                print vultr_errors
                                print active_sub[0]
                                print "New sub being added to errors"
                                sql = """INSERT INTO vultr_errors(error_msg, customer_id, wp_edd_sub_id) \
                                         VALUES ('You already have a Micro or Single-location plan, and we can only provide one of each per customer. We were not able to setup your new hosting package. Please cancel it under "Subscriptions". If you need any assistance, you can email us: support@hostifi.net.', %s, %s)"""
                                try:
                                   # Execute the SQL command
                                   cursor.execute(sql, (active_sub[1], active_sub[0]))
                                   # Commit your changes in the database
                                   db.commit()
                                except:
                                   # Rollback in case there is any error
                                   db.rollback()
                            else:
                                print "Sub already has an error msg, skipping"
                            print active_sub
                            end_flag_2 = 1
                            break


                if end_flag_2 != 1:
                    # The user doesn't already have a micro/single plan, build it:
		
                    # Get current server number aka micro0x.hostifi.net:
                    sql = "SELECT * FROM vultr_options where id = 1"

                    try:
                       # Execute the SQL command
                       cursor.execute(sql)
                       # Fetch all the rows in a list of lists.
                       results = cursor.fetchall()
                       for row in results:
                          micro_no = int(row[1])
                          single_no = int(row[2])
                          
                    except Exception as e:
                       print "Error: " + str(e)
                         
                    if active_sub[2] == 3002 or active_sub[2] == 2955:
  			
                    	# remove this! continue above me breaks the free plan!!!
                        # Build micro
                        print "Building a micro for " + str(active_sub)
                        # Get username and email address for this subscription:
                        customer_id = active_sub[1]
                        # Get WP user id
                        sql = "SELECT * FROM wp_edd_customers where id = %s"

                        try:
                            # Execute the SQL command
                            cursor.execute(sql, [customer_id])
                            # Fetch all the rows in a list of lists.
                            results = cursor.fetchall()
                            for row in results:
                                wp_user_id = row[1]
                                
                        except Exception as e:
                            print "Error: " + str(e)
                        user_id = wp_user_id
                        print "customer id is"
                        print customer_id

                        if live_mode == True:
                            stripe.api_key = "redacted"
                        else:
                            stripe.api_key = "redacted"


                        # Get Stripe customer id
                        sql = "SELECT * FROM wp_users where id = %s"
                        is_broken = 0

                        # Execute the SQL command
                        cursor.execute(sql, [user_id])
                        # Fetch all the rows in a list of lists.
                        results = cursor.fetchall()
                        for row in results:
                            print "ROW @@@@@@@@@@@@@@@@@@@"
                            print row
                            wp_email = row[4]
                            print "Email ###########"
                            print wp_email
                        print "here ...."
                        print wp_email
                        # Get WP user id
                        sql = "SELECT * FROM wp_edd_customers where id = %s"

                        try:
                             # Execute the SQL command
                             cursor.execute(sql, [customer_id])
                             # Fetch all the rows in a list of lists.
                             results = cursor.fetchall()
                             for row in results:
                                wp_user_id = row[1]
                                
                        except Exception as e:
                            print "Error: " + str(e)

                        # Get WP username
                        sql = "SELECT * FROM wp_users where id = %s"

                        try:
                            # Execute the SQL command
                            cursor.execute(sql, [wp_user_id])
                            # Fetch all the rows in a list of lists.
                            results = cursor.fetchall()
                            for row in results:
                                wp_username = row[3]
                                wp_username = re.sub(r'\W+', '', wp_username)
                                wp_username = re.sub(r'_', '', wp_username)
                                # Truncate to 16 charz
                                wp_username = (wp_username[:16]) if len(wp_username) > 16 else wp_username
				wp_username = wp_username + user_gen()
                        except Exception as e:
                            print "Error: " + str(e)
                        unifi_pw = pw_gen()
                        server_name = 'p01.hostifi.net'
                        c = Controller(server_name, 'redacted', 'redacted')
                        unifi_site_list = c.create_site_and_admin(wp_username, wp_username, wp_email, unifi_pw)
                        print unifi_site_list
                        print "new"
                        print "site list above this"
                        if unifi_site_list is not None:
                            unifi_site_id = unifi_site_list[0]
                            unifi_site_name = unifi_site_list[1]
                        else: 
                            print "something broke here ..222"
                            continue
                        server_ip = '0.0.0.0'
                        server_status = 'running'
                        # Save server setup info back to vultr_check

                        sql = """INSERT INTO vultr_check(customer_id, product_id, status, wp_edd_sub_id, server_ip, server_name, admin_pw, unifi_site_id, unifi_site_name, username, email, ssl_server_name) \
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                              
                        try:
                            print wp_email
                            # Execute the SQL command
                            cursor.execute(sql,  (customer_id, active_sub[2], server_status, active_sub[0], server_ip, server_name, unifi_pw, unifi_site_id, unifi_site_name, wp_username, wp_email, server_name))
                            # Commit your changes in the database
                            db.commit()
                        except:
			    print "failed to insert row!"
                            # Rollback in case there is any error
                            db.rollback()
			print "sending email..."
                        domain = 'p01.hostifi.net'
                        # Send setup trigger notification email
                        smtp_ssl_host = 'redacted'  # smtp.mail.yahoo.com
                        smtp_ssl_port = 465
                        username = 'redacted'
                        password = 'redacted'
                        sender = 'redacted'
                        targets = ['support@hostifi.net', wp_email]
                        msg_txt = 'Thanks for checking out HostiFi!\nYour account has finished being setup. Login at https://hostifi.net/user to find your temporary password, as well as instructions on how to get started adding a new device or migrating existing sites.\n\nUsername: ' + wp_username + '\n' + 'Server: https://' + domain + ':8443\n\nIf you need any help just reply to this email, and we will get back to you shortly\n\n'
                        msg = MIMEText(msg_txt)
                        msg['Subject'] = 'UniFi login ready'
                        msg['From'] = sender
                        msg['To'] = ', '.join(targets)

                        server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
                        server.login(username, password)
                        server.sendmail(sender, targets, msg.as_string())
                        server.quit()
                      
                    
    ###
    ### Begin destroying cancelled packages:
    ###
    sql = "SELECT * FROM vultr_check"
    vultr_check = []
    try:
       # Execute the SQL command
       cursor.execute(sql)
       # Fetch all the rows in a list of lists.
       results = cursor.fetchall()
       for row in results:
          this_list = []
          id_no = int(row[0])
          customer_id = int(row[1])
          product_id = int(row[2])
          status = str(row[3])
          wp_edd_sub_id = int(row[4])
          server_ip = row[5]
          server_name = row[6]
          admin_pw = row[7]
          site_id = row[8]
          site_name = row[9]
          username = row[10]
          email = row[11]
          delete_request = row[17]
          zabbix_host_id = row[15]
          this_list.append(id_no)
          this_list.append(customer_id)
          this_list.append(product_id)
          this_list.append(status)
          this_list.append(wp_edd_sub_id)
          this_list.append(server_ip)
          this_list.append(server_name)
          this_list.append(admin_pw)
          this_list.append(site_id)
          this_list.append(site_name)
          this_list.append(username)
          this_list.append(email)
          this_list.append(zabbix_host_id)
          this_list.append(delete_request)
          vultr_check.append(this_list)
          
    except Exception as e:
       print "Error: " + str(e)

    print vultr_check

    sql = "SELECT * FROM wp_edd_subscriptions where status = 'cancelled'"
    wp_edd_subscriptions = []
    try:

       # Execute the SQL command
       cursor.execute(sql)
       # Fetch all the rows in a list of lists.
       results = cursor.fetchall()
       for row in results:
          this_list = []
          id_no = int(row[0])
          customer_id = int(row[1])
          product_id = int(row[8])
          this_list.append(id_no)
          this_list.append(customer_id)
          this_list.append(product_id)
          wp_edd_subscriptions.append(this_list)

    except Exception as e:
       print "Error: " + str(e)
    to_be_cancelled = []
    for cancelled_sub in wp_edd_subscriptions:
        for vultr_created in vultr_check:
            if cancelled_sub[0] == vultr_created[4]:
                print cancelled_sub
                print "Needs to be cancelled"
                to_be_cancelled.append(vultr_created)

    for cancel_me in to_be_cancelled:
        if cancel_me[13] == '0':
            x = datetime.datetime.now()
            x = x.date()
            d = datetime.datetime.today() + datetime.timedelta(days=2)
            d = d.date()
            d = d.strftime('%Y-%m-%d')
            print "----"
            print "Formatted date"
            print d
            print "----"
            sql = "UPDATE vultr_check SET delete_request = '" + d +  "' WHERE id = " + str(cancel_me[0])
            print sql
            try:
               # Execute the SQL command
               cursor.execute(sql)
               # Commit your changes in the database
               db.commit()
            except:
               # Rollback in case there is any error
               db.rollback()

            # Send cancellation trigger notification email
            smtp_ssl_host = 'redacted'  # smtp.mail.yahoo.com
            smtp_ssl_port = 465
            username = 'redacted'
            password = 'redacted'
            sender = 'redacted'
            targets = ['support@hostifi.net']
            if cancel_me[6].startswith("m"):
                cancel_me[6] = cancel_me[6] + ":8443"
            msg_txt = "Customer email: " + cancel_me[11] + "\n" + "Server: https://" + cancel_me[6]
            msg = MIMEText(msg_txt)
            msg['Subject'] = 'HostiFi Cancellation Triggered'
            msg['From'] = sender
            msg['To'] = ', '.join(targets)

            server = smtplib.SMTP_SSL(smtp_ssl_host, smtp_ssl_port)
            server.login(username, password)
            server.sendmail(sender, targets, msg.as_string())
            server.quit()

        else:
            print "Already waiting to be cancelled..."
    cancel_now = []
    for row in vultr_check:
        x = datetime.datetime.now()
        x = x.date()
        date_to_cancel = str(row[13])
        if date_to_cancel != "0":
            print "Checking if it is time to cancel yet:"
            print row
            print date_to_cancel
            date_to_cancel = datetime.datetime.strptime(date_to_cancel, '%Y-%m-%d')
            if date_to_cancel.date()<x:
                print "Cancelling this:"
                print row
                cancel_now.append(row)

    for cancel_me in cancel_now:
        print "Cancelling now"

        if cancel_me[2] != 2955 and cancel_me[2] != 3002:
            # Do server cancellation steps
            print "doing server cancellation"
            # Get list of servers
            url = 'https://api.vultr.com/v1/server/list'
            r = requests.get(url, headers={"API-Key": "redacted"})
            json_obj = json.loads(r.text)
            print r.text
            # Delete Zabbix Host
            print "Zabbix ID:"
            print cancel_me
            print cancel_me[12]
 
            for row in json_obj:
                # Find server with label matching server_name
                server_fqdn = cancel_me[6]
                if json_obj[row]["label"] == server_fqdn:
                    # Vultr - delete this server
                    print "we have a winner"
                    print row
                    print "\n"
                    url = 'https://api.vultr.com/v1/server/destroy'
                    payload = {'SUBID': row}
                    r = requests.post(url, data=payload, headers={"API-Key": "redacted"})

            # Delete A record at Cloudflare
            zone_id = 'redacted'
            account_email = 'redacted'
            account_api = 'redacted'

            cf = Cloudflare_DNS(zone_id, account_email, account_api, "A", server_fqdn, 'this-doesnt-matter-but-must-be-set',
                                'unknown-id')
            r = cf.get_records()

            for row in r["result"]:
                print row["name"]
                print server_fqdn
                if row["name"] == server_fqdn:
                    print row
                    delete_id = row["id"]
                    break

            cf = Cloudflare_DNS(zone_id, account_email, account_api, "A", server_fqdn, 'this-doesnt-matter-but-must-be-set',
                                delete_id)
            r = cf.delete_record()

            # Delete vultr_check row
            sql = "DELETE FROM vultr_check WHERE id ='%s'"
            try:
               # Execute the SQL command
               cursor.execute(sql, [cancel_me[0]])
               # Commit your changes in the database
               db.commit()
               print "Deleted vultr_check row: " + str(cancel_me[0])
            except:
               # Rollback in case there is any error
               db.rollback()

        elif cancel_me[2] == 3002 or cancel_me[2] == 2955:
            continue
	    # this is breaking free plan cancelations!!!!!
	    # Do micro cancellation steps
            # Get current server number aka micro0x.hostifi.net:
            sql = "SELECT * FROM vultr_options where id = 1"

            try:
               # Execute the SQL command
               cursor.execute(sql)
               # Fetch all the rows in a list of lists.
               results = cursor.fetchall()
               for row in results:
                  micro_no = int(row[1])
                  single_no = int(row[2])
                  
            except Exception as e:
               print "Error: " + str(e)

            # Find admin
            # Get username and email address for this subscription:
            wp_username = cancel_me[10]
            wp_username = re.sub(r'\W+', '', wp_username)
            wp_username = re.sub(r'_', '', wp_username)
            # Truncate to 20 charz
            wp_username = (wp_username[:20]) if len(wp_username) > 20 else wp_username
            wp_email = cancel_me[11]

            # Get list of UniFi admins, sort by email to get unifi_admin_id
            unifi_site_id = cancel_me[8]
            print "UniFi site id"
            print unifi_site_id
            unifi_site_name = cancel_me[9]
            server_name = 'p01.hostifi.net'
            c = Controller(server_name, 'redacted', 'redacted', site_id=unifi_site_name)
            print "You are here"
            r = c.get_admins()
            for row in r:
              print row
              if wp_email == row["email"]:
                unifi_admin_id = row["_id"]
                break
            print "You probably didn't make it here"
            # Delete admin from UniFi
            r = c.delete_admin(unifi_admin_id)

            # Delete site from UniFi
            r = c.delete_site(unifi_site_id)

            # Delete vultr_check row
            sql = "DELETE FROM vultr_check WHERE id ='%s'"
            try:
               # Execute the SQL command
               cursor.execute(sql, [cancel_me[0]])
               # Commit your changes in the database
               db.commit()
               print "Deleted vultr_check row: " + str(cancel_me[0])
            except:
               # Rollback in case there is any error
               db.rollback()

        
    ### 
    ### Remove fixed vultr_errors
    ###
    sql = "SELECT * FROM vultr_errors"
    try:
       # Execute the SQL command
       cursor.execute(sql)
       # Fetch all the rows in a list of lists.
       results = cursor.fetchall()
       for row in results:
          wp_edd_sub_id = row[3]
          sql = "SELECT * FROM wp_edd_subscriptions where id = %s"
          try:
             # Execute the SQL command
             cursor.execute(sql, [wp_edd_sub_id])
             # Fetch all the rows in a list of lists.
             results = cursor.fetchall()
             for row in results:
                sub_status = row[12]
                if sub_status == "cancelled":
                  sql = "DELETE FROM vultr_errors WHERE wp_edd_sub_id ='%s'"
                  try:
                     # Execute the SQL command
                     cursor.execute(sql, [wp_edd_sub_id])
                     # Commit your changes in the database
                     db.commit()
                     print "Deleted vultr_error sub wp_edd_sub_id: " + str(wp_edd_sub_id)
                  except:
                     # Rollback in case there is any error
                     db.rollback()

          except Exception as e:
             print "Error: " + str(e)
          
    except Exception as e:
       print "Error: " + str(e)

finally:
    # disconnect from server
    db.close()
    print "---"
    print vultr_check
    print wp_edd_subscriptions
    os.unlink(pidfile)

