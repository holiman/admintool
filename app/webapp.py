# -*- coding: utf-8 -*-

import os,sys
import flask
import requests
import httplib2,json
import traceback

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from flask import render_template

import geoip2.database


WHITELIST = [
    #   Bahnhof DBM 
    "46.59.0.0/17",
    # PrivActually Ltd, IPRedator 
    "46.246.32.0/19",
    # IP Telefonica O2 Germany
    "217.184.0.0/13",
    # Hofnetz & IT Services GmbH
    "178.19.208.0/20",
    # Comcast Cable Communications, Inc.
    "73.0.0.0/8",
    # Sidley and Austin
    "198.232.50.0/24",
    # CLARO S.A., Brazil,
    "179.218.0.0/16",
    # Kabel Deutschland RIPE, 
    "91.64.0.0/17",
    # Mannesmann Arcor Network Operation Center
    "188.96.0.0/12",
    # Classic Communications, US, 
    "205.201.101.0/24",
    # Comcast Cable Communications, Inc. 
    "68.32.0.0/11",
    # R van der Velden, 
    "13.34.64.0/20",
    # TC contact IP services, 
    "37.120.0.0/18",
    ]

BLACKLIST = [
    #London trust media VPN
    "109.201.128.0/19",
    "208.167.224.0/19",
    "64.237.32.0/19",
    "179.43.128.0/18",
    "46.166.184.0/21",
    "77.247.176.0/21",
    "85.159.232.0/21",
    "46.166.136.0/21",
]

# The geocity database reader
geo_city_reader = geoip2.database.Reader('/GeoLite2-City.mmdb')


# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "/creds/client_secrets.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
  #Read-only access when retrieving an activity report.
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
  #Read-only access when retrieving the usage report.
  "https://www.googleapis.com/auth/admin.reports.usage.readonly",
]

def url_for(endpoint):
  return "%s/%s" % (external_webroot, endpoint)

app = flask.Flask(__name__)
app.secret_key = open("/dev/urandom","rb").read(32) 

@app.route("/admin/")
def index():
    return render_template("report.html",errors="Not logged in")

@app.route('/admin/iplist')
def iplist():
  if 'credentials' not in flask.session:
    return flask.redirect(url_for('admin/authorize'))

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)


  try:
      # Create an httplib2.Http object to handle our HTTP requests, and authorize it
      # using the credentials.authorize() function.
      hdrs = {}
      credentials.apply(hdrs)
      http = httplib2.Http()
      url = "https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=200"
      (resp_headers, content) = http.request(url, "GET", headers=hdrs)
      return report_events(json.loads(content))

  except Exception, e:
          return render_template("report.html", errors= traceback.format_exc())


@app.route('/admin/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  flow.redirect_uri = url_for('admin/oauth2callback')

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state
  return flask.redirect(authorization_url)


@app.route('/admin/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  #flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
  flow.redirect_uri = url_for('admin/oauth2callback')
  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(url_for('admin/iplist'))


@app.route('/admin/logout')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})


  del flask.session['credentials']

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' )
  else:
    return('An error occurred.' )



def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


from netaddr import *
import socket



def listChecker(aList):
    networklist = [IPNetwork(addr) for addr in aList]
    def isListed(ip):
        for ip_network in networklist:
            if ip in ip_network:
                return True
        return False
    return isListed

whiteListed = listChecker(WHITELIST)
blackListed = listChecker(BLACKLIST)

def report_events(content_json):


  ips = {}
  events = []
  warnings = []
  errors = []
  for item in content_json['items']:
      str_ip = item['ipAddress']
      ip = IPAddress(str_ip)
      try:
          (hostname, alias_list, IP) = socket.gethostbyaddr(str_ip) 
      except Exception, e:
          hostname = "N/A"
          errors.append("%s : %s" % (str_ip, str(e)))

      geo_result = geo_city_reader.city(str_ip)
      _country = geo_result.country.name
      _city = geo_result.city.name

      note = ""
      if whiteListed(ip):
          displaytype = "info"
          note = "whitelisted"
      elif blackListed(ip):
          displaytype = "danger"
          note = "blacklisted"
          ips[item['ipAddress']] = "%s (%s) %s %s" % (str_ip, hostname, _country, _city)
      else:
          displaytype = "warning"


      for event in item['events']:
          _email = item['actor']['email']

          _evname = event['name']
          _time = item['id']['time']
          # Email, ip, hostname, country, city, type, time, warning
          info_item = {"data":[_email,str_ip,hostname, _country, _city, _evname, _time, note],
                      "class" : displaytype}
          events.append(info_item)

  return render_template("report.html", ips = ips, events=events, errors=errors)


external_webroot = "http://localhost:5000/"

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  external_webroot = sys.argv[1]
  app.run('0.0.0.0', 5000, debug=False)

