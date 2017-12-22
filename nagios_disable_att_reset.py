import json
import os
import requests
import sys
import time
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()
basedir = os.path.abspath(os.path.dirname(__file__))
db_name = 'nagios_att_disable_reset.db'
disabled_alert_elapsed_time = 24 * 3600
secrets_path = '/etc/nagios/nagios_att_reset.json'

class DisabledAttributesDB (Base):
    __tablename__ = 'disabledattributes'

    id = Column(Integer, primary_key=True)
    created_date = Column(Integer)
    action = Column(String(15))
    host_name = Column(String(80))
    service = Column(String(20))

class Slack (object):
    def __init__(self):
        self.slack_auth = self.load_slack_configuration()

    def load_slack_configuration(self):
        # load the slack configuration necessary for posting updates
        try:
            self.f = open(secrets_path)
            self.data = json.load(self.f)
            self.f.close()
        except IOError, e:
            self._error_exit(e)

        try:
            slack_auth = {  "slack_webhook_url": "{}".format(self.data['slack_webhook_url']),
                            "slack_channel": "{}".format(self.data['slack_channel'])
                        }
            return slack_auth
        except KeyError, e:
            self._error_exit(e)

    def output_to_slack(self, text, channel):
        # post update to slack channel
        payload = {
           "channel": "{}".format(self.slack_auth['slack_channel']),
           "username": "NagiosEvents",
           "attachments": [{
               "pretext": "Nagios disabled attributes",
               "mrkdwn_in": ["text", "pretext"],
               "color": "#ff3333",
               "ts": int(time.time()),
               "text": text
           }]
       }

        try:
            r = requests.post(self.slack_auth['slack_webhook_url'], data=json.dumps(payload))
        except:
            e = sys.exc_info()[0]
            self._error_exit(e)


class NagiosEvents (object):
    def __init__(self):
        self.nagios_auth = self.load_nagios_configuration()
        self.db_connect()

    def db_connect(self):
        #connection to the local DB
        self.engine = create_engine('sqlite:///' + os.path.join(basedir, db_name))
        Base.metadata.create_all(self.engine)
        Base.metadata.bind = self.engine
        self.DBSession = sessionmaker(bind=self.engine)
        self.session = self.DBSession()

    def load_nagios_configuration(self):
        # load the Nagios configuration necessary for posting updates
        try:
            f = open(secrets_path)
            data = json.load(f)
            f.close()
        except IOError, e:
            self._error_exit(e)

        try:
            nagios_auth = { 'nagios_api_url': data['nagios_api_url'],
                     'nagios_auth_token': data['nagios_auth_token']
                    }
            return nagios_auth
        except KeyError, e:
            self._error_exit(e)

    def api_call(self, endpoint):
        # Api calls for collection Nagios events
        self.nagios_api_headers = {
            'content-type': 'application/json',
            'bc-authz-string': self.nagios_auth['nagios_auth_token'],
            'cache-control': 'no-cache',
            }

        try:
          self.response = requests.request("GET", self.nagios_auth['nagios_api_url'] + endpoint,
           headers=self.nagios_api_headers)
          return json.loads(self.response.text)
        except requests.exceptions.RequestException as e:
            print e
            sys.exit(1)

    def fetch_logs(self,search):
        #Search specific Nagios logs for disabled notifications and disabled attributed
        self.fetch_result = {}
        for log in self.api_call('log')['content']:
            if any(x in log for x in search):
                self.split = log.split(" ")
                self.split2 = self.split[3].split(';')
                self.fetch_result[self.split2[1]] = {'action' : self.split2[0],
                 'created_date' : self.split[0][1:-1], 'service' : self.split2[2]}
        return self.fetch_result

    def re_enable_notification(self,host,service):
        payload = { "host": host, "service": service}
        try:
            self.response_notification = requests.post(self.nagios_auth['nagios_api_url'] +
            'enable_notifications', headers=self.nagios_api_headers, \
            data=json.dumps(payload))
        except requests.exceptions.RequestException as e:
            print e
            sys.exit(1)
        return json.loads(self.response.text)

    def stats(self,host,service,check):
        # collecting Nagios objects values
        if check == 'DISABLE_SVC_NOTIFICATIONS':
            verif = 'notifications_enabled'
        else:
            verif = 'active_checks_enabled'
        return self.api_call('state')['content'][host]['services'][service][verif]

    def add_to_db(self,created_date,action,host_name,service):
        # Adding disabled attributes in a local sqlite DB to keep track
        # of them and be able to re-enable them automatically
        self.new_alert = DisabledAttributesDB(
        created_date=created_date, action=action,host_name=host_name, service=service)
        self.existing_alert = self.session.query(
        DisabledAttributesDB).filter_by(host_name=host_name)
        # If the alert already exists in the DB, it's not re-added
        for alert in self.existing_alert:
            if action == alert.action and service == alert.service:
                return
        self.session.add(self.new_alert)
        self.session.commit()

    def delete_in_db(self,db_id):
        # Deleting disabled attributes from the local DB
        alert = self.session.query(DisabledAttributesDB).filter_by(id=db_id).one()
        self.session.delete(alert)
        self.session.commit()

    def delete_re_enabled_att(self,action,host_name,service,created_date):
        #Looking at attributes in DB that have been re-enabled. If so,
        #those re-enabled attributes are removed from the DB.
        self.deleted_att = self.session.query(
        DisabledAttributesDB).filter_by(host_name=host_name)
        for att in self.deleted_att:
            if att.service == service and att.action == 'DISABLE_SVC_CHECK' \
            and action == 'ENABLE_SVC_CHECK':
                self.delete_in_db(att.id)
            elif att.service == service and att.action == 'DISABLE_SVC_NOTIFICATIONS' \
            and action == 'ENABLE_SVC_NOTIFICATIONS':
                self.delete_in_db(att.id)

    def fetch_all_db(self):
        # Returns the full content of the local DB.
        self.all_db = self.session.query(DisabledAttributesDB).all()
        for result in self.all_db:
            print 'created_date:{}'.format(result.created_date)
            print 'action:{}'.format(result.action)
            print 'host_name:{}'.format(result.host_name)
            print 'service:{}'.format(result.service)
        return self.all_db

def business_hours():
# Returning True if the current time is a week day and between 2pm and 6pm Central Time.
    t = time.localtime()
    if t.tm_hour in range(14, 20) and t.tm_wday in range(0, 5) \
    and t.tm_min >= 30:
      return True
    else:
      return False

if __name__ == '__main__':

    slack = Slack()
    nagios = NagiosEvents()

    # Collecting the new disabled attributes from Nagios logs
    new_disabled_alert = nagios.fetch_logs(['DISABLE_SVC_CHECK', 'DISABLE_SVC_NOTIFICATIONS'])

    # Adding any new disabled attributes to the local DB
    for host,values in new_disabled_alert.iteritems():
        nagios.add_to_db(new_disabled_alert[host]['created_date'], \
        new_disabled_alert[host]['action'],host,new_disabled_alert[host]['service'])

    # Collecting the new re-enabled attributes from Nagios logs
    new_re_enabled_alert = nagios.fetch_logs(['ENABLE_SVC_CHECK', 'ENABLE_SVC_NOTIFICATIONS'])

    # Deleting any disabled attributes that have been re-enabled from the DB
    # and re-enabling atrributes that haven't been re-enabled about X hours
    # if it happens during business hours
    # and send a slack notification to techops channel
    for host, values in new_re_enabled_alert.iteritems():
        nagios.delete_re_enabled_att(new_re_enabled_alert[host]['action'],host, \
        new_re_enabled_alert[host]['service'],new_re_enabled_alert[host]['created_date'])

    # Re-enabling disabled notification after X hours only if it's during business hours
    fetch_all_disabled_alert = nagios.fetch_all_db()
    for alert in fetch_all_disabled_alert:
        elapsed_time =  int(time.time()) - alert.created_date
        if  elapsed_time >= disabled_alert_elapsed_time and business_hours():
            if alert.action == 'DISABLE_SVC_NOTIFICATIONS':
                slack.output_to_slack('Notification for ' +
                alert.host_name + ':' + alert.service + ' has been disabled for ' +
                str(elapsed_time / 160) + ' hrs. Re-enabling it automatically', slack.slack_auth['slack_channel'])
                nagios.re_enable_notification(alert.host_name,alert.service)
                nagios.delete_in_db(alert.id)
            else:
                slack.output_to_slack('Attribute for ' + alert.host_name +
                ':' + alert.service + ' has been disabled for ' + str(elapsed_time / 160) +
                ' hrs. It\'s been too long. Re-enable it!', slack.slack_auth['slack_channel'])
        #verifying that disabled alerts in the local DB are up to date. '1' below means that
        # the alert is enabled in Nagios.
        elif nagios.stats(alert.host_name,alert.service,alert.action) == 1:
            nagios.delete_in_db(alert.id)

