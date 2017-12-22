# nagios_reset_att

Resetting Nagios disabled notifications automatically after X hours and notify in Slack if an attribute has been disabled after X hours.
The script provides Slack notifications in #<channel> channel. It only operates during business hours. 
The script is meant to run on a cron job.
Disabled notifications are re-enabled automatically after X hours.
Disabled attributes only notify you after X hours in Slack.
