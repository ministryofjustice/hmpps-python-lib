import requests
import yaml
import json
from hmpps.services.job_log_handling import (
  log_debug,
  log_error,
  log_info,
  log_critical,
  log_level,
)


class AlertmanagerData:
  def __init__(self, am_params):
    self.url = am_params['url']
    self.get_alertmanager_data()

  def get_alertmanager_data(self):
    self.json_config_data = None
    try:
      response = requests.get(self.url, verify=False, timeout=5)
      if response.status_code == 200:
        alertmanager_data = response.json()
        config_data = alertmanager_data['config']
        formatted_config_data = config_data['original'].replace('\\n', '\n')
        yaml_config_data = yaml.safe_load(formatted_config_data)
        self.json_config_data = json.loads(json.dumps(yaml_config_data))
        # log_debug(
        #   f'Alertmanager data:\n=================\n\n{json.dumps(self.json_config_data, indent=2)}\n\n'
        # )
        log_info('Successfully fetched Alertmanager data')
      else:
        log_error(f'Error fetching Alertmanager data: {response.status_code}')

    except requests.exceptions.SSLError as e:
      log_error(f'Alertmanager SSL Error: {e}')

    except requests.exceptions.RequestException as e:
      log_error(f'Alertmanager Request Error: {e}')

    except json.JSONDecodeError as e:
      log_error(f'Alertmanager JSON Decode Error: {e}')

    except Exception as e:
      log_error(f'Error getting data from Alertmanager: {e}')

  def isDataAvailable(self):
    return self.json_config_data is not None

  def find_channel_by_severity_label(self, alert_severity_label):
    # Find the receiver name for the given severity
    receiver_name = ''
    if self.isDataAvailable():
      log_debug(f'Looking for a route for {alert_severity_label}')
      for route in self.json_config_data.get('route', {}).get('routes', []):
        if route['match'].get('severity') == alert_severity_label:
          receiver_name = route['receiver']
          log_debug(
            f'Found route for {alert_severity_label} - receiver_name: {receiver_name}'
          )
          break
      # Find the channel for the receiver name
      if receiver_name:
        for receiver in self.json_config_data.get('receivers'):
          if receiver['name'] == receiver_name:
            log_debug(f'Found receiver for {receiver_name}')
            slack_configs = receiver.get('slack_configs', [])
            if slack_configs:
              log_info(
                f'Found slack_channel for {receiver_name} - {slack_configs[0].get("channel")}'
              )
              return slack_configs[0].get('channel')
            else:
              log_debug(f'No slack_configs found for {receiver_name}')
              return None
    else:
      log_error('No Alertmanager data available')
      return None
