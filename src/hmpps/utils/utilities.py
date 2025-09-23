import requests
from dockerfile_parse import DockerfileParser
import tempfile
import re
from hmpps.services.job_log_handling import log_debug, log_error, log_info, log_critical


# Cheeky little function to update a dictionary or add a new record if there isn't one
def update_dict(this_dict, key, sub_dict):
  if key not in this_dict:
    this_dict[key] = {}
  this_dict[key].update(sub_dict)


# Various endoint tests
def test_endpoint(url, endpoint):
  headers = {'User-Agent': 'hmpps-service-discovery'}
  try:
    r = requests.get(
      f'{url}{endpoint}', headers=headers, allow_redirects=False, timeout=10
    )
    # Test if json is returned
    if r.json() and r.status_code != 404:
      log_debug(f'Found endpoint: {url}{endpoint} ')
      return True
  except Exception as e:
    log_info(f'Could not connect to endpoint {url}{endpoint} - {e}')
    return False


def test_swagger_docs(url):
  headers = {'User-Agent': 'hmpps-service-discovery'}
  try:
    r = requests.get(
      f'{url}/swagger-ui.html', headers=headers, allow_redirects=False, timeout=10
    )
    # Test for 302 redirect)
    if r.status_code == 302 and (
      '/swagger-ui/index.html' in r.headers['Location']
      or 'api-docs/index.html' in r.headers['Location']
    ):
      log_debug(f'Found swagger docs: {url}/swagger-ui.html')
      return True
  except Exception as e:
    log_debug(f"Couldn't connect to {url}/swagger-ui.html - {e}")
    return False


def test_subject_access_request_endpoint(url):
  headers = {'User-Agent': 'hmpps-service-discovery'}
  try:
    r = requests.get(
      f'{url}/v3/api-docs', headers=headers, allow_redirects=False, timeout=10
    )
    if r.status_code == 200:
      try:
        if r.json()['paths']['/subject-access-request']:
          log_debug(f'Found SAR endpoint at: {url}/v3/api-docs')
          return True
      except KeyError:
        log_debug('No SAR endpoint found.')
        return False
  except TimeoutError:
    log_debug(f'Timed out connecting to: {url}/v3/api-docs')
    return False
  except Exception as e:
    log_debug(f"Couldn't connect to {url}/v3/api-docs: {e}")
    return False


# This method is to find the values defined for allowlist in values*.yaml files under helm_deploy folder of each project.
# This methods read all the values files under helm_deploy folder and create a dictionary object of allowlist for each environment
# including the default values.


def fetch_yaml_values_for_key(yaml_data, key):
  values = {}
  if isinstance(yaml_data, dict):
    if key in yaml_data:
      if isinstance(yaml_data[key], dict):
        values.update(yaml_data[key])
      else:
        values[key] = yaml_data[key]
    for k, v in yaml_data.items():
      if isinstance(v, (dict, list)):
        child_values = fetch_yaml_values_for_key(v, key)
        if child_values:
          values.update({k: child_values})
  elif isinstance(yaml_data, list):
    for item in yaml_data:
      child_values = fetch_yaml_values_for_key(item, key)
      if child_values:
        values.update(child_values)

  return values


# This method read the value stored in dictionary passed to it checks if the ip allow list is present or not and returns boolean
def is_ipallowList_enabled(yaml_data):
  ip_allow_list_enabled = False
  if isinstance(yaml_data, dict):
    for value in yaml_data.values():
      if isinstance(value, dict) and value:
        ip_allow_list_enabled = True
  return ip_allow_list_enabled


def get_dockerfile_data(dockerfile_contents):
  dockerfile = DockerfileParser(fileobj=tempfile.NamedTemporaryFile())
  dockerfile.content = dockerfile_contents

  docker_data = {}
  if re.search(r'rsds-ca-2019-root\.pem', dockerfile.content, re.MULTILINE):
    docker_data['rds_ca_cert'] = {'rds-ca-2019-root.pem'}
  if re.search(r'global-bundle\.pem', dockerfile.content, re.MULTILINE):
    docker_data['rds_ca_cert'] = 'rds-ca-2019-root.pem'

  try:
    # Get list of parent images, and strip out references to 'base'
    parent_images = list(filter(lambda i: i != 'base', dockerfile.parent_images))
    # Get the last element in the array, which should be the base image of the final stage.
    base_image = parent_images[-1]
    docker_data['base_image'] = base_image
    log_debug(f'Found Dockerfile base image: {base_image}')
  except Exception as e:
    log_error(f'Error parent/base image from Dockerfile: {e}')
  return docker_data


################################################################################################
# get_existing_env_config
# This function will get the config value from the component environment
# to prevent it being overwritten by blank entries
def get_existing_env_config(component, env_name, config, services):
  config_value = None
  if envs := component.get('envs', {}):
    env_data = next(
      (env for env in envs if env.get('name') == env_name),
      {},
    )
    if config_value := env_data.get(config):
      log_debug(f'Existing config: {config}, {config_value}')
    else:
      log_debug(f'No existing value found for {config}')

  return config_value


################################################################################################


def find_matching_keys(data, search_key):
  found_values = []

  if isinstance(data, dict):
    for key, value in data.items():
      if key == search_key:
        found_values.append(value)
      else:
        found_values.extend(find_matching_keys(value, search_key))
  elif isinstance(data, list):
    for item in data:
      found_values.extend(find_matching_keys(item, search_key))

  return found_values


def remove_version(data, version):
  log_debug(f'attempting to remove {version} from data["versions"]')
  if versions := data.get('versions', {}):
    if version in versions:
      log_debug(f'found {version}')
      versions.pop(version)
