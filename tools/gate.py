"""Refuse secret-bearing jobs unless protected main and owner review are configured."""
import json
import os
import urllib.request
from bundle import require
from sealed_metadata_request import parse_job_request
from sealed_request import parse_request

REPO = 'samuelalake/taste-releases'
OWNER = 58840187
ENVIRONMENT = 'taste-reference-transfer'


def get(path):
    request = urllib.request.Request('https://api.github.com/repos/' + REPO + '/' + path,
                                     headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                                              'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def check(environment, policies):
    require(environment.get('can_admins_bypass') is False)
    require(environment.get('deployment_branch_policy') == {'protected_branches': False, 'custom_branch_policies': True})
    reviewers = [r for r in environment['protection_rules'] if r['type'] == 'required_reviewers']
    require(len(reviewers) == 1 and reviewers[0].get('prevent_self_review') is False)
    require([(r['type'], r['reviewer']['id']) for r in reviewers[0]['reviewers']] == [('User', OWNER)])
    require([(p['name'], p['type']) for p in policies['branch_policies']] == [('main', 'branch')])


def main():
    require(os.environ['GITHUB_REPOSITORY'] == REPO)
    require(os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch')
    require(os.environ['GITHUB_REF'] == 'refs/heads/main')
    require(get('commits/main')['sha'] == os.environ['GITHUB_SHA'])
    workflow = os.environ.get('GITHUB_WORKFLOW')
    if workflow in ('Submitted private reference transfer', 'Submitted private metadata job'):
        with open(os.environ['GITHUB_EVENT_PATH']) as handle:
            event = json.load(handle)
        if workflow == 'Submitted private reference transfer':
            parse_request(event['inputs']['request'])
        else:
            parse_job_request(event['inputs']['request'])
    check(get('environments/' + ENVIRONMENT), get('environments/' + ENVIRONMENT + '/deployment-branch-policies'))
    print('Admission passed')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Admission denied')
        raise SystemExit(1)
