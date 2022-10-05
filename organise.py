from operator import itemgetter
import collections

import re
import os.path
from typing import Dict, List, Optional

import logging
import tqdm

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
sender_regex = re.compile(
    r'(?:^\"?(?P<name>[^<>\"]+)\"?\s|^)\<?(?P<email>[^<>]+)\>?$')
Sender = collections.namedtuple('Sender', ['name', 'email'])


def authorise() -> Credentials:
    credentials = Credentials.from_authorized_user_file(
        'token.json', SCOPES) if os.path.exists('token.json') else None

    if credentials is not None and credentials.valid:
        return credentials

    if credentials and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)

        credentials = flow.run_local_server(port=0)

    with open('token.json', 'w') as f:
        f.write(credentials.to_json())

    return credentials


def get_senders(credentials: Credentials) -> Dict:
    service = build('gmail', 'v1', credentials=credentials)
    messages = service.users().messages()

    # Get the first 500 message IDs in the user's inbox
    query = messages.list(userId='me', maxResults=500).execute()
    ids = list(map(itemgetter('id'), query.get('messages', [])))

    senders = {}

    # Loop through each message and obtain the header
    for id in tqdm.tqdm(ids, unit='message', desc="Creating senders list"):
        message = messages.get(userId='me', id=id, format='metadata').execute()
        headers = message.get('payload', {}).get('headers')

        if headers is None:
            logging.info(f'No headers found for message "{id}"')
            continue

        sender_header = next(
            (head for head in headers if head['name'].lower() == 'from'), None)

        if sender_header is None:
            logging.info(f'No sender found for message "{id}"')

        sender_string = sender_header.get('value')
        match = sender_regex.match(sender_string)

        if match is None:
            logging.info(f'Failed to match "{sender_string}".')
            continue

        if match.group('email') not in senders:
            senders[match.group('email')] = set([match.group('name')])
        else:
            senders[match.group('email')].add(match.group('name'))

    return senders


def organise_senders(senders: Dict) -> Dict:
    structure = {}

    for email in senders.keys():
        account, domains = email.split('@')
        domains = domains.split('.').reverse()

        domain_level = structure

        for level in domains:
            pass


def create_filter_document(senders: List[str], document: Optional[Dict] = None) -> Dict:
    pass


def create_gmail_filters(filter_document: Dict, credentials: Credentials) -> None:
    pass


if __name__ == '__main__':
    credentials = authorise()
    senders = get_senders(credentials)

    print(senders)
