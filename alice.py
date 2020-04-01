## Taufique Noorani ##
## 12/09/2019 ##
## Alice Bot ##

import os
import time
import json
import threading
import requests
import datetime
import pytz
import base64
import logging
import warnings
import xmltodict
import re
import subprocess
from variables import *
from netmiko import ConnectHandler
from azure.servicebus.control_client import ServiceBusService
from dotenv import load_dotenv
import time
load_dotenv()
warnings.simplefilter("ignore", UserWarning)

currentBackOff = 0

# Loading Env Variables
ALICE_AZ_CORE_NAMESPACE = os.getenv('ALICE_AZ_CORE_NAMESPACE')
ALICE_AZ_CORE_KEYNAME = os.getenv('ALICE_AZ_CORE_KEYNAME')
ALICE_AZ_CORE_KEYVALUE = os.getenv('ALICE_AZ_CORE_KEYVALUE')
ALICE_AZ_CORE_ENDPOINT = os.getenv('ALICE_AZ_CORE_ENDPOINT')
ALICE_ZD_CORE_USERNAME = os.getenv('ALICE_ZD_CORE_USERNAME')
ALICE_ZD_CORE_PASSWORD = os.getenv('ALICE_ZD_CORE_PASSWORD')
ALICE_ZDV_CORE_USERNAME = os.getenv('ALICE_ZDV_CORE_USERNAME')
ALICE_ZDV_CORE_TOKEN = os.getenv('ALICE_ZDV_CORE_TOKEN')
ALICE_JUNIPER_USERNAME = os.getenv('ALICE_JUNIPER_USERNAME')
ALICE_JUNIPER_PASSWORD = os.getenv('ALICE_JUNIPER_PASSWORD')
ALICE_CTRLUSER = os.getenv('ALICE_CTRLUSER')
ALICE_CTRLPASS = os.getenv('ALICE_CTRLPASS')
ALICE_VPXUSER = os.getenv('ALICE_VPXUSER')
ALICE_VPXPASS = os.getenv('ALICE_VPXPASS')
ES_BASE_CONNECTION = os.getenv('ES_BASE_CONNECTION')
CLC_ES_USER = os.getenv('CLC_ES_USER')
CLC_ES_PASSWORD = os.getenv('CLC_ES_PASSWORD')

bus_service = ServiceBusService(
    service_namespace=ALICE_AZ_CORE_NAMESPACE,
    shared_access_key_name=ALICE_AZ_CORE_KEYNAME,
    shared_access_key_value=ALICE_AZ_CORE_KEYVALUE)


def service_bus_listener(callback):
    print('Started listening to service bus messages')
    while True:
        msg = bus_service.receive_queue_message('alice', peek_lock=False, timeout=60)
        if msg.body is not None:
            process_message(msg)
        else:
            print("No message to process. Backing off for 5 seconds")
            time.sleep(5)


def process_message(msg):
    try:
        global conv

        message = json.loads(msg.body.decode())
        conversation = message.get("conversation")
        print(message)
        logging.basicConfig(level=logging.INFO, filename='alice.log', filemode='w', format='%(asctime)s :: %(message)s')
        logging.info(message)

        # Add conversation ID to list
        conv = conversation['id']

        # Get name from Activity Object
        zd_name = message.get("from").get("name")

        # Setting temporary name from Teams
        tmp_name = zd_name.replace(' ', '').split(',')
        name.append(tmp_name[1] + ' ' + tmp_name[0])

        # Rearranging name from Teams to send to Zendesk
        email.append(message.get('from').get('userPrincipalName'))

        # Strip Message
        _msg = message.get('text').strip()
        strip_msg = ""

        if _msg.startswith("<at>Alice</at> "):
            strip_msg = _msg.replace("<at>Alice</at> ", "")
        elif _msg.startswith("<at>Alice</at>"):
            strip_msg = _msg.replace("<at>Alice</at>", "")
        elif _msg.startswith("vpn lookup"):
            dc = (message.get('text').strip('\n').split(' ')[2]).lower()
            ip = message.get('text').strip('\n').split(' ')[3]
            vpn_lookup(dc, ip)
        elif _msg.startswith("vpn stats"):
            dc = (message.get('text').strip('\n').split(' ')[2]).lower()
            index = message.get('text').strip('\n').split(' ')[4]
            vpn_stats(dc, index)
        elif _msg.startswith("get mrr"):
            alias = (message.get('text').strip('\n').split(' ')[2]).lower()
            get_mrr(alias)
        elif _msg.startswith("hot customer"):
            alias = (message.get('text').strip('\n').split(' ')[2]).lower()
            hot_customer(alias)

        if strip_msg == 'online' or strip_msg == 'on-shift' or strip_msg == 'on shift':
            alice_online()
        elif strip_msg == 'zdvon' or message.get('text') == 'zdvon':
            zdv_online()
        elif strip_msg == 'zdvoff' or message.get('text') == 'zdvoff':
            zdv_offline()
        elif strip_msg == 'eos':
            alice_eos()
        elif strip_msg.startswith('vpn lookup'):
            dc = (strip_msg.split(' ')[2]).lower()
            ip = strip_msg.split(' ')[3]
            vpn_lookup(dc, ip)
        elif strip_msg.startswith('vpn stats'):
            dc = (strip_msg.split(' ')[2]).lower()
            index = strip_msg.split(' ')[4]
            vpn_stats(dc, index)
        elif strip_msg == 'help' or message.get('text') == 'help':
            alice_help()
        elif strip_msg.startswith('get mrr'):
            alias = (strip_msg.split(' ')[2]).lower()
            get_mrr(alias)
        elif strip_msg.startswith('hot customer'):
            alias = (strip_msg.split(' ')[2]).lower()
            hot_customer(alias)
        elif strip_msg.startswith('public-ip'):
            original_ip = strip_msg.split(' ')[-1]
            user_ip = re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\b", original_ip).group(0)
            public_ip(original_ip, user_ip)
        elif _msg.startswith('public-ip'):
            original_ip = _msg.split(' ')[-1]
            user_ip = re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\b", original_ip).group(0)
            public_ip(original_ip, user_ip)

    except Exception as e:
        print(e)


def alice_online():
    recent_events = (datetime.datetime.now(pytz.timezone('US/Pacific')) - datetime.timedelta(days=4)).date()
    upcoming_events = (datetime.datetime.now(pytz.timezone('US/Pacific')) + datetime.timedelta(days=1)).date()

    time_now = datetime.datetime.now(pytz.timezone('US/Pacific'))
    am_pm = datetime.datetime.strftime(time_now, '%Y-%m-%d %H:%M %p')

    if am_pm.endswith('AM'):
        # Daily News Message
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "Good Morning {}! Your Daily News will be delivered to you in a direct message once it is ready.".format(name[-1]),
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)
    elif am_pm.endswith('PM'):
        # Daily News Message
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "Good Afternoon {}! Your Daily News will be delivered to you in a direct message once it is ready.".format(
                name[-1]),
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    # Get Recent Incidents
    recent_incidents = requests.get('https://t3n.zendesk.com/api/v2/search.json?query=tags:bridge_needed+created>{}'.format(recent_events),
                 auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))
    response = recent_incidents.json()

    # Get Upcoming Tasks
    upcoming_tasks = requests.get(
        'https://t3n.zendesk.com/api/v2/search.json?query=type:ticket status<solved  group_id:20048861 due_date:{}'.format(upcoming_events),
        auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))
    upcoming_response = upcoming_tasks.json()

    # Get Past QIs
    past_qis = requests.get(
        'https://t3n.zendesk.com/api/v2/search.json?query=updated>{} custom_field_22741770:true custom_field_24217653:aaron_lemoine_qi status:closed'.format(recent_events),
        auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))
    qi_response = past_qis.json()

    # Send message to user for recent incidents
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<img src='https://i.ibb.co/5RH7twN/daily-news.png' width='300', height='50'>"
                "<h2>Recent High / Urgent Incidents (Past 96 hours)</h2>",
        "botName": "Alice",
        "teamName": teamName,
        "memberName": email[-1]
        }

    requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)

    if len(response.get('results')) < 1:
        no_recent()

    else:
        recent_ui(response)

    # Send message to user about upcoming tasks
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<h2>Customer Care Scheduled Tasks (Next 24 hours)</h2>",
        "botName": "Alice",
        "teamName": teamName,
        "memberName": email[-1]
        }
    requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)

    if len(upcoming_response.get('results')) < 1:
        no_recent()

    else:
        tasks(upcoming_response)

    # Send message to user about past QIs
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<h2>Quality Issues of Interest (Past 96 hours)</h2>",
        "botName": "Alice",
        "teamName": teamName,
        "memberName": email[-1]
        }
    requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)

    if len(qi_response.get('results')) < 1:
        no_recent()

    else:
        qi(qi_response)

    # Send message to user about their ZDV status
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<h2>Zendesk Voice Status</h2>",
        "botName": "Alice",
        "teamName": teamName,
        "memberName": email[-1]
        }
    requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)

    zdv_online()


def alice_eos():
    # Engineer Name
    engineer = name[-1]

    # Search ZD user
    zd_response = requests.get('https://t3n.zendesk.com/api/v2/users/search.json?query=email:{}'.format(email[-1]),
                               auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))

    zd_result = zd_response.json()
    zd_user_id = zd_result.get('users')[0].get('id')

    response = requests.get(
        'https://t3n.zendesk.com/api/v2/search.json?query=type:ticket ticket_type:task ticket_type:incident ticket_type:question '
        'ticket_type:problem -subject:PM* status<solved order_by:updated_at sort:desc assignee:{}'.format(zd_user_id),
        auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))

    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<b>{}: </b>is going End of Shift. Is anyone available to take these tickets?".format(engineer),
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }
    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    result = response.json()

    if len(result.get('results')) < 1:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<b>{}: </b>is going End of Shift. Nothing to hand-off".format(engineer),
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    else:
        # EOS user message
        msg = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.0",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "ExtraLarge",
                                "weight": "Bolder",
                                "text": "End Of Shift",
                                "color": "Attention"
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "items": [
                                            {
                                                "type": "Image",
                                                "style": "Person",
                                                "url": "https://findicons.com/files/icons/1733/msn_messenger_aqua/256/msn_offline.png",
                                                "size": "Small"
                                            }
                                        ],
                                        "width": "auto"
                                    },
                                    {
                                        "type": "Column",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "weight": "Bolder",
                                                "text": engineer,
                                                "wrap": True,
                                                "size": "Large",
                                                "color": "Accent"
                                            }
                                        ],
                                        "width": "stretch"
                                    }
                                ]
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                ]
                            }
                        ],
                    }
                }
            ],
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        for tickets in result.get('results'):
            ticket = tickets.get('id')
            subject = tickets.get('subject')
            priority = tickets.get('priority').capitalize()
            status = tickets.get('status').capitalize()

            msg['attachments'][0]['content']['body'][-1]['facts'].append({"title": "Ticket#: ", "value": ticket})
            msg['attachments'][0]['content']['body'][-1]['facts'].append({"title": "Subject: ", "value": subject})
            msg['attachments'][0]['content']['body'][-1]['facts'].append({"title": "Priority: ", "value": priority})
            msg['attachments'][0]['content']['body'][-1]['facts'].append({"title": "Status: ", "value": status})
            msg['attachments'][0]['content']['body'][-1]['facts'].append({"title": "--------- ",
                                                                          "value": "--------------------------------------------------------------"})

        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    zdv_offline()


def recent_ui(response):
    global impacted_product, cause, minutes_of_impact
    # Loop through the response from recent incidents
    for incidents in response.get('results'):
        ticket_id = incidents.get('id')
        subject = incidents.get('subject')
        start_time = incidents.get('created_at')
        start_time = datetime.datetime.strptime(start_time, '%Y-%m-%dT%H:%M:%SZ')
        status = incidents.get('status')
        for custom in incidents.get('custom_fields'):
            if custom.get('id') == 24305619:
                if custom.get('value') is None:
                    impacted_product = None
                else:
                    impacted_product = custom.get('value')
                    impacted_product = impacted_product.split('__')
                    impacted_product = ' -> '.join(impacted_product)
            if custom.get('id') == 24363155:
                if custom.get('value') is None:
                    cause = None
                else:
                    cause = custom.get('value')
                    cause = cause.split('__')
                    cause = ' -> '.join(cause)
            if custom.get('id') == 24305749:
                minutes_of_impact = custom.get('value')

        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<b><a href=https://t3n.zendesk.com/agent/tickets/{}>Ticket# {}</a></b><br>"
                    "<pre>"
                    "<b>Subject:</b> {}</br>"
                    "<b>Start Time:</b> {}</br>"
                    "<b>Status:</b> {}</br>"
                    "<b>Impacted Product: </b> {} <br>"
                    "<b>Cause of Impact: </b> {} <br>"
                    "<b>Minutes of Impact: </b> {} <br>"
                    "</pre>".format(ticket_id, ticket_id, subject, start_time, status, impacted_product, cause,
                                    minutes_of_impact),
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)


def tasks(upcoming_response):
    # Loop through the response from upcoming tasks
    for events in upcoming_response.get('results'):
        task_id = events.get('id')
        subject = events.get('subject')
        status = events.get('status')

        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<b><a href=https://t3n.zendesk.com/agent/tickets/{}>Ticket# {}</a></b><br>"
                    "<pre>"
                    "<b>Subject:</b> {}</br>"
                    "<b>Status:</b> {}</br>"
                    "</pre>".format(task_id, task_id, subject, status),
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)


def qi(qi_response):
    for qi in qi_response.get('results'):
        qi_ticket = qi.get('id')
        qi_subject = qi.get('subject')

        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<b><a href=https://t3n.zendesk.com/agent/tickets/{}>Ticket# {}</a></b><br>"
                    "<pre>"
                    "<b>Subject:</b> {}</br>"
                    "</pre>".format(qi_ticket, qi_ticket, qi_subject),
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)


def no_recent():
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<pre>No tickets found</pre>",
        "botName": "Alice",
        "teamName": teamName,
        "memberName": email[-1]
        }
    requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)


def zdv_online():
    # Encode Token
    encodedBytes = base64.b64encode((ALICE_ZDV_CORE_USERNAME + '/token:' + ALICE_ZDV_CORE_TOKEN).encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")

    # Search ZD user
    zd_response = requests.get('https://t3n.zendesk.com/api/v2/users/search.json?query=email:{}'.format(email[-1]),
                               auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))

    zd_result = zd_response.json()
    zd_user_id = zd_result.get('users')[0].get('id')

    data = {
        "availability": {
            "via": "client",
            "agent_state": "online"
        }
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + encodedStr
    }

    response = requests.put('https://t3n.zendesk.com/api/v2/channels/voice/availabilities/{}.json'.format(zd_user_id), json=data,
                            headers=headers)

    if response.status_code == 200:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<pre>Zendesk Voice Status : Available</pre>",
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)
    else:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<pre>There was an error setting your Zendesk Voice to Available</pre>",
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)


def zdv_offline():
    # Encode Token
    encodedBytes = base64.b64encode((ALICE_ZDV_CORE_USERNAME + '/token:' + ALICE_ZDV_CORE_TOKEN).encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")

    # Search ZD user
    zd_response = requests.get('https://t3n.zendesk.com/api/v2/users/search.json?query=email:{}'.format(email[-1]),
                               auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))

    zd_result = zd_response.json()
    zd_user_id = zd_result.get('users')[0].get('id')

    data = {
        "availability": {
            "via": "client",
            "agent_state": "offline"
        }
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + encodedStr
    }

    response = requests.put('https://t3n.zendesk.com/api/v2/channels/voice/availabilities/{}.json'.format(zd_user_id), json=data,
                            headers=headers)

    if response.status_code == 200:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<pre>Zendesk Voice Status : Offline</pre>",
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)

    else:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<pre>There was an error setting your Zendesk Voice to Available</pre>",
            "botName": "Alice",
            "teamName": teamName,
            "memberName": email[-1]
        }
        requests.post('https://chatopsbots.azurewebsites.net/root/message', json=msg)


def vpn_lookup(dc, ip):
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "Just a moment please as I perform the requested site-to-site VPN lookup for you...",
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }
    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    for loc, dc_ip in dc_info.items():
        if loc == dc:
            try:
                junos_dc = {
                    'device_type': 'juniper_junos',
                    'host': dc_ip,
                    'username': ALICE_JUNIPER_USERNAME,
                    'password': ALICE_JUNIPER_PASSWORD,
                }

                net_connect = ConnectHandler(**junos_dc)

                p1_status = json.dumps(xmltodict.parse(net_connect.send_command(
                    'show security ike security-associations {} detail | display xml | no-more'.format(ip))))
                p1_status = json.loads(p1_status)

                if p1_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get('error'):
                    error = p1_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get('error').get('message')
                    msg = {
                        "type": "message",
                        "textFormat": "xml",
                        "text": "<pre><b>{}</b></pre>".format(error),
                        "from": {
                            "name": "Alice"
                        },
                        "conversation": {
                            "id": conv
                        },
                        "serviceUrl": "https://smba.trafficmanager.net/amer/"
                    }
                    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)
                    break
                else:
                    pass

                ike_sa = p1_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get(
                    'ike-security-associations-information').get('ike-security-associations-block').get('ike-security-associations')
                ike_algo = p1_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get(
                    'ike-security-associations-information').get('ike-security-associations-block').get(
                    'ike-security-associations').get('ike-sa-algorithms')

                local_ip = ike_sa.get('ike-sa-local-address')
                remote_ip = ike_sa.get('ike-sa-remote-address')
                local_port = ike_sa.get('ike-sa-local-port')
                remote_port = ike_sa.get('ike-sa-remote-port')
                policy_name = p1_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get(
                    'ike-security-associations-information').get('ike-security-associations-block').get('ike-gw-name')
                gw_name = p1_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get(
                    'ike-security-associations-information').get('ike-security-associations-block').get('ike-gw-name')
                auth_mode = ike_sa.get('ike-sa-authentication-method')
                protocol_mode = ike_sa.get('ike-sa-exchange-type')
                encryption_algo = ike_algo.get('ike-sa-encryption-algorithm')
                hashing_algo = ike_algo.get('ike-sa-prf-algorithm')
                diffie_group = ike_algo.get('ike-sa-dhgroup')
                lifetime_exp = ike_sa.get('ike-sa-lifetime')
                ike_status = ike_sa.get('ike-sa-state')

                if ike_status == 'DOWN':
                    msg = {
                        "type": "message",
                        "textFormat": "xml",
                        "text": "<pre>"
                                "<h1>VPN INFORMATION</h1>"
                                "--------------------------------------<br>"
                                "<b>Local Endpoint IP: </b>{}<br>"
                                "<b>Remote Endpoint IP: </b>{}<br>"
                                "<b>Local Port: </b>{}<br>"
                                "<b>Remote Port: </b>{}<br>"
                                "<br>"
                                "<br>"
                                "<h1>PHASE 1 (IKE) INFORMATION</h1>"
                                "--------------------------------------<br>"
                                "<b>Policy Name: </b>{}<br>"
                                "<b>Gateway Name: </b>{}<br>"
                                "<b>Authentication Method: </b>{}<br>"
                                "<b>Protocol Mode: </b>{}<br>"
                                "<b>Encryption Algorithm: </b>{}<br>"
                                "<b>Hashing Algorithm: </b>{}<br>"
                                "<b>Diffie-Hellman Group: </b>{}<br>"
                                "<b>Lifetime Expiration: </b>{}<br>"
                                "<b>IKE Tunnel Status: </b>{}<br>"
                                "<br>"
                                "</pre>".format(local_ip, remote_ip, local_port, remote_port, policy_name, gw_name, auth_mode, protocol_mode, encryption_algo,
                                    hashing_algo, diffie_group, lifetime_exp, ike_status),
                        "from": {
                            "name": "Alice"
                        },
                        "conversation": {
                            "id": conv
                        },
                        "serviceUrl": "https://smba.trafficmanager.net/amer/"
                    }
                    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)
                else:
                    pass
                try:
                    # Phase 2 Information
                    p2_status = json.dumps(xmltodict.parse(net_connect.send_command(
                        'show security ipsec security-associations vpn-name {} | no-more | display xml | no-more'.format(gw_name))))
                    active_sa = net_connect.send_command(
                        'show security ipsec security-associations vpn-name {} detail | match "id:| identity:" | no-more'.format(gw_name))
                    inactive_sa = net_connect.send_command(
                        'show security ipsec inactive-tunnels vpn-name {} detail | match "id:| identity:" | no-more'.format(gw_name))
                    p2_status = json.loads(p2_status)
                    p2_ike_sa = p2_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get(
                        'ipsec-security-associations-information').get('ipsec-security-associations-block')

                    vpn_name = gw_name

                    try:
                        ipsec_protocol = (p2_ike_sa.get('ipsec-security-associations')[0].get('sa-protocol')).strip(':')
                        encrypt_algo = (p2_ike_sa.get('ipsec-security-associations')[0].get('sa-esp-encryption-algorithm')).strip('/')
                        signing_algo = p2_ike_sa.get('ipsec-security-associations')[0].get('sa-hmac-algorithm')
                        total_sa = p2_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item').get(
                            'ipsec-security-associations-information').get('total-active-tunnels')
                    except:
                        ipsec_protocol = (p2_ike_sa[0].get('ipsec-security-associations')[0].get('sa-protocol').strip(':'))
                        encrypt_algo = (p2_ike_sa[0].get('ipsec-security-associations')[0].get('sa-esp-encryption-algorithm').strip('/'))
                        signing_algo = p2_ike_sa[0].get('ipsec-security-associations')[0].get('sa-hmac-algorithm')
                        total_sa = p2_status.get('rpc-reply').get('multi-routing-engine-results').get('multi-routing-engine-item')\
                            .get('ipsec-security-associations-information').get('total-active-tunnels')
                    finally:
                        pass

                    msg = {
                        "type": "message",
                        "textFormat": "xml",
                        "text": "<pre>"
                                "<h1>VPN INFORMATION</h1>"
                                "--------------------------------------<br>"
                                "<b>Local Endpoint IP: </b>{}<br>"
                                "<b>Remote Endpoint IP: </b>{}<br>"
                                "<b>Local Port: </b>{}<br>"
                                "<b>Remote Port: </b>{}<br>"
                                "<br>"
                                "<br>"
                                "<h1>PHASE 1 (IKE) INFORMATION</h1>"
                                "--------------------------------------<br>"
                                "<b>Policy Name: </b>{}<br>"
                                "<b>Gateway Name: </b>{}<br>"
                                "<b>Authentication Method: </b>{}<br>"
                                "<b>Protocol Mode: </b>{}<br>"
                                "<b>Encryption Algorithm: </b>{}<br>"
                                "<b>Hashing Algorithm: </b>{}<br>"
                                "<b>Diffie-Hellman Group: </b>{}<br>"
                                "<b>Lifetime Expiration: </b>{}<br>"
                                "<b>IKE Tunnel Status: </b>{}<br>"
                                "<br>"
                                "<br>"
                                "<h1>PHASE 2 (IPSEC) INFORMATION</h1>"
                                "--------------------------------------<br>"
                                "<b>VPN Name: </b>{}<br>"
                                "<b>IPSec Protocol: </b>{}<br>"
                                "<b>Encryption Algorithm: </b>{}<br>"
                                "<b>Signing Algorithm: </b>{}<br>"
                                "<b>Active SAs: </b>{}<br>"
                                "<br>"
                                "<br>"
                                "<h1>INDEX MAPS</h1>"
                                "--------------------------------------<br>"
                                "<b>Active IPsec SAs ({})</b>"
                                "{}<br>"
                                "<br>"
                                "<b>Inactive IPsec SAs ({})</b>"
                                "{}<br>"
                                "</pre>".format(local_ip, remote_ip, local_port, remote_port, policy_name, gw_name, auth_mode, protocol_mode, encryption_algo,
                                        hashing_algo, diffie_group, lifetime_exp, ike_status, vpn_name, ipsec_protocol, encrypt_algo, signing_algo,
                                        total_sa, vpn_name, active_sa, vpn_name, inactive_sa),
                        "from": {
                            "name": "Alice"
                        },
                        "conversation": {
                            "id": conv
                        },
                        "serviceUrl": "https://smba.trafficmanager.net/amer/"
                    }
                    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)
                except:
                    pass
            except:
                msg = {
                    "type": "message",
                    "textFormat": "xml",
                    "text": "I'm sorry but I am not able to find {} in {}. Please double-check the IP address and "
                        "datacenter and try again. If they are correct, you will need to investigate this IP address manually. "
                        "If it is pingable, it is possible that the public IP address might be assignedto an LBaaS pool or a VFW static NAT."
                        " Please check with those teams as well.".format(ip, dc),
                    "from": {
                        "name": "Alice"
                    },
                    "conversation": {
                        "id": conv
                    },
                    "serviceUrl": "https://smba.trafficmanager.net/amer/"
                }
                requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)


def vpn_stats(dc, index):
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "Just a moment please as I perform the requested site-to-site VPN statistics lookup for you...",
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }
    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    for loc, dc_ip in dc_info.items():
        if loc == dc:
            try:
                junos_dc = {
                    'device_type': 'juniper_junos',
                    'host': dc_ip,
                    'username': ALICE_JUNIPER_USERNAME,
                    'password': ALICE_JUNIPER_PASSWORD,
                }
                net_connect = ConnectHandler(**junos_dc)

                # First run
                get_stats = json.dumps(xmltodict.parse(net_connect.send_command(
                    'show security ipsec statistics index {} node primary | display xml'.format(index))))
                get_stats = json.loads(get_stats)

                # Get Data
                first_encrypted_bytes = get_stats.get('rpc-reply').get('multi-routing-engine-results').\
                    get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information').\
                    get('esp-statistics').get('esp-encrypted-bytes')
                first_decrypted_bytes = get_stats.get('rpc-reply').get('multi-routing-engine-results')\
                    .get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information').\
                    get('esp-statistics').get('esp-decrypted-bytes')
                first_encrypted_packets = get_stats.get('rpc-reply').get('multi-routing-engine-results').\
                    get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information').\
                    get('esp-statistics').get('esp-encrypted-packets')
                first_decrypted_packets = get_stats.get('rpc-reply').get('multi-routing-engine-results').\
                    get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information').\
                    get('esp-statistics').get('esp-decrypted-packets')

                time.sleep(10)
                # Second Run
                get_stats = json.dumps(xmltodict.parse(net_connect.send_command(
                    'show security ipsec statistics index {} node primary | display xml'.format(index))))
                get_stats = json.loads(get_stats)

                # Get Data
                second_encrypted_bytes = get_stats.get('rpc-reply').get('multi-routing-engine-results'). \
                    get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information'). \
                    get('esp-statistics').get('esp-encrypted-bytes')
                second_decrypted_bytes = get_stats.get('rpc-reply').get('multi-routing-engine-results') \
                    .get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information'). \
                    get('esp-statistics').get('esp-decrypted-bytes')
                second_encrypted_packets = get_stats.get('rpc-reply').get('multi-routing-engine-results'). \
                    get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information'). \
                    get('esp-statistics').get('esp-encrypted-packets')
                second_decrypted_packets = get_stats.get('rpc-reply').get('multi-routing-engine-results'). \
                    get('multi-routing-engine-item').get('usp-ipsec-total-statistics-information'). \
                    get('esp-statistics').get('esp-decrypted-packets')

                en_bytes_diff = int(second_encrypted_bytes) - int(first_encrypted_bytes)
                de_bytes_diff = int(second_decrypted_bytes) - int(first_decrypted_bytes)
                en_packet_diff = int(second_encrypted_packets) - int(first_encrypted_packets)
                de_packet_diff = int(second_decrypted_packets) - int(first_decrypted_packets)

                msg = {
                    "type": "message",
                    "textFormat": "xml",
                    "text": "<pre>"
                            "<p>Statistics for index {} with a 10 second delay in-between two passes.</p><br>"
                            "<b>Encrypted Bytes:</b><br>"
                            "First Pass: {}<br>"
                            "Second Pass: {}<br>"
                            "Difference: {}<br>"
                            "<b>Decrypted Bytes</b><br>"
                            "First Pass: {}<br>"
                            "Second Pass: {}<br>"
                            "Difference: {}<br>"
                            "<b>Encrypted Packets:</b><br>"
                            "First Pass: {}<br>"
                            "Second Pass: {}<br>"
                            "Difference: {}<br>"
                            "<b>Decrypted Packets:</b><br>"
                            "First Pass: {}<br>"
                            "Second Pass: {}<br>"
                            "Difference: {}<br>"
                            "</pre>".format(index, first_encrypted_bytes, second_encrypted_bytes, en_bytes_diff,
                                           first_decrypted_bytes, second_decrypted_bytes, de_bytes_diff,
                                           first_encrypted_packets, second_encrypted_packets, en_packet_diff,
                                           first_decrypted_packets, second_decrypted_packets, de_packet_diff),
                    "from": {
                        "name": "Alice"
                    },
                    "conversation": {
                        "id": conv
                    },
                    "serviceUrl": "https://smba.trafficmanager.net/amer/"
                }
                requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

            except:
                msg = {
                    "type": "message",
                    "textFormat": "xml",
                    "text": "I'm sorry but I was not able to get valid stats. Please have someone look at the core firewall.",
                    "from": {
                        "name": "Alice"
                    },
                    "conversation": {
                        "id": conv
                    },
                    "serviceUrl": "https://smba.trafficmanager.net/amer/"
                }
                requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)


def alice_help():
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "<b>alice online</b> OR </b>on-shift</b> OR <b>on shift</b> - This will sign you into Zendesk Voice and provide a report of the previous days activity.<br> "
                "<b>alice eos</b> - This will sign you out of Zendesk Voice and bring back a list of tickets to pass.<br>"
                "<b>alice zdvon</b> - This will sign you into Zendesk Voice.<br> "
                "<b>alice zdvoff</b> - This will sign you out of Zendesk Voice.<br>"
                "<b>alice vpn lookup <datacenter> <datacenter or VPN endpoint IP address></b> - Reports the status"
                "and IPsec SA index mappings of a site-to-site VPN tunnel from a given datacenter to another datacenter or remote VPN endpoint..<br>"
                "<b>alice get mrr <alias></b> - This command will lookup MRR details for the account and its subs"
                "<b>alice hot customer <alias></b> - Produces a report of tickets associated with the provided customer alias"
                "<b>alice vpn stats <datacenter> index <index number></b> - Reports the statistics for an IPsec SA index in a given datacenter (Use 'vpn lookup' first to get a mapping of indices).",
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }
    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)


def public_ip(original_ip, user_ip):
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "Just a moment please as I perform the requested action for you...",
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }
    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    user_dc = []

    if user_ip in dc_ips:
        for dc, ip in ip_list.items():
            if user_ip in ip:
                user_dc.append(dc)

        SRXEDGE = dc_netinfo[user_dc[-1]][0]
        SRXCORE = dc_netinfo[user_dc[-1]][1]
        VPXRNAT = dc_netinfo[user_dc[-1]][2]

        cmd = ['/root/cc-alice/get_public_ip.sh', user_dc[-1], original_ip, ALICE_JUNIPER_USERNAME, ALICE_JUNIPER_PASSWORD, SRXEDGE, SRXCORE, ALICE_CTRLUSER, ALICE_CTRLPASS, ALICE_VPXUSER, ALICE_VPXPASS, VPXRNAT]
        output = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = output.communicate()
        result = stdout.decode('utf-8')

        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "<pre>" + result + "</pre>",
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

        user_dc.clear()
    else:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "I'm sorry but I am not able to find {}. Please double-check the IP address and "
                    "datacenter and try again. If they are correct, you will need to investigate this IP address manually. "
                    "If it is pingable, it is possible that the public IP address might be assignedto an LBaaS pool or a VFW static NAT."
                    " Please check with those teams as well.".format(original_ip),
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)


def get_mrr(alias):
    # Authenticate to CLC
    auth_url = 'https://api.ctl.io/v2/authentication/login'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    auth = {
        'username': ALICE_CTRLUSER,
        'password': ALICE_CTRLPASS
    }
    result = requests.post(auth_url, headers=headers, json=auth)
    result = result.json()
    token = result.get('bearerToken')

    # Get Account Information
    url = 'https://api.ctl.io/v2-experimental/subaccounts/'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    result = requests.get(url + alias, headers=headers)
    result = result.json()
    business_name = result[0].get('businessName')

    # Authenticate to ElasticSearch
    encodedBytes = base64.b64encode((CLC_ES_USER + ':' + CLC_ES_PASSWORD).encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")
    data = {
        "query":
            {"bool":
                {"should":[
                    {"term":
                        {"doc.billingSummary.AccountAlias": alias}
                    }
                ]
                }
            },
        "size": 0,
        "aggs": {"range": {"date_range": {"field": "doc.billingSummary.TimeGenerated", "ranges": [{"from": "now-12h/h"}]
        }, "aggs": {"total": {"sum": {"field": "doc.billingSummary.Dashboard.MonthlyEstimate"}}}}}
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + encodedStr
    }
    result = requests.post(ES_BASE_CONNECTION, json=data, headers=headers)
    result = result.json()
    mrr = result.get('aggregations').get('range').get('buckets')[0].get('total').get('value')
    mrr = round(mrr, 2)
    mrr = "{:,}".format(mrr)

    # Send info to user
    msg = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.0",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Medium",
                            "weight": "Bolder",
                            "text": business_name
                        },
                        {
                            "type": "ColumnSet",
                            "columns": [
                                {
                                    "type": "Column",
                                    "items": [
                                        {
                                            "type": "Image",
                                            "style": "Person",
                                            "url": "https://www.pnglot.com/pngfile/detail/114-1149376_money-flat-icon-money-flat-icon-png.png",
                                            "size": "Small"
                                        }
                                    ],
                                    "width": "auto"
                                },
                                {
                                    "type": "Column",
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "weight": "Bolder",
                                            "text": "MRR ESTIMATES",
                                            "wrap": True
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "$" + mrr,
                                            "isSubtle": True,
                                            "wrap": True,
                                            "color": "Good",
                                            "spacing": "Small"
                                        }
                                    ],
                                    "width": "stretch"
                                }
                            ]
                        }
                    ],
                }
            }
        ],
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }

    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)


def hot_customer(alias):
    msg = {
        "type": "message",
        "textFormat": "xml",
        "text": "Please give me a few moments to build the report for you.",
        "from": {
            "name": "Alice"
        },
        "conversation": {
            "id": conv
        },
        "serviceUrl": "https://smba.trafficmanager.net/amer/"
    }
    requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

    # Authenticate to CLC
    auth_url = 'https://api.ctl.io/v2/authentication/login'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    auth = {
        'username': ALICE_CTRLUSER,
        'password': ALICE_CTRLPASS
    }
    result = requests.post(auth_url, headers=headers, json=auth)
    result = result.json()
    token = result.get('bearerToken')

    # Get Account Information
    url = 'https://api.ctl.io/v2-experimental/subaccounts/'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
    }
    result = requests.get(url + alias, headers=headers)
    result = result.json()
    if len(result) < 1:
        msg = {
            "type": "message",
            "textFormat": "xml",
            "text": "No account found. Please check the account Alias",
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }
        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)
    else:
        sub_accounts = []
        # Get Subaccounts
        for accounts in result:
            sub_accounts.append(accounts)

        # Authenticate to ElasticSearch
        encodedBytes = base64.b64encode((CLC_ES_USER + ':' + CLC_ES_PASSWORD).encode("utf-8"))
        encodedStr = str(encodedBytes, "utf-8")

        # Get MRR
        data = {
            "query":
                {"bool":
                    {"should": [
                        {"term":
                             {"doc.billingSummary.AccountAlias": alias}
                         }
                    ]
                    }
                },
            "size": 0,
            "aggs": {"range": {"date_range": {"field": "doc.billingSummary.TimeGenerated", "ranges": [{"from": "now-12h/h"}]
                                              },
                               "aggs": {"total": {"sum": {"field": "doc.billingSummary.Dashboard.MonthlyEstimate"}}}}}
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + encodedStr
        }
        result = requests.post(ES_BASE_CONNECTION, json=data, headers=headers)
        result = result.json()
        mrr = result.get('aggregations').get('range').get('buckets')[0].get('total').get('value')
        mrr = round(mrr, 2)
        mrr = "{:,}".format(mrr)

        # Get Account Info
        data = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "term": {
                                    "doc.account.accountAlias": alias
                                }
                            }
                        ]
                    }
                },
                "size": 1
                }
        result = requests.post(ES_BASE_CONNECTION, json=data, headers=headers)
        result = result.json()

        business_name = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('businessName')
        parent_account = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('parentAlias')
        primary_datacenter = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get(
            'primaryDataCenter')
        if result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('billingAccountNumber'):
            ban_number = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('billingAccountNumber')
        else:
            ban_number = "None"
        street_address = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('addressLine1')
        city = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('city')
        customer_address = street_address + ', ' + city
        billing_contact = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get(
            'billingContactUsername')
        if result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('primaryContactUsername'):
            primary_contact = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('primaryContactUsername')
        else:
            primary_contact = "None"
        if result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get('secondaryContactUsername'):
            secondary_contact = result.get('hits').get('hits')[0].get('_source').get('doc').get('account').get(
            'secondaryContactUsername')
        else:
            secondary_contact = "None"

        # Get User Info
        billing_info = []
        primary_info = []
        secondary_info = []

        data = {
                "query": {
                    "bool": {
                        "must": [{
                            "term": {
                                "doc.user.accountAlias": alias
                                }
                            }]
                        }
                    },
                "size":100
                }
        result = requests.post(ES_BASE_CONNECTION, json=data, headers=headers)
        result = result.json()

        user_names = result.get('hits').get('hits')
        if len(user_names) < 1:
            billing_info.extend(['None', 'None'])
            primary_info.extend(['None', 'None'])
            secondary_info.extend(['None', 'None'])

        for user in user_names:
            ctrl_user = user.get('_source').get('doc').get('user').get('userName')
            if ctrl_user == billing_contact:
                billing_info.append(user.get('_source').get('doc').get('user').get('firstName'))
                billing_info.append(user.get('_source').get('doc').get('user').get('lastName'))
            elif ctrl_user == primary_contact:
                primary_info.append(user.get('_source').get('doc').get('user').get('firstName'))
                primary_info.append(user.get('_source').get('doc').get('user').get('lastName'))
            elif ctrl_user == secondary_contact:
                secondary_info.append(user.get('_source').get('doc').get('user').get('firstName'))
                secondary_info.append(user.get('_source').get('doc').get('user').get('lastName'))

        if len(billing_info) < 1:
            billing_info.extend(['None', 'None'])
        if len(primary_info) < 1:
            primary_info.extend(['None', 'None'])
        if len(secondary_info) < 1:
            secondary_info.extend(['None', 'None'])
        # Get Account Service Level
        service_level = []

        data = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "_id": "accountsetting:" + alias + ":account.servicelevel"
                            }
                        }
                    ]
                }
            },
            "size": 1
        }
        result = requests.post(ES_BASE_CONNECTION, json=data, headers=headers)
        result = result.json()

        if len(result['hits']['hits']) < 1:
            service_level.append('None')

        else:
            account_level = result['hits']['hits'][0]['_source']['doc']['accountSetting']['Account.ServiceLevel']

            if account_level == 0 or account_level == 'legacy':
                service_level.append('Legacy')
            elif account_level == 1 or account_level == 'developer':
                service_level.append('Developer')
            elif account_level == 2 or account_level == 'professional':
                service_level.append('Professional')
            elif account_level == 3 or account_level == 'enterprise':
                service_level.append('Enterprise')

        # Total VMs
        data = {
            "query": {
                "bool": {
                    "should": [{"term": {"doc.vm.accountID": alias}}],
                    "must_not": [{"term": {"doc.vm.status": "deleted"}}, {"term": {"doc.vm.type": "vpn"}}]}
            },
            "size": 0,
            "aggs": {"statuses": {"terms": {"field": "doc.vm.status", "size": 50, "order": {"_term": "asc"}}}
            }
        }
        result = requests.post(ES_BASE_CONNECTION, json=data, headers=headers)
        result = result.json()
        total_vms = result['hits']['total']

        # User Message
        msg = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.0",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Medium",
                                "weight": "Bolder",
                                "text": "Business Name",
                                "horizontalAlignment": "Center"
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "weight": "Bolder",
                                                "text": "ACCOUNT INFO",
                                                "wrap": True,
                                                "separator": True,
                                                "color": "Attention"
                                            }
                                        ],
                                        "width": "stretch"
                                    }
                                ]
                            },
                            {
                                "type": "ColumnSet",
                                "style": "default",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "100px",
                                        "style": "default",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "MRR:",
                                                "wrap": True,
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Service Level:",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Account Alias:",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Account BAN:",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Address:",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Contact Info:",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Billing:"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Primary:"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Secondary:"
                                            }
                                        ]
                                    },
                                    {
                                        "type": "Column",
                                        "width": "140px",
                                        "items": [
                                        ]
                                    }
                                ]
                            },
                            {
                                "type": "TextBlock",
                                "text": "CUSTOMER FOOTPRINT",
                                "separator": True,
                                "weight": "Bolder",
                                "color": "Attention"
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "100px",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "text": "Servers:",
                                                "weight": "Bolder"
                                            },
                                            {
                                                "type": "TextBlock",
                                                "text": "Primary DC:",
                                                "weight": "Bolder"
                                            }
                                        ],
                                        "separator": True
                                    },
                                    {
                                        "type": "Column",
                                        "width": "140px",
                                        "separator": True,
                                        "items": [
                                        ]
                                    }
                                ]
                            },
                            {
                                "type": "TextBlock",
                                "text": "CUSTOMER TICKETS",
                                "separator": True,
                                "color": "Attention",
                                "weight": "Bolder"
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "width": "100px",
                                        "items": [
                                        ],
                                        "separator": True,
                                        "id": "_ticket"
                                    },
                                    {
                                        "type": "Column",
                                        "width": "140px",
                                        "separator": True,
                                        "items": [
                                        ],
                                        "id": "_ticket_info"
                                    }
                                ],
                                "id": ""
                            }
                        ],
                    }
                }
            ],
            "from": {
                "name": "Alice"
            },
            "conversation": {
                "id": conv
            },
            "serviceUrl": "https://smba.trafficmanager.net/amer/"
        }

        upper_alias = alias.upper()
        # Update the msg card
        msg['attachments'][0]['content']['body'][0]['text'] = business_name
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": "$" + mrr, "color": "Good"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": service_level[0], "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": upper_alias, "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": ban_number, "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": customer_address, "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": "----------------------------", "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": billing_info[0] + ' ' + billing_info[1], "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": primary_info[0] + ' ' + primary_info[1], "color": "Accent"})
        msg['attachments'][0]['content']['body'][2]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": secondary_info[0] + ' ' + secondary_info[1], "color": "Accent"})
        msg['attachments'][0]['content']['body'][4]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": total_vms, "color": "Accent"})
        msg['attachments'][0]['content']['body'][4]['columns'][-1]['items'].append(
            {"type": "TextBlock", "text": primary_datacenter, "color": "Accent"})


        # Get Zendesk Tickets
        start_date = (datetime.datetime.now(pytz.timezone('US/Pacific')) - datetime.timedelta(3*365/12)).date()
        end_date = (datetime.datetime.now(pytz.timezone('US/Pacific')) + datetime.timedelta(days=0)).date()

        customer_tickets = requests.get(
            'https://t3n.zendesk.com/api/v2/search.json?query=custom_field_20321291:{}+created>{}+created<{}'.format(alias, start_date, end_date),
            auth=(ALICE_ZD_CORE_USERNAME, ALICE_ZD_CORE_PASSWORD))
        ticket_response = customer_tickets.json()
        if len(ticket_response['results']) < 1:
            pass

        else:
            for tickets in ticket_response.get('results'):
                ticket_id = str(tickets.get('id'))
                subject = tickets.get('subject')
                created = tickets.get('created_at')
                updated = tickets.get('updated_at')
                status = tickets.get('status')

                msg['attachments'][0]['content']['body'][-1]['columns'][0]['items'].append({"type": "TextBlock", "text": "Ticket#: ", "weight": "Bolder"})
                msg['attachments'][0]['content']['body'][-1]['columns'][0]['items'].append(
                    {"type": "TextBlock", "text": "Subject: ", "weight": "Bolder"})
                msg['attachments'][0]['content']['body'][-1]['columns'][0]['items'].append(
                    {"type": "TextBlock", "text": "Created: ", "weight": "Bolder"})
                msg['attachments'][0]['content']['body'][-1]['columns'][0]['items'].append(
                    {"type": "TextBlock", "text": "Updated#: ", "weight": "Bolder"})
                msg['attachments'][0]['content']['body'][-1]['columns'][0]['items'].append(
                    {"type": "TextBlock", "text": "Status: ", "weight": "Bolder"})
                msg['attachments'][0]['content']['body'][-1]['columns'][0]['items'].append(
                    {"type": "TextBlock", "text": "------------", "weight": "Bolder"})
                msg['attachments'][0]['content']['body'][-1]['columns'][-1]['items'].append({"type": "TextBlock", "text": ticket_id, "color": "Accent"},)
                msg['attachments'][0]['content']['body'][-1]['columns'][-1]['items'].append({"type": "TextBlock", "text": subject, "color": "Accent"},)
                msg['attachments'][0]['content']['body'][-1]['columns'][-1]['items'].append({"type": "TextBlock", "text": created, "color": "Accent"},)
                msg['attachments'][0]['content']['body'][-1]['columns'][-1]['items'].append({"type": "TextBlock", "text": updated, "color": "Accent"},)
                msg['attachments'][0]['content']['body'][-1]['columns'][-1]['items'].append({"type": "TextBlock", "text": status, "color": "Accent"},)
                msg['attachments'][0]['content']['body'][-1]['columns'][-1]['items'].append(
                    {"type": "TextBlock", "text": "----------------------------", "color": "Accent"}, )

        requests.post(ALICE_AZ_CORE_ENDPOINT, json=msg)

        # Clear the list
        billing_info.clear()
        primary_info.clear()
        secondary_info.clear()
        service_level.clear()
        sub_accounts.clear()


if __name__ == '__main__':
    thread = threading.Thread(target=service_bus_listener, args=(process_message,))
    thread.start()
