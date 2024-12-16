"""
subscription.py

An ansible-rulebook event source plugin template.

Arguments:
  - apic1: APIC IP or hostname
  - username: APIC username
  - password: APIC password
  - subscriptions: query api endpoints for subscriptions
  - refresh_timeout: (optional) timeout of subscription

Examples:
  cisco.aci_eda.websocket:
    hostname: apic1
    username: ansible
    password: ansible
    subscriptions:
        - /api/mo/uni/tn-demo/ap-demo/epg-demo.json?query-target=children&target-subtree-class=fvCEp&query-target=subtree
    refresh_timeout: 60

"""
import asyncio
import json
import os
import sys
import signal
import ssl
from typing import Any, Dict, NoReturn
import requests
import websockets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def login(hostname: str, username: str, password: str) -> str:
    """
    login to apic and get session token

    :param hostname: apic hostname or ip
    :param username: apic username
    :param password: apic password
    :return: session token
    """
    login_url = f"https://{hostname}/api/aaaLogin.json"
    payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
    token = ""

    login_response = requests.post(login_url, json=payload, verify=False)
    if login_response.ok:
        response_json = login_response.json()
        token = response_json["imdata"][0]["aaaLogin"]["attributes"]["token"]
    return token


def subscribe(hostname: str, token: str, rf_timeout: int, sub_urls: list[str]) -> list[str]:
    """
    subscribe to a websocket

    :param hostname: apic hostname or ip
    :param token: apic session token
    :param rf_timeout: refresh timeout of subscription
    :param sub_urls: subscriptions url
    :return: list of subscription ids
    """
    sub_ids = []

    for sub in sub_urls:
        sub_url = (
            f"https://{hostname}{sub}&subscription=yes&refresh-timeout={rf_timeout}"
        )
        cookie = {"APIC-cookie": token}
        sub_response = requests.get(sub_url, verify=False, cookies=cookie, timeout=60)
        if sub_response.ok:
            sub_id = sub_response.json()["subscriptionId"]
            sub_ids.append(sub_id)
    return sub_ids


async def refresh(hostname: str, token: str, refresh_timeout: int, sub_ids: list[str]) -> NoReturn:
    """
    refresh subscriptions

    :param hostname: apic hostname or ip
    :param token: session token
    :param refresh_timeout: subscription refresh timeout
    :param sub_ids: subscription ids
    :return: NoReturn
    """
    cookie = {"APIC-cookie": token}
    while True:
        await asyncio.sleep(refresh_timeout / 2)
        for sub_id in sub_ids:
            refresh_url = f"https://{hostname}/api/subscriptionRefresh.json?id={sub_id}"
            requests.get(refresh_url, verify=False, cookies=cookie, timeout=60)


async def main(queue: asyncio.Queue, args: Dict[str, Any]):
    hostname = args.get("hostname", "")
    username = args.get("username", "")
    password = args.get("password", "")
    refresh_timeout = int(args.get("refresh_timeout", 300))
    subscriptions = args.get("subscriptions")

    if "" in [hostname, username, password]:
        print(
            f"hostname, username and password can't be empty:{hostname}, {username}, *****"
        )
        sys.exit(1)

    if (
        not isinstance(subscriptions, list)
        or subscriptions == []
        or subscriptions is None
    ):
        print(f"subscriptions is empty or not a list: {subscriptions}")
        sys.exit(1)

    token = login(hostname=hostname, username=username, password=password)
    websocket_uri = f"wss://{hostname}/socket{token}"
    ctx = ssl.SSLContext()

    async with websockets.connect(websocket_uri, ssl=ctx) as ws:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, loop.create_task, ws.close())
        sub_ids = subscribe(hostname, token, refresh_timeout, subscriptions)

        # task to refresh subscription token
        asyncio.create_task(refresh(hostname, token, refresh_timeout, sub_ids))

        async for message in ws:
            await queue.put(json.loads(message))


if __name__ == "__main__":
    # this function is conly called when executed directly
    apic_username = os.environ["apic_username"]
    apic_password = os.environ["apic_password"]
    apic_url = os.environ["apic_url"]

    class MockQueue(asyncio.Queue):
        async def put(self, item):
            print(item)

    mock_arguments = {
        "hostname": apic_url,
        "username": apic_username,
        "password": apic_password,
        "subscriptions": [
            '/api/node/class/faultInst.json?query-target-filter=and(eq(faultInst.code,"F1386"))',
        ],
        "refresh_timeout": 30,
    }
    asyncio.run(main(MockQueue(), mock_arguments))