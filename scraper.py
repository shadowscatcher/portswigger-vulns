import asyncio
import json
import logging
import os
from asyncio import Queue
from dataclasses import dataclass
from typing import Tuple, List

import aiohttp
import bs4
from bs4 import BeautifulSoup

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Configuration with environment variable defaults
VULNERABILITIES_LIST_URL = os.getenv('VULNERABILITIES_LIST_URL', 'https://portswigger.net/burp/documentation/scanner/vulnerabilities-list')
OUTPUT_FILE = os.getenv('OUTPUT_FILE', 'vulnerabilities.json')
MAX_WORKERS = int(os.getenv('MAX_WORKERS', 10))

@dataclass
class Vulnerability:
    name: str
    severity: str
    id_hex: str
    id_dec: int
    cwes: List[str]
    link: str
    description: str = ''
    remediation: str = ''

    def to_dict(self):
        return self.__dict__

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

# Asynchronous function to fetch the content of a URL
async def fetch(session, url):
    try:
        logger.info("fetching url: %s", url)
        async with session.get(url) as response:
            if response.status == 200:
                return await response.text()
            else:
                logger.warning("failed to fetch %s: %s", url, response.status)
    except Exception as e:
        logger.error("error fetching %s: %s", url, e)

# Parse vulnerabilities list to get IDs, CWEs, and links
def parse_vulnerabilities_list(html: str) -> List[Vulnerability]:
    soup = BeautifulSoup(html, 'html.parser')
    vulnerabilities = []

    for row in soup.select('table tbody tr'):
        cols = row.find_all('td')
        if len(cols) >= 5:
            link_tag = cols[0].find('a')
            link = link_tag['href'] if link_tag else ''

            vuln = Vulnerability(
                name=cols[0].text.strip(),
                severity=cols[1].text.strip(),
                id_hex=cols[2].text.strip(),
                id_dec=int(cols[3].text.strip()),
                cwes=[cwe.strip() for cwe in cols[4].text.split('\n') if cwe.strip()],
                link=f"https://portswigger.net{link}" if link else ''
            )
            vulnerabilities.append(vuln)
            logger.info("successfully parsed vulnerability: %s (%d)", vuln.name, vuln.id_dec)
    return vulnerabilities

# Extract vulnerability details from individual pages
def parse_vulnerability_details(html: str) -> Tuple[str, str]:
    soup = BeautifulSoup(html, 'html.parser')
    # a description is <p> tags that follow h2 with text starting with "Description:" and before the next h2
    # same logic applies to remediation. The markup is kept for the description and remediation
    description, remediation = '', ''
    for h2 in soup.find_all('h2'):
        text = h2.text.strip()
        siblings = h2.find_next_siblings()
        if text.startswith('Description:'):
            description = add_siblings_before_header(siblings)
        elif text.startswith('Remediation:'):
            remediation = add_siblings_before_header(siblings)
    return description, remediation


def add_siblings_before_header(siblings: List[bs4.Tag]) -> str:
    result = ''
    for s in siblings:
        if s.name.startswith('h'):  # next header
            break
        result += str(s)
    return result


# Load existing vulnerabilities from the JSON file
def load_existing_vulnerabilities(output_file: str) -> List[Vulnerability]:
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            raw = json.load(f)
            return [Vulnerability.from_dict(v) for v in raw]
    return []

# Worker function to process vulnerability details
async def worker(input_queue: Queue, output_queue: Queue, session: aiohttp.ClientSession):
    while True:
        vuln: Vulnerability = await input_queue.get()
        if vuln is None:
            break
        html = await fetch(session, vuln.link)
        if html:
            description, remediation = parse_vulnerability_details(html)
            # Update the vulnerability with the details and add it to the output queue
            vuln.description = description
            vuln.remediation = remediation
        await output_queue.put(vuln)
        input_queue.task_done()

# Process vulnerabilities with asyncio queues
async def process_vulnerabilities(session: aiohttp.ClientSession, vulnerabilities_list_url: str, output_file: str, concurrency:int=10):
    existing_vulnerabilities = load_existing_vulnerabilities(output_file)
    existing_ids = {v.id_hex for v in existing_vulnerabilities}

    vuln_list_html = await fetch(session, vulnerabilities_list_url)
    vulnerabilities = parse_vulnerabilities_list(vuln_list_html)
    new_vulnerabilities = [v for v in vulnerabilities if v.id_hex not in existing_ids]

    input_queue = asyncio.Queue()  # Queue to hold vulnerabilities to be processed
    output_queue = asyncio.Queue()  # Queue to hold processed vulnerabilities

    for vuln in new_vulnerabilities:
        await input_queue.put(vuln)

    workers = [asyncio.create_task(worker(input_queue, output_queue, session)) for _ in range(concurrency)]

    await input_queue.join()

    for _ in range(concurrency):
        await input_queue.put(None)

    await asyncio.gather(*workers)

    processed_vulnerabilities = existing_vulnerabilities + [await output_queue.get() for _ in range(output_queue.qsize())]
    processed_vulnerabilities.sort(key=lambda x: x.id_dec)

    if new_vulnerabilities:
        with open(output_file, 'w') as fp:
            json.dump([v.to_dict() for v in processed_vulnerabilities], fp, indent=2)
        logger.info("added %d new vulnerabilities.", len(new_vulnerabilities))
    else:
        logger.info("no new vulnerabilities found.")

# Main asynchronous function
async def main(vulnerabilities_list_url: str, output_file: str, concurrency:int=10):
    async with aiohttp.ClientSession() as session:
        await process_vulnerabilities(session, vulnerabilities_list_url, output_file, concurrency)

# Entry point
if __name__ == "__main__":
    asyncio.run(main(VULNERABILITIES_LIST_URL, OUTPUT_FILE, MAX_WORKERS))

