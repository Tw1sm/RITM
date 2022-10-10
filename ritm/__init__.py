import logging

__version__ = '0.1.2'

# kill off Scapy's logger
logging.getLogger('scapy').setLevel(logging.CRITICAL)