from scapy.all import *
from ritm.logger import logger
from threading import Thread, currentThread

PA_ENC_TIMESTAMP = 0x2


class Sniffer:

    def __init__(self, interface):
        self.__interface = interface
        self.__sniff_thread = None
        self.as_req_packet = None


    # called as each packet is sniffed
    # search for AS-REQ with PA-ENC-TIMESTAMP
    def __call__(self, packet):
        if TCP in packet:
            if packet[TCP].dport == 88: 
                if KRB_AS_REQ in packet:
                    if packet[Kerberos].root.padata[0].padataType == PA_ENC_TIMESTAMP:
                        logger.debug('Found AS-REP with padata-type PA-ENC-TIMESTAMP')
                        self.as_req_packet = packet
                        return


    # method for sniffer thread
    def _sniff(self):
        current_thread = currentThread()    
        sniff(iface=self.__interface, prn=self, store=0, stop_filter=lambda x: getattr(current_thread, "exit", False))
        
        logger.debug('Terminated sniffer thread')


    # start the sniffer to locate an AS-REQ
    def run(self):
        logger.info('Sniffer waiting for AS-REQ...')
        try:
            self.__sniff_thread = Thread(target=self._sniff, daemon=True)
            self.__sniff_thread.start()
            #sniff(iface=self.__interface, prn=self, store=0)
        except OSError as e:
            if 'No such device' in str(e):
                logger.error(f'{self.__interface} is not a valid interface')
            else:
                logger.error(str(e))
            exit(1)


    # shutdown the sniffer
    def stop(self):
        self.__sniff_thread.exit = True
        self.__sniff_thread.join()