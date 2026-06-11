'''
Punto de entrada del sniffer.

Lo que hace este fichero, paso a paso:
  1. Lee la configuracion (conf/conf.ini).
  2. Elige el patron del protocolo segun el valor de 'log_type'.
  3. Muestra una ficha explicativa del protocolo elegido.
  4. Lanza la captura (clase NetSniffer).
'''
from utils.ConfigReader import ConfigReader
import os
import json
from net.NetSniffer import NetSniffer

# Colores para que la salida de la consola se vea mas clara.
R  = '\033[0m'       # reset (vuelve al color normal)
B  = '\033[1m'       # negrita
DM = '\033[2m'       # gris/atenuado
CY = '\033[96m'      # cian
GR = '\033[92m'      # verde
YL = '\033[93m'      # amarillo
MG = '\033[95m'      # magenta
RD = '\033[91m'      # rojo

# Importamos todos los patrones de protocolo disponibles.
from lectura_logs.patrones.connPatron import connPatron
from lectura_logs.patrones.pcapLivePatron import pcapLivePatron
from lectura_logs.patrones.curso_2025.arpPatron import arpPatron
from lectura_logs.patrones.curso_2025.dnsPatron import dnsPatron
from lectura_logs.patrones.curso_2025.tcpPatron import tcpPatron
from lectura_logs.patrones.curso_2025.httpPatron import httpPatron
from lectura_logs.patrones.curso_2025.dhcpPatron import dhcpPatron
from lectura_logs.patrones.curso_2025.icmpPatron import icmpPatron
from lectura_logs.patrones.curso_2025.tlsPatron import tlsPatron
from lectura_logs.patrones.curso_2025.mdnsPatron import mdnsPatron

# Tabla que relaciona el nombre que se pone en conf.ini ('log_type')
# con la clase de patron que hay que usar.
logs_patterns_types = {
    'conn': connPatron,
    'pcap_live': pcapLivePatron,
    'arp': arpPatron,
    'dns': dnsPatron,
    'tcp': tcpPatron,
    'http': httpPatron,
    'dhcp': dhcpPatron,
    'icmp': icmpPatron,
    'tls': tlsPatron,
    'mdns': mdnsPatron
}

# Ruta a la carpeta conf/ (esta un nivel por encima de src/).
_conf_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'conf')

def _load_json(filename):
    # Abre un JSON de la carpeta conf/ y lo devuelve como diccionario.
    with open(os.path.join(_conf_dir, filename), encoding='utf-8') as f:
        return json.load(f)

# Textos explicativos de cada protocolo (se muestran al arrancar).
PATRON_INFO = _load_json('patron_info.json')


def __launch_net_process(project_name, log_type, interfaces, custome_filters='', solo_resumen=True):
    # Crea el sniffer con la configuracion leida y arranca la captura.
    lg = NetSniffer(project_name, log_type, interfaces, custome_filters, solo_resumen)
    lg.comenzar()


def __get_current_log_patterns(log_type, log_path):
    # Devuelve una instancia del patron que corresponde a 'log_type'.
    # Si ese nombre no existe en la tabla, avisa y termina el programa.
    try:
        return logs_patterns_types[log_type](log_path)
    except KeyError:
        print(f'\n{RD}{B}[ERROR]{R} El patrón "{RD}{log_type}{R}" no existe.')
        print(f'        Patrones disponibles: {YL}{", ".join(logs_patterns_types.keys())}{R}')
        print(f'        Revisa el valor de {CY}log_type{R} en conf/conf.ini')
        exit(0)


import textwrap

def __print_patron_info(log_type):
    # Imprime la ficha del protocolo elegido (capa, campos, descripcion...)
    # leyendola de patron_info.json. Es solo informativo.
    info = PATRON_INFO.get(log_type)
    if not info:
        return

    ancho_total = 100

    # Sangria para que, si una linea es muy larga y se parte, quede alineada.
    sangria = "                   "
    wrapper = textwrap.TextWrapper(width=ancho_total, subsequent_indent=sangria)

    sep = f'{CY}{"─" * ancho_total}{R}'

    print(f'\n{sep}')
    print(f'  {B}{CY}PATRÓN ACTIVO{R}  : {B}{YL}{log_type.upper()}{R}')
    print(f'\n  {CY}Protocolo{R}      : {GR}{info["protocolo"]}{R}')
    print(f'\n  {CY}Capa OSI{R}       : {MG}{info["capa"]}{R}')
    print(f'\n  {CY}Campos{R}         : {DM}{info["campos"]}{R}')

    desc_texto = f'{CY}Descripción{R}    : {info["descripcion"]}'
    print(f'\n  {wrapper.fill(desc_texto)}')

    ej_texto = f'{CY}Ejemplo{R}        : {YL}{info["ejemplo"]}{R}'
    print(f'\n  {wrapper.fill(ej_texto)}')


if __name__ == '__main__':
    print(f'{CY}Iniciando...{R}')

    # Cargamos el fichero de configuracion conf/conf.ini.
    config_file = (os.path.dirname(os.path.realpath(__file__)).replace('/src', '')) + '/conf/conf.ini'
    config = ConfigReader(config_file)

    # Banner del proyecto (solo decorativo).
    print("")
    print(f'{B}{CY}' + r"  _           _____   _____  _____  " + f'{R}')
    print(f'{B}{CY}' + r" | |         |  __ \ / ____|/ ____| " + f'{R}')
    print(f'{B}{CY}' + r" | |__  _   _| |__) | |  __| |  __  " + f'{R}')
    print(f'{B}{CY}' + r" | '_ \| | | |  ___/| | |_ | | |_ | " + f'{R}')
    print(f'{B}{CY}' + r" | |_) | |_| | |    | |__| | |__| | " + f'{R}')
    print(f'{B}{CY}' + r" |_.__/ \__, |_|     \_____|\_____| " + f'{R}')
    print(f'{B}{CY}' + r"         __/ |                      " + f'{R}')
    print(f'{B}{CY}' + r"        |___/                       " + f'{R}')
    print(f'{DM}  Sniffer de red — Grado en Seguridad EUNEIZ{R}')
    print("")

    # Leemos del conf.ini el nombre del proyecto y el filtro BPF (opcional).
    project_name = config.ConfigSectionMap('App')['project_name']
    custome_filters = config.ConfigSectionMap('App')['net_custome_filters']

    # Elegimos el patron del protocolo y mostramos su ficha.
    log_type_name = config.ConfigSectionMap('App')['log_type']
    log_type = __get_current_log_patterns(log_type_name, '')
    __print_patron_info(log_type_name)

    # La interfaz puede venir como una lista separada por comas.
    interfaces = config.ConfigSectionMap('App')['net_sniffer_interface']
    interfaces = interfaces.split(',')

    # net_summarize: true  -> solo muestra los paquetes por pantalla.
    # net_summarize: false -> ademas los GUARDA en el JSON de salida.
    net_summarize = True
    if 'net_summarize' in config.ConfigSectionMap('App'):
        net_summarize = config.getBoolean('App', 'net_summarize')

    # Arrancamos la captura.
    __launch_net_process(project_name, log_type, interfaces, custome_filters, net_summarize)

    print(f'\n{CY}── Captura finalizada ──{R}')
    print(f'{DM}FIN{R}')
