'''
Patron del protocolo DHCP (Dynamic Host Configuration Protocol).

DHCP asigna automaticamente la configuracion de red (direccion IP, mascara,
puerta de enlace y servidores DNS) a los equipos que se conectan a una red.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa DHCP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'dhcp'.

TOPOLOGIA:
DHCP va sobre IP/UDP, asi que los nodos del grafo son las IPs del cliente y
del servidor DHCP (al inicio el cliente aun no tiene IP, por lo que puede
aparecer 0.0.0.0). PatronPadre rellena topo_src / topo_dst con esas IPs.

Nota: en algunas versiones de tshark la capa DHCP aparece como 'bootp' en
lugar de 'dhcp'. Si la captura sale vacia, prueba a cambiar layer_name de
'dhcp' a 'bootp'.
'''
from lectura_logs.PatronPadre import PatronPadre


class dhcpPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'dhcp'

    def __init__(self, path_log):
        super().__init__('dhcp.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa DHCP (+ campos de topologia).
        return self.extraer_todo(data_string)
