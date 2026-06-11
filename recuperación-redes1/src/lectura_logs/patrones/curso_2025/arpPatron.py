'''
Patron del protocolo ARP (Address Resolution Protocol).

ARP se utiliza dentro de una red local para averiguar que direccion fisica
(MAC) corresponde a una direccion IP conocida.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa ARP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'arp'.

TOPOLOGIA:
Para ARP, los "nodos" del grafo son las MAC de los equipos. PatronPadre se
encarga de rellenar topo_src / topo_dst con las MAC origen y destino de la
trama ARP (campos src_hw_mac / dst_hw_mac de tshark). No hay que hacer nada
extra aqui: basta con que layer_name valga 'arp'.
'''
from lectura_logs.PatronPadre import PatronPadre


class arpPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'arp'

    def __init__(self, path_log):
        # Nombre del archivo JSON de salida.
        super().__init__('arp.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa ARP (+ campos de topologia).
        return self.extraer_todo(data_string)
