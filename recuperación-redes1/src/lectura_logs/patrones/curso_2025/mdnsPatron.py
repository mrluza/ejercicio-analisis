'''
Patron del protocolo mDNS (Multicast DNS).

mDNS permite resolver nombres dentro de una red local sin necesidad de un
servidor DNS central. Lo usan impresoras, altavoces, televisores, etc.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa mDNS, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'mdns'.

TOPOLOGIA:
mDNS usa multicast: el origen es la IP del equipo que se anuncia y el destino
suele ser la direccion multicast (224.0.0.251 / ff02::fb). PatronPadre rellena
topo_src / topo_dst con esas IPs, de modo que en el grafo se ve que equipos se
anuncian hacia la direccion multicast.

Nota: mDNS reutiliza el formato de DNS. En algunas versiones de tshark el
trafico mDNS aparece bajo la capa 'dns' en lugar de 'mdns'. Si la captura
sale vacia, prueba a cambiar layer_name de 'mdns' a 'dns'.
'''
from lectura_logs.PatronPadre import PatronPadre


class mdnsPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'mdns'

    def __init__(self, path_log):
        super().__init__('mdns.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa mDNS (+ campos de topologia).
        return self.extraer_todo(data_string)
