'''
Patron del protocolo ARP (Address Resolution Protocol).

ARP se utiliza dentro de una red local para averiguar que direccion fisica
(MAC) corresponde a una direccion IP conocida.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa ARP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'arp'.
'''
from lectura_logs.PatronPadre import PatronPadre


class arpPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'arp'

    def __init__(self, path_log):
        # Nombre del archivo JSON de salida.
        super().__init__('arp.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa ARP.
        return self.extraer_todo(data_string)
