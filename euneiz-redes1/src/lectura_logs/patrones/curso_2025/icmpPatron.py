'''
Patron del protocolo ICMP (Internet Control Message Protocol).

ICMP transporta mensajes de control, error y diagnostico entre los equipos
de una red. Es el protocolo que usan herramientas como ping y traceroute.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa ICMP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'icmp'.
'''
from lectura_logs.PatronPadre import PatronPadre


class icmpPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'icmp'

    def __init__(self, path_log):
        super().__init__('icmp.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa ICMP.
        return self.extraer_todo(data_string)
