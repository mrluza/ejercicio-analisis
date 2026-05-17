'''
Patron del protocolo TCP (Transmission Control Protocol).

TCP es el protocolo de transporte que ofrece una comunicacion fiable y
ordenada entre dos equipos.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa TCP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'tcp'.
'''
from lectura_logs.PatronPadre import PatronPadre


class tcpPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'tcp'

    def __init__(self, path_log):
        super().__init__('tcp.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa TCP.
        return self.extraer_todo(data_string)
