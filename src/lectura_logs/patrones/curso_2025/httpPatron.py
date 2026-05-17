'''
Patron del protocolo HTTP (HyperText Transfer Protocol).

HTTP es el protocolo de aplicacion que sustenta la web. Sigue un modelo de
peticion y respuesta entre un cliente y un servidor.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa HTTP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'http'.
'''
from lectura_logs.PatronPadre import PatronPadre


class httpPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'http'

    def __init__(self, path_log):
        super().__init__('http.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa HTTP.
        return self.extraer_todo(data_string)
