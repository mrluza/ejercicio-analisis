'''
Patron del protocolo TLS (Transport Layer Security).

TLS es el protocolo que cifra las comunicaciones para que viajen de forma
segura por la red. Es la base de HTTPS.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa TLS, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'tls'.

TOPOLOGIA:
TLS va sobre TCP/IP, asi que los nodos del grafo son las IPs del cliente y del
servidor seguro. PatronPadre rellena topo_src / topo_dst con esas IPs.
'''
from lectura_logs.PatronPadre import PatronPadre


class tlsPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'tls'

    def __init__(self, path_log):
        super().__init__('tls.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa TLS (+ campos de topologia).
        return self.extraer_todo(data_string)
