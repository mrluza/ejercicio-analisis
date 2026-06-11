'''
Patron del protocolo DNS (Domain Name System).

DNS traduce los nombres de dominio legibles por las personas en las
direcciones IP que necesitan los equipos.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa DNS, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'dns'.

TOPOLOGIA:
DNS viaja sobre IP, asi que los nodos del grafo son las IPs del cliente y del
servidor DNS. PatronPadre rellena topo_src / topo_dst con esas IPs.
'''
from lectura_logs.PatronPadre import PatronPadre


class dnsPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'dns'

    def __init__(self, path_log):
        super().__init__('dns.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa DNS (+ campos de topologia).
        return self.extraer_todo(data_string)
