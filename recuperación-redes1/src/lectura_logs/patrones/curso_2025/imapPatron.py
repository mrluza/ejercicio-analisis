'''
Created on 29 abr. 2025
https://www.bro.org/sphinx/scripts/base/protocols/imap/main.bro.html
@author: pgg

Patron del protocolo IMAP (Internet Message Access Protocol).
IMAP es el protocolo para leer correo electronico desde un servidor.

MODIFICADO para la Practica de Redes 1:
Este patron captura TODOS los campos de la capa IMAP, sin filtrar ninguno.
La logica esta en PatronPadre.extraer_todo(); aqui solo se indica que la
capa del protocolo se llama 'imap'.

TOPOLOGIA:
IMAP va sobre TCP/IP, asi que los nodos del grafo son las IPs del cliente de
correo y del servidor IMAP. PatronPadre rellena topo_src / topo_dst con esas IPs.
'''
from lectura_logs.PatronPadre import PatronPadre


class imapPatron(PatronPadre):

    # Nombre de la capa del protocolo dentro del paquete capturado.
    layer_name = 'imap'

    def __init__(self, path_log):
        super().__init__('imap.log', path_log)

    def process_log_data(self, data_string):
        # Captura todos los campos de la capa IMAP (+ campos de topologia).
        return self.extraer_todo(data_string)
