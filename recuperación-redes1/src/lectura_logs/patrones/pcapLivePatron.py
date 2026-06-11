'''
Created on 14 jun. 2018
@author: pgg

Patron "comodin": no filtra por protocolo. Devuelve el paquete entero tal cual
llega (con todas sus capas). Util para explorar que protocolos circulan por la
red antes de decidir que patron concreto usar.
'''
from lectura_logs.PatronPadre import PatronPadre


class pcapLivePatron(PatronPadre):
    '''
    Clase patron de la captura pacp en formato live
    '''

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'pcap_live', path_log)

    def process_log_data(self, data_string):
        # No filtramos nada: solo marcamos el origen y devolvemos el paquete
        # completo (todas las capas y todos sus campos).
        data_string['db_name'] = self.tipo
        return data_string
