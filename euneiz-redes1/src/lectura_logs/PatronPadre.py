'''
Created on 14 jun. 2018
https://www.bro.org/sphinx/script-reference/log-files.html
@author: pgg

------------------------------------------------------------------------------
MODIFICADO para la Practica de Redes 1:

Se ha anadido el metodo extraer_todo(), comun a todos los patrones, que
captura TODOS los campos del protocolo (sin filtrar ninguno).

Antes, cada patron tenia una lista 'dict_values' con unos pocos campos y solo
guardaba esos. Ahora los patrones capturan la capa completa del protocolo, con
todos sus campos. La logica esta centralizada aqui, asi que cada patron hijo
solo tiene que indicar cual es su capa (layer_name).
------------------------------------------------------------------------------
'''
from abc import abstractmethod, ABCMeta
import datetime


class PatronPadre(object):
    __metaclass__ = ABCMeta
    
    '''
    Clase padre de los patrones
    '''
    tipo = 'ABSTRACTO_PADRE_PGG'
    path_log = None
    boolean_true_values = ['t', 'tr', 'true']
    boolean_false_values = ['f', 'fa', 'false']
    date_pattern = '%Y-%m-%d_%H:%M:%S'

    # Nombre de la capa del protocolo dentro de data_string['layers'].
    # Cada patron hijo lo define (ej: 'http', 'icmp', 'arp'...). Sirve para
    # localizar la capa del protocolo dentro del paquete capturado.
    layer_name = None

    def __init__(self, tipo, path_log):
        '''
        Constructor
        '''
        self.tipo = tipo
        self.path_log = path_log

    def extraer_todo(self, data_string):
        '''
        Metodo COMUN a todos los patrones.

        Captura TODOS los campos de la capa del protocolo, sin filtrar.

        - Si el paquete no contiene la capa del protocolo, devuelve None
          (asi se descartan los paquetes que no interesan).
        - Si la contiene, devuelve un diccionario con todos los campos de
          esa capa, limpiando el texto 'LayerFieldsContainer:' que mete
          tshark por defecto, y anade el identificador db_name.

        El patron hijo solo tiene que tener definido 'layer_name' y llamar
        a este metodo desde process_log_data.
        '''
        capa = self.layer_name

        # El paquete no tiene la capa de este protocolo -> se descarta
        if 'layers' not in data_string or capa not in data_string['layers']:
            return None

        datos_capa = data_string['layers'][capa]

        # Copiamos TODOS los campos de la capa, sin filtrar ninguno.
        resultado = {}
        for clave, valor in datos_capa.items():
            if isinstance(valor, str):
                # Limpieza del texto que tshark anade por defecto.
                resultado[clave] = valor.replace('LayerFieldsContainer:', '').strip()
            else:
                resultado[clave] = valor

        # Identificador del log de procedencia.
        resultado['db_name'] = self.tipo
        return resultado
    
    @abstractmethod
    def generate_result_dict_from_pattern_data(self, pattern_data_list):
        result = {}
        for info in pattern_data_list:
            result[info] = ''
        return result 
    
    @abstractmethod
    def process_log_data(self, data_string):
        return {}
    
    @abstractmethod
    def prepare_data_to_send(self, dict_to_send):
        dict_to_send['db_name'] = self.tipo
        for key, value in dict_to_send.items():
            if(isinstance(value, datetime.datetime)):
                dict_to_send[key] = value.strftime(self.date_pattern)
        return dict_to_send
    
    @abstractmethod
    def change_date_to_string(self, date_value):
        return date_value.strftime(self.date_pattern)
    
    @abstractmethod
    def get_date_from_int(self, data):
#         data = (data / 1000)
#         return datetime.datetime.fromtimestamp(data / 1e3)
        return datetime.datetime.fromtimestamp(data)
    
    @abstractmethod
    def enrich_processed_log_data(self, resultado):
        self.process_empty_log_data(resultado, self.dict_values)
        try:
            resultado[self.dict_values[0]] = self.get_date_from_int(resultado[self.dict_values[0]])
        except:
            print('posicion 0 no es date en long')
        
        return resultado
    
    @abstractmethod
    def process_empty_log_data(self, log_dict, log_list):
        for key in log_list:
            value_to_check = log_dict[key].lower() 
            
            if ((value_to_check == '') or (value_to_check == '-')):
                # value is missing
                log_dict[key] = None
            elif(value_to_check in self.boolean_false_values):
                # value is boolean FALSE
                log_dict[key] = False
            elif(value_to_check in self.boolean_true_values):
                # value is boolean TRUE
                log_dict[key] = True
            else:
                # value is a number
                try:
                    new_value = float(log_dict[key])
                    if new_value.is_integer():
                        new_value = int(new_value)
                    log_dict[key] = new_value
                except:
                    pass
        return log_dict
