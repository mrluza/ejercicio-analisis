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
AMPLIACION (datos para la grafica de nodos):

Para poder dibujar despues la grafica de nodos de la red necesitamos saber,
en cada paquete, QUIEN habla con QUIEN. Pero ojo: la capa del protocolo no
siempre contiene esa informacion. Por ejemplo, la capa 'icmp' NO lleva las IPs
(las IPs van en la capa 'ip', que esta por debajo). Por eso, ademas de copiar
los campos del protocolo como hasta ahora, ahora extraemos tambien un par de
campos NUEVOS:

    topo_src   -> identificador del que envia    (IP o MAC)
    topo_dst   -> identificador del que recibe   (IP o MAC)
    topo_tipo  -> 'ip' o 'mac', segun el tipo de identificador

El sniffer NO dibuja nada: solo deja estos datos en el JSON. Con ellos, cada
nodo es un host (un valor de topo_src/topo_dst) y cada arista es una
comunicacion (un par origen->destino). Los campos antiguos del protocolo se
mantienen TAL CUAL; estos solo se anaden encima.
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
        # 'tipo' es el nombre del log de salida (p.ej. 'icmp.log') y 'path_log'
        # la ruta de origen cuando se lee de fichero (en captura en vivo va vacio).
        self.tipo = tipo
        self.path_log = path_log

    # ------------------------------------------------------------------
    # Pequena utilidad: tshark a veces mete el prefijo 'LayerFieldsContainer:'
    # delante del valor real. Esta funcion lo limpia. La sacamos a un metodo
    # aparte porque ahora la necesitamos en mas de un sitio.
    # ------------------------------------------------------------------
    def _limpiar(self, valor):
        if isinstance(valor, str):
            return valor.replace('LayerFieldsContainer:', '').strip()
        return valor

    # ------------------------------------------------------------------
    # NUEVO: extrae el "origen" y el "destino" del paquete para la topologia.
    #
    # La idea es: dependiendo del protocolo, el par origen/destino vive en una
    # capa distinta del paquete. Aqui decidimos de donde sacarlo:
    #
    #   - ARP  -> es un protocolo de capa 2, asi que usamos las direcciones MAC
    #             (y si no, las IP que viajan dentro de la propia trama ARP).
    #   - IP   -> la mayoria de protocolos (icmp, tcp, http, dns, tls...) van
    #             sobre IP, asi que cogemos ip.src / ip.dst.
    #   - IPv6 -> mismo caso que IP pero version 6.
    #   - eth  -> si no hay capa IP, nos quedamos con las MAC de la trama.
    #
    # Devuelve una tupla (origen, destino, tipo) donde tipo es 'ip' o 'mac'.
    # ------------------------------------------------------------------
    def _extraer_endpoints(self, data_string):
        capas = data_string.get('layers', {})

        # --- Caso ARP: identificadores dentro de la propia capa arp ---
        # En ARP nos interesan las MAC (el enunciado pide MACs para ARP).
        # tshark las nombra como src_hw_mac / dst_hw_mac; las IP como
        # src_proto_ipv4 / dst_proto_ipv4. Probamos primero MAC, luego IP.
        if self.layer_name == 'arp' and 'arp' in capas:
            arp = capas['arp']
            src_mac = arp.get('src_hw_mac')
            dst_mac = arp.get('dst_hw_mac')
            if src_mac or dst_mac:
                return self._limpiar(src_mac), self._limpiar(dst_mac), 'mac'
            # Si no hubiera MAC, caemos a las IP que anuncia el ARP.
            return (self._limpiar(arp.get('src_proto_ipv4')),
                    self._limpiar(arp.get('dst_proto_ipv4')),
                    'ip')

        # --- Caso general: protocolos sobre IP (icmp, tcp, dns, http...) ---
        if 'ip' in capas:
            ip = capas['ip']
            return self._limpiar(ip.get('src')), self._limpiar(ip.get('dst')), 'ip'

        if 'ipv6' in capas:
            ip6 = capas['ipv6']
            return self._limpiar(ip6.get('src')), self._limpiar(ip6.get('dst')), 'ip'

        # --- Ultimo recurso: no hay IP, usamos las MAC de Ethernet ---
        if 'eth' in capas:
            eth = capas['eth']
            return self._limpiar(eth.get('src')), self._limpiar(eth.get('dst')), 'mac'

        # No hemos podido identificar a los extremos.
        return None, None, None

    def extraer_todo(self, data_string):
        '''
        Metodo COMUN a todos los patrones.

        Captura TODOS los campos de la capa del protocolo, sin filtrar.

        - Si el paquete no contiene la capa del protocolo, devuelve None
          (asi se descartan los paquetes que no interesan).
        - Si la contiene, devuelve un diccionario con todos los campos de
          esa capa, limpiando el texto 'LayerFieldsContainer:' que mete
          tshark por defecto, y anade el identificador db_name.

        Ademas (AMPLIACION) anade los campos topo_src / topo_dst / topo_tipo
        para poder construir despues el grafo de la red.

        El patron hijo solo tiene que tener definido 'layer_name' y llamar
        a este metodo desde process_log_data.
        '''
        capa = self.layer_name

        # El paquete no tiene la capa de este protocolo -> se descarta.
        if 'layers' not in data_string or capa not in data_string['layers']:
            return None

        datos_capa = data_string['layers'][capa]

        # Copiamos TODOS los campos de la capa, sin filtrar ninguno
        # (esto es exactamente lo que ya hacia antes; no se toca).
        resultado = {}
        for clave, valor in datos_capa.items():
            resultado[clave] = self._limpiar(valor)

        # ------------------------------------------------------------------
        # NUEVO: anadimos los campos de topologia. Son los datos que hacen
        # falta para construir la grafica de nodos (quien habla con quien).
        # Solo los anadimos si realmente hemos podido identificar a los
        # extremos, para no ensuciar el JSON con valores vacios.
        # ------------------------------------------------------------------
        origen, destino, tipo = self._extraer_endpoints(data_string)
        if origen:
            resultado['topo_src'] = origen
        if destino:
            resultado['topo_dst'] = destino
        if tipo and (origen or destino):
            resultado['topo_tipo'] = tipo

        # Identificador del log de procedencia.
        resultado['db_name'] = self.tipo
        return resultado

    @abstractmethod
    def generate_result_dict_from_pattern_data(self, pattern_data_list):
        # Crea un diccionario vacio (valor '') con una clave por cada campo
        # de la lista. Lo usa el patron 'conn', que si filtra campos concretos.
        result = {}
        for info in pattern_data_list:
            result[info] = ''
        return result

    @abstractmethod
    def process_log_data(self, data_string):
        # Metodo que cada patron hijo implementa. Recibe el paquete ya
        # convertido a diccionario y devuelve los datos que se guardaran
        # (o None si el paquete no interesa para ese patron).
        return {}

    @abstractmethod
    def prepare_data_to_send(self, dict_to_send):
        # Metodo heredado (de la version original del proyecto). Marca el
        # origen (db_name) y convierte las fechas a texto. En esta version
        # basica no se usa, pero se deja por compatibilidad.
        dict_to_send['db_name'] = self.tipo
        for key, value in dict_to_send.items():
            if(isinstance(value, datetime.datetime)):
                dict_to_send[key] = value.strftime(self.date_pattern)
        return dict_to_send

    @abstractmethod
    def change_date_to_string(self, date_value):
        # Pasa un objeto fecha a cadena con el formato del proyecto.
        return date_value.strftime(self.date_pattern)

    @abstractmethod
    def get_date_from_int(self, data):
        # Convierte un timestamp (segundos) a un objeto fecha de Python.
#         data = (data / 1000)
#         return datetime.datetime.fromtimestamp(data / 1e3)
        return datetime.datetime.fromtimestamp(data)

    @abstractmethod
    def enrich_processed_log_data(self, resultado):
        # "Enriquece" el resultado: limpia campos vacios y trata de
        # interpretar el primer campo como una fecha. Lo usan los patrones
        # antiguos basados en logs de Bro/Zeek.
        self.process_empty_log_data(resultado, self.dict_values)
        try:
            resultado[self.dict_values[0]] = self.get_date_from_int(resultado[self.dict_values[0]])
        except:
            print('posicion 0 no es date en long')

        return resultado

    @abstractmethod
    def process_empty_log_data(self, log_dict, log_list):
        # Normaliza los valores de cada campo:
        #   - '' o '-'         -> None        (campo ausente)
        #   - 't'/'true'...    -> True        (booleano verdadero)
        #   - 'f'/'false'...   -> False       (booleano falso)
        #   - un numero        -> int o float (si se puede convertir)
        # Asi los datos quedan tipados y no como simples cadenas de texto.
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
