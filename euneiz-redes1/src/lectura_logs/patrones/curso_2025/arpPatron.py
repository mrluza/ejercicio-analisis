# Importamos la clase principal de la que heredan todos los patrones
from lectura_logs.PatronPadre import PatronPadre

class arpPatron(PatronPadre):
    # Lista de los campos exactos que queremos extraer del motor de tshark
    dict_values = ["opcode", "src.hw_mac", "dst.hw_mac"]

    def __init__(self, path_log):
        # Inicializamos la clase padre indicándole cómo se llamará el archivo JSON de salida
        super().__init__('arp.log', path_log)

    def process_log_data(self, data_string):
        # Creamos un diccionario base usando los valores de dict_values (todos empiezan vacíos/None)
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Comprobamos si el paquete capturado contiene la capa 'arp'
        if 'layers' in data_string and 'arp' in data_string['layers']:
            # Recorremos cada campo que hemos pedido en dict_values
            for key in resultado.keys():
                # Si ese campo existe dentro de la capa ARP del paquete...
                if key in data_string['layers']['arp']:
                    # Lo guardamos y limpiamos el texto 'LayerFieldsContainer:' que mete tshark por defecto
                    resultado[key] = data_string['layers']['arp'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        # Si el paquete no tenía datos de ARP, devolvemos None para no guardarlo
        if not has_data: 
            return None
            
        # Añadimos el nombre del log como identificador final y devolvemos el paquete
        resultado['db_name'] = self.tipo
        return resultado
