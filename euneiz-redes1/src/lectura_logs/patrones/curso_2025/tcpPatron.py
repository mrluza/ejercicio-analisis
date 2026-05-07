from lectura_logs.PatronPadre import PatronPadre

class tcpPatron(PatronPadre):
    # Campos base de TCP: puertos origen/destino, secuencia y banderas (SYN, ACK...)
    dict_values = ["srcport", "dstport", "seq", "flags"]

    def __init__(self, path_log):
        super().__init__('tcp.log', path_log)

    def process_log_data(self, data_string):
        # Preparamos el diccionario de salida
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Comprobamos si la capa de transporte es TCP
        if 'layers' in data_string and 'tcp' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['tcp']:
                    # Limpieza básica obligatoria de tshark
                    resultado[key] = data_string['layers']['tcp'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        # Descartamos cualquier paquete que no use TCP
        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
