from lectura_logs.PatronPadre import PatronPadre

class icmpPatron(PatronPadre):
    # Para el ping sacamos el tipo (8 es petición, 0 respuesta), el código y la secuencia
    dict_values = ["type", "code", "seq"]

    def __init__(self, path_log):
        super().__init__('icmp.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Interceptamos la capa ICMP
        if 'layers' in data_string and 'icmp' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['icmp']:
                    # Extraemos el dato numérico en bruto (Fase 1 pura)
                    resultado[key] = data_string['layers']['icmp'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
