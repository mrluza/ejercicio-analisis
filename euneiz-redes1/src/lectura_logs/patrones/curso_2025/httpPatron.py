from lectura_logs.PatronPadre import PatronPadre

class httpPatron(PatronPadre):
    # Extraemos el método, el dominio, la ruta de la web y el código de estado (ej: 200, 404)
    dict_values = ["request_method", "host", "request_uri", "response_code"]

    def __init__(self, path_log):
        super().__init__('http.log', path_log)

    def process_log_data(self, data_string):
        # Preparamos el recolector de datos
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Si el paquete es HTTP (texto plano)...
        if 'layers' in data_string and 'http' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['http']:
                    # Guardamos el valor capturado tal cual (Fase 1)
                    resultado[key] = data_string['layers']['http'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        # Fase 1 estricta: Si no tiene NINGÚN dato de la capa HTTP, lo tiramos
        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
