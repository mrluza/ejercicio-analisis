from lectura_logs.PatronPadre import PatronPadre

class tlsPatron(PatronPadre):
    # Extraemos la versión de TLS, el tipo de saludo inicial y el nombre del servidor al que nos conectamos
    dict_values = ["record_version", "handshake_type", "handshake_extensions_server_name"]

    def __init__(self, path_log):
        super().__init__('tls.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Buscamos tráfico cifrado (HTTPS, puertos 443, etc.)
        if 'layers' in data_string and 'tls' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['tls']:
                    resultado[key] = data_string['layers']['tls'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
