from lectura_logs.PatronPadre import PatronPadre

class mdnsPatron(PatronPadre):
    # mDNS funciona igual que DNS, sacamos nombre consultado y respuesta
    dict_values = ["qry_name", "resp_name"]

    def __init__(self, path_log):
        super().__init__('mdns.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Buscamos tráfico mDNS (Multicast DNS) típico de redes locales
        if 'layers' in data_string and 'mdns' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['mdns']:
                    resultado[key] = data_string['layers']['mdns'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
