from lectura_logs.PatronPadre import PatronPadre

class dnsPatron(PatronPadre):
    # Campos base de DNS: nombre de la consulta, tipo de consulta y nombre de la respuesta
    dict_values = ["qry_name", "qry_type", "resp_name"]

    def __init__(self, path_log):
        super().__init__('dns.log', path_log)

    def process_log_data(self, data_string):
        # Generamos la estructura base para guardar los datos
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Buscamos la capa 'dns' en el JSON crudo del sniffer
        if 'layers' in data_string and 'dns' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['dns']:
                    # Extraemos el valor bruto y le quitamos la basura de tshark
                    resultado[key] = data_string['layers']['dns'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        # Descartamos si no es un paquete DNS
        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
