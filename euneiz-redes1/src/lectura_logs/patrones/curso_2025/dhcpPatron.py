from lectura_logs.PatronPadre import PatronPadre

class dhcpPatron(PatronPadre):
    # Extraemos el tipo de mensaje DHCP, el ID de transacción y la MAC del dispositivo
    dict_values = ["type", "id", "hw.mac_addr"]

    def __init__(self, path_log):
        super().__init__('dhcp.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        has_data = False

        # Buscamos la capa DHCP (a veces aparece como 'bootp' en tshark, pero lo intentamos con dhcp)
        if 'layers' in data_string and 'dhcp' in data_string['layers']:
            for key in resultado.keys():
                if key in data_string['layers']['dhcp']:
                    resultado[key] = data_string['layers']['dhcp'][key].replace('LayerFieldsContainer:', '').strip()
                    has_data = True

        if not has_data: 
            return None
            
        resultado['db_name'] = self.tipo
        return resultado
