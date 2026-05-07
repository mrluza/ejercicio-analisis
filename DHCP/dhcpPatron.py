from lectura_logs.PatronPadre import PatronPadre

class dhcpPatron(PatronPadre):

    dict_values = [
        "type",
        "id",
        "ip_client",
        "ip_your",
        "ip_server",
        "hw_mac_addr",
        "option_hostname"
    ]

    def __init__(self, path_log):
        super().__init__('dhcp.log', path_log)

    def process_log_data(self, data_string):

        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)

        resultado['db_name'] = self.tipo

        has_data = False

        if 'layers' in data_string:

            if 'dhcp' in data_string['layers']:

                for x in resultado.keys():

                    if x in data_string['layers']['dhcp']:

                        resultado[x] = data_string['layers']['dhcp'][x] \
                            .replace('LayerFieldsContainer:', '').strip()

                        has_data = True

        if not has_data:
            resultado = None

        return resultado
