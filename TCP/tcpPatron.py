from lectura_logs.PatronPadre import PatronPadre

class tcpPatron(PatronPadre):

    dict_values = [
        "srcport",
        "dstport",
        "seq",
        "ack",
        "flags",
        "window_size",
        "len"
    ]

    def __init__(self, path_log):
        super().__init__('tcp.log', path_log)

    def process_log_data(self, data_string):

        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)

        resultado['db_name'] = self.tipo

        has_data = False

        if 'layers' in data_string:

            if 'tcp' in data_string['layers']:

                for x in resultado.keys():

                    if x in data_string['layers']['tcp']:

                        resultado[x] = data_string['layers']['tcp'][x] \
                            .replace('LayerFieldsContainer:', '').strip()

                        has_data = True

        if not has_data:
            resultado = None

        return resultado
