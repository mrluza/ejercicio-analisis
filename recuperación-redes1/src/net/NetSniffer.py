'''
Motor de captura del sniffer.

Usa pyshark (que por debajo llama a tshark, el de Wireshark) para escuchar una
interfaz de red y procesar cada paquete que pasa por ella.

Tiene dos modos:
  - solo_resumen = True  -> modo "explicativo": imprime por pantalla una
    descripcion de cada paquete, pero NO guarda nada en disco.
  - solo_resumen = False -> modo "captura": guarda cada paquete como una linea
    JSON en el fichero de salida.
'''
import pyshark
import json
import os
import time
import asyncio

# Colores para la salida de la consola.
R  = '\033[0m'
B  = '\033[1m'
DM = '\033[2m'
CY = '\033[96m'
GR = '\033[92m'
YL = '\033[93m'
MG = '\033[95m'
RD = '\033[91m'
BL = '\033[94m'

# Un color por cada capa, solo para que la salida en pantalla se lea mejor.
LAYER_COLOR = {
    'eth': BL, 'arp': BL,
    'ip': GR, 'ipv6': GR, 'icmp': GR,
    'tcp': YL, 'udp': YL,
    'dns': MG, 'http': MG, 'tls': MG,
    'imap': MG, 'ftp': MG, 'ssh': MG, 'smtp': MG,
}

def _load_json(path):
    # Carga un JSON (de la carpeta conf/) y lo devuelve como diccionario.
    with open(path, encoding='utf-8') as f:
        return json.load(f)

# Cargamos las descripciones de las capas y los significados de los tipos ICMP.
_conf_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'conf')
LAYER_INFO  = _load_json(os.path.join(_conf_dir, 'layer_info.json'))
ICMP_TYPES  = _load_json(os.path.join(_conf_dir, 'icmp_types.json'))


class NetSniffer(object):
    '''
    Clase que captura los paquetes de una red.
    '''

    # Carpeta donde se guardan las capturas.
    base_folder = '../captured_data/'

    def __init__(self, project_name, pattern_parser, interface, custome_filters='', solo_resumen=True):
        '''
        Constructor: guarda la configuracion y prepara la ruta de salida.
        '''
        # Nos aseguramos de que existe la carpeta de salida.
        os.makedirs(self.base_folder, exist_ok=True)
        # Fichero de salida: ../captured_data/<project_name>.json
        self.project_name = f'{self.base_folder}/{project_name}.json'

        # Interfaz(es) de red a escuchar.
        self.interfaces = interface
        # Modo: solo mostrar (True) o tambien guardar (False).
        self.solo_resumen = solo_resumen
        # Patron del protocolo elegido (icmp, arp, dns...).
        self.patron = pattern_parser
        # Filtro BPF opcional.
        self.filters = custome_filters

    def __add_fields_data(self, p, list_names, data_dict):
        # Copia en data_dict todos los campos 'list_names' de la capa 'p'
        # que tengan algun valor.
        for n in list_names:
            if n:
                field_data = getattr(p, n)
                if field_data:
                    data_dict[n] = field_data
        return data_dict

    def __describe_packet(self, packet):
        """Imprime un resumen explicativo de las capas del paquete."""
        # Reconstruimos la pila de capas (ej: eth -> ip -> icmp).
        layer_names = [l.layer_name for l in packet.layers]
        pila = ' → '.join(f'{LAYER_COLOR.get(n, R)}{n.upper()}{R}' for n in layer_names)
        print(f'\n  {B}Paquete capturado{R} | Pila: {pila}')

        # Recorremos cada capa y mostramos su descripcion y sus datos.
        for layer in packet.layers:
            name = layer.layer_name
            color = LAYER_COLOR.get(name, R)
            desc = LAYER_INFO.get(name, f'Capa desconocida: {name}')
            print(f'    {color}{B}[{name.upper():8}]{R} {desc}')

            # Anotaciones especificas por protocolo:
            # ICMP -> traducimos el numero de tipo a su significado.
            if name == 'icmp' and hasattr(layer, 'type'):
                tipo = str(layer.type)
                significado = ICMP_TYPES.get(tipo, 'Tipo no común')
                print(f'             {GR}→ Tipo ICMP {B}{tipo}{R}{GR}: {significado}{R}')

            # IP -> mostramos origen → destino y el TTL.
            if name == 'ip' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                ttl = getattr(layer, 'ttl', '?')
                print(f'             {GR}→ {B}{layer.src}{R}{GR} → {B}{layer.dst}{R}{GR}  (TTL: {ttl}){R}')

            # Ethernet -> mostramos las MAC origen y destino.
            if name == 'eth' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                print(f'             {BL}→ MAC src: {B}{layer.src}{R}{BL}  |  MAC dst: {B}{layer.dst}{R}')

            # TCP -> puertos y flags (SYN, ACK...).
            if name == 'tcp' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                flags = getattr(layer, 'flags_str', '')
                print(f'             {YL}→ Puerto {B}{layer.srcport}{R}{YL} → {B}{layer.dstport}{R}{YL}  flags: {flags}{R}')

            # UDP -> solo los puertos.
            if name == 'udp' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                print(f'             {YL}→ Puerto {B}{layer.srcport}{R}{YL} → {B}{layer.dstport}{R}')

            # DNS -> el nombre consultado.
            if name == 'dns' and hasattr(layer, 'qry_name'):
                print(f'             {MG}→ Consulta DNS: {B}{layer.qry_name}{R}')

            # IMAP -> aviso de que el comando viaja sin cifrar.
            if name == 'imap' and hasattr(layer, 'request_command'):
                print(f'             {RD}{B}⚠️  Comando IMAP visible: {layer.request_command}{R}')

            print(f'          {DM}Datos de la capa:{R}')
            layer.pretty_print()

        print(f'  {DM}{"─" * 56}{R}')

    def __capture_resume(self, capture):
        # MODO EXPLICATIVO: escucha la red y describe cada paquete. No guarda.
        print(f'\n  {CY}Escuchando la red.{R} Cada bloque es un paquete capturado.')
        print(f'  Pulsa {YL}Ctrl+C{R} para detener la captura.')
        time.sleep(10)
        print(f'  {DM}{"─" * 56}{R}')

        for packet in capture.sniff_continuously():
            self.__describe_packet(packet)

    def __capture_all(self, capture):
        # MODO CAPTURA: por cada paquete construimos un diccionario con TODAS
        # sus capas y campos, lo pasamos por el patron y, si el patron lo
        # acepta, lo guardamos en el JSON.
        for packet in capture.sniff_continuously():
            data_dict = {'layers': {}}

            # 1) Metadatos de la trama (numero, tiempo, longitud...).
            frame_info = packet.frame_info
            for frame_field in frame_info.field_names:
                data_dict[frame_field] = getattr(frame_info, frame_field)

            # 2) Recorremos TODAS las capas y guardamos cada una bajo
            #    data_dict['layers'][nombre_capa]. Gracias a esto, aunque el
            #    patron sea 'icmp', el diccionario tambien tiene la capa 'ip'
            #    y la 'eth' -> de ahi salen las IP/MAC para la grafica de nodos.
            available_layers = packet.layers
            for l in available_layers:
                layer_data = {'layer_name': l.layer_name}
                data_dict['layers'][l.layer_name] = layer_data
                self.__add_fields_data(l, l.field_names, layer_data)

                # Algunas capas pueden aparecer repetidas (sub-capas).
                ml = packet.get_multiple_layers(l.layer_name)
                for ml_tmp in ml:
                    if ml_tmp.layer_name != l.layer_name:
                        sub_layer_data = {'sub_layer_name': ml_tmp.layer_name}
                        layer_data['layer_' + str(l.layer_name)] = sub_layer_data
                        self.__add_fields_data(l, l.field_names, layer_data)
                        self.__add_fields_data(ml_tmp, ml_tmp.field_names, sub_layer_data)

            # 3) El patron decide que se queda (o devuelve None si no interesa).
            data_dict = self.patron.process_log_data(data_dict)

            # 4) Si hay datos, los guardamos.
            if data_dict:
                self.__write_new_packet_data(data_dict)

    def __write_new_packet_data(self, packet_data):
        # Guarda el paquete como una linea JSON al final del fichero.
        with open(self.project_name, 'a') as archivo:
            json.dump(packet_data, archivo)
            archivo.write('\n')

        # Ademas imprime un resumen con los primeros 4 campos (no vacios y
        # que no sean db_name / layer_name), para no saturar la pantalla.
        campos = {k: v for k, v in packet_data.items() if v and k not in ('db_name', 'layer_name')}
        resumen = '  |  '.join(f'{CY}{k}{R}: {YL}{v}{R}' for k, v in list(campos.items())[:4])
        print(f'  {GR}{B}[GUARDADO]{R} {resumen}')

    def __init_capture(self):
        # Prepara y arranca la captura con pyshark.

        # Esto silencia un error inofensivo (EOFError) que pyshark lanza al
        # cerrar tshark con Ctrl+C.
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        loop.set_exception_handler(
            lambda lp, ctx: None if isinstance(ctx.get('exception'), EOFError)
            else lp.default_exception_handler(ctx)
        )

        # Captura en vivo sobre la(s) interfaz(es), con el filtro BPF indicado.
        capture = pyshark.LiveCapture(
            interface=self.interfaces,
            bpf_filter=self.filters
        )

        # Elegimos el modo segun la configuracion.
        if self.solo_resumen:
            self.__capture_resume(capture)
        else:
            self.__capture_all(capture)

    def comenzar(self):
        # Punto de entrada: imprime la cabecera y lanza la captura.
        sep = f'{CY}{"─" * 60}{R}'
        print(f'\n{sep}')
        print(f'  {B}{CY}¿QUÉ ES UN SNIFFER?{R}')
        print(f'  Un sniffer (o analizador de paquetes) captura el tráfico')
        print(f'  que circula por una interfaz de red. Permite inspeccionar')
        print(f'  los protocolos y datos de cada comunicación en tiempo real.')
        print(f'{sep}')
        print(f'  {CY}Interfaz escuchada{R} : {YL}{B}{", ".join(self.interfaces)}{R}')
        print(f'  {DM}(la interfaz es el adaptador de red físico o virtual que recibe los paquetes){R}')
        filtro = self.filters if self.filters else f'{DM}ninguno — se captura todo el tráfico{R}'
        print(f'  {CY}Filtro BPF activo{R}  : {YL}{filtro}{R}')
        print(f'  {DM}(BPF = Berkeley Packet Filter, permite acotar qué paquetes capturar){R}')
        print(f'  {CY}Datos guardados en{R} : {GR}{self.project_name}{R}')
        print(f'{sep}\n')
        try:
            self.__init_capture()
        except KeyboardInterrupt:
            # Ctrl+C: cerramos limpiamente e indicamos donde estan los datos.
            print(f'\n\n{sep}')
            print(f'  {YL}{B}Captura detenida por el usuario.{R}')
            print(f'  {DM}Los paquetes capturados están guardados en:{R}')
            print(f'  {GR}{self.project_name}{R}')
            print(f'{sep}\n')
