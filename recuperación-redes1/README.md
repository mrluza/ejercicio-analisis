# recuperación-redes1 - Sniffer de Red

Práctica de captura y análisis de tráfico de red en tiempo real para el Grado en Seguridad de EUNEIZ.

El sniffer captura paquetes de una interfaz de red, los procesa según el protocolo elegido y los guarda en un fichero JSON local. Entre los campos guardados están los datos necesarios para construir después la **gráfica de nodos** de la red.

---

## Requisitos previos

- **Linux** (Ubuntu/Debian recomendado).
- **Python 3.8+** → `sudo apt install python3`
- **tshark** (motor de captura) → `sudo apt install tshark`
- **uv** (gestor de entorno) → `curl -LsSf https://astral.sh/uv/install.sh | sh`

Durante la instalación de `tshark`, responde **Sí** a que los usuarios sin privilegios puedan capturar. Si no, añade tu usuario al grupo `wireshark`:

```bash
sudo usermod -aG wireshark $USER
# Cierra sesión y vuelve a entrar para que el cambio surta efecto
tshark -D   # debe listar las interfaces sin errores
```

---

## Instalación

```bash
# 1. Copia el fichero de configuración de ejemplo
cp conf/conf_tmp.ini conf/conf.ini

# 2. Instala las dependencias con uv (crea el entorno .venv automáticamente)
uv sync
```

---

## Configuración

Edita `conf/conf.ini`. Es la única fuente de configuración.

```ini
[GlobalConfig]
debug_mode: true              # información detallada por consola

[App]
project_name: captura_mdns    # nombre del fichero JSON de salida
log_type: mdns                # protocolo a capturar (ver tabla)
net_sniffer_interface: eth0   # interfaz de red a escuchar
net_summarize: false          # false = GUARDA en JSON ; true = solo muestra
net_custome_filters:          # filtro BPF opcional (vacío = captura todo)
```

Para saber el nombre de tu interfaz: `tshark -D` o `ip link show`.

### Patrones disponibles (`log_type`)

| Valor       | Protocolo | Capa OSI |
|-------------|-----------|----------|
| `conn`      | Ethernet (MACs) | Capa 2 |
| `arp`       | ARP       | Capa 2 |
| `icmp`      | ICMP (ping) | Capa 3 |
| `tcp`       | TCP       | Capa 4 |
| `dns`       | DNS       | Capa 7 |
| `http`      | HTTP      | Capa 7 |
| `dhcp`      | DHCP      | Capa 7 |
| `tls`       | TLS       | Capa 6 |
| `mdns`      | mDNS      | Capa 7 |
| `pcap_live` | Genérico (todas las capas) | 2–7 |

---

## Lanzar la captura

```bash
# Forma rápida
./lanzar.sh

# Forma manual
uv run python src/MAIN.py
```

Para detener: `Ctrl + C`.

Los paquetes se guardan, una línea JSON por paquete, en `captured_data/<project_name>.json`.

---

## Datos para la gráfica de nodos

El sniffer NO dibuja ninguna gráfica: solo deja en el JSON los datos que se necesitan para construirla. En cada paquete se añaden tres campos:

| Campo       | Significado |
|-------------|-------------|
| `topo_src`  | Identificador del que envía (IP o MAC) |
| `topo_dst`  | Identificador del que recibe (IP o MAC) |
| `topo_tipo` | `ip` o `mac`, según el tipo de identificador |

Estos campos se rellenan automáticamente en `PatronPadre.extraer_todo()`. La lógica decide de qué capa sacarlos: para **ICMP/TCP/HTTP/DNS/TLS/mDNS** usa las IP de la capa `ip`; para **ARP** usa las MAC de la capa `arp`; si no hay IP, recurre a las MAC de Ethernet.

Con esos campos ya tienes todo lo necesario para montar tú la gráfica de nodos: cada **nodo** es un host (un valor distinto de `topo_src` / `topo_dst`) y cada **arista** es una comunicación (un par origen→destino). Para ICMP saldrán las IP que se hacen ping; para ARP, las MAC; etc.

Ejemplo de línea capturada con el patrón `icmp`:

```json
{
  "layer_name": "icmp",
  "type": "8",
  "code": "0",
  "seq": "1",
  "topo_src": "10.0.2.15",
  "topo_dst": "8.8.8.8",
  "topo_tipo": "ip",
  "db_name": "icmp.log"
}
```

---

## Estructura del proyecto

```
recuperación-redes1/
├── conf/
│   ├── conf.ini              # Tu configuración
│   ├── conf_tmp.ini          # Plantilla
│   ├── patron_info.json      # Descripciones de cada protocolo
│   ├── layer_info.json       # Descripciones de capas OSI
│   └── icmp_types.json       # Significado de los tipos ICMP
├── src/
│   ├── MAIN.py               # Punto de entrada
│   ├── net/NetSniffer.py     # Motor de captura (pyshark)
│   ├── utils/ConfigReader.py # Lectura del conf.ini
│   └── lectura_logs/
│       ├── PatronPadre.py    # Clase base de los patrones (+ campos topo_*)
│       └── patrones/
│           ├── connPatron.py
│           ├── pcapLivePatron.py
│           └── curso_2025/   # arp, dns, tcp, http, dhcp, icmp, tls, mdns
├── lanzar.sh                 # Script de arranque
└── pyproject.toml            # Dependencias (solo pyshark)
```

---

## Añadir un nuevo patrón

1. Crea un fichero en `src/lectura_logs/patrones/curso_2025/` que herede de `PatronPadre`.
2. Define `layer_name` con el nombre de la capa (ej: `'dns'`).
3. Implementa `process_log_data()` devolviendo `self.extraer_todo(data_string)`.
4. Regístralo en el diccionario `logs_patterns_types` de `src/MAIN.py`.
5. Usa su nombre como valor de `log_type` en `conf.ini`.
