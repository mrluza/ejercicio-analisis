import json
from pathlib import Path

# ==========================================
# EJERCICIO DE TRANSFORMACIÓN - REDES I
# ==========================================
#
# Este script filtra únicamente los campos
# seleccionados en el ejercicio de filtrado.
#
# Además, renombra los campos utilizando
# nombres más descriptivos para facilitar
# el análisis posterior.
#
# ==========================================

BASE_PATH = Path(".")

# ==========================================
# CONFIGURACIÓN DE CAMPOS FILTRADOS
# ==========================================

FILTERS = {
    "arp": {
        "opcode": "operation_code",
        "src_hw_mac": "source_mac",
        "dst_hw_mac": "destination_mac"
    },

    "dns": {
        "qry_name": "query_name",
        "qry_type": "query_type",
        "resp_name": "response_name"
    },

    "tcp": {
        "srcport": "source_port",
        "dstport": "destination_port",
        "seq": "sequence_number",
        "flags": "tcp_flags"
    },

    "http": {
        "request_method": "http_method",
        "host": "host",
        "request_uri": "resource_uri",
        "response_code": "response_code"
    },

    "dhcp": {
        "type": "message_type",
        "id": "transaction_id",
        "hw_mac_addr": "client_mac"
    },

    "icmp": {
        "type": "icmp_type",
        "code": "icmp_code",
        "seq": "sequence_number"
    },

    "tls": {
        "handshake_type": "handshake_type",
        "handshake_version": "tls_version",
        "handshake_ciphersuite": "cipher_suite",
        "handshake_extensions_server_name": "server_name"
    },

    "mdns": {
        "dns_qry_name": "query_name",
        "dns_qry_type": "query_type",
        "dns_resp_name": "response_name"
    }
}

# ==========================================
# ARCHIVOS DE ENTRADA
# ==========================================

INPUT_FILES = {
    "arp": "captura_arp.json",
    "dns": "captura_dns.json",
    "tcp": "captura_tcp.json",
    "http": "captura_http.json",
    "dhcp": "captura_dhcp.json",
    "icmp": "captura_icmp.json",
    "tls": "captura_tls.json",
    "mdns": "captura_mdns.json"
}

# ==========================================
# DIRECTORIO DE SALIDA
# ==========================================

OUTPUT_DIR = BASE_PATH / "salida_filtrada"
OUTPUT_DIR.mkdir(exist_ok=True)

# ==========================================
# FUNCIÓN DE FILTRADO
# ==========================================

def process_protocol(protocol_name, filename):
    input_path = BASE_PATH / filename

    if not input_path.exists():
        print(f"[ERROR] Archivo no encontrado: {filename}")
        return

    filtered_packets = []

    with open(input_path, "r", encoding="utf-8") as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                packet = json.loads(line)
            except json.JSONDecodeError:
                continue

            filtered_packet = {}

            for original_field, renamed_field in FILTERS[protocol_name].items():

                if original_field in packet:
                    filtered_packet[renamed_field] = packet[original_field]

            if filtered_packet:
                filtered_packets.append(filtered_packet)

    output_file = OUTPUT_DIR / f"{protocol_name}_filtrado.json"

    with open(output_file, "w", encoding="utf-8") as outfile:
        json.dump(filtered_packets, outfile, indent=4)

    print(f"[OK] {protocol_name.upper()} procesado -> {output_file}")

# ==========================================
# EJECUCIÓN PRINCIPAL
# ==========================================

def main():

    print("========================================")
    print(" SNIFFER - TRANSFORMACIÓN DE CAMPOS ")
    print("========================================")

    for protocol, filename in INPUT_FILES.items():
        process_protocol(protocol, filename)

    print("\nProceso completado correctamente.")

# ==========================================
# INICIO
# ==========================================

if __name__ == "__main__":
    main()
