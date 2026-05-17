# Sniffer modificado — Captura completa de campos

Este proyecto es el sniffer de la Practica de Redes 1, modificado para que
los 8 protocolos capturen TODOS los campos de cada paquete, en lugar de solo
unos pocos campos seleccionados.


## Que se ha cambiado

Antes, cada patron (httpPatron, icmpPatron...) tenia una lista llamada
'dict_values' con unos pocos campos, y solo guardaba esos. El resto de
informacion del paquete se descartaba.

Ahora los patrones capturan la capa completa del protocolo, con todos sus
campos. La logica se ha centralizado en la clase PatronPadre, en un metodo
nuevo llamado extraer_todo(). Cada patron hijo se ha simplificado: solo
declara cual es su capa (layer_name) y delega el trabajo en PatronPadre.

Protocolos afectados (los 8 de la practica):
  arp, dns, tcp, http, dhcp, icmp, tls, mdns

Tambien se ha adaptado imapPatron por coherencia, aunque IMAP no es uno de
los protocolos pedidos.


## Archivos modificados

  src/lectura_logs/PatronPadre.py                      (metodo extraer_todo)
  src/lectura_logs/patrones/curso_2025/arpPatron.py
  src/lectura_logs/patrones/curso_2025/dnsPatron.py
  src/lectura_logs/patrones/curso_2025/tcpPatron.py
  src/lectura_logs/patrones/curso_2025/httpPatron.py
  src/lectura_logs/patrones/curso_2025/dhcpPatron.py
  src/lectura_logs/patrones/curso_2025/icmpPatron.py
  src/lectura_logs/patrones/curso_2025/tlsPatron.py
  src/lectura_logs/patrones/curso_2025/mdnsPatron.py
  src/lectura_logs/patrones/curso_2025/imapPatron.py
  conf/conf.ini                                        (config lista para usar)

El resto de archivos del proyecto (MAIN.py, NetSniffer.py, connPatron.py,
pcapLivePatron.py, etc.) NO se han tocado: siguen funcionando igual.


## Como capturar

1. Edita conf/conf.ini:
   - log_type: pon el protocolo (arp, dns, tcp, http, dhcp, icmp, tls, mdns).
   - net_sniffer_interface: pon el nombre real de tu interfaz de red
     (en Linux, mira el comando  ip a ).
   - net_summarize: debe estar en false (si no, no guarda nada).
   - net_custome_filters (opcional): filtro BPF para capturar solo el
     protocolo que te interesa, p. ej. 'tcp port 80', 'icmp', 'arp'.

2. Ejecuta el sniffer (lanzar.sh o como lo hagas habitualmente).

3. Genera trafico del protocolo que estes capturando.

4. Detiene la captura con Ctrl+C cuando tengas mas de 200 paquetes.

5. El resultado queda en captured_data/<project_name>.json
   Cada linea del JSON tendra todos los campos de la capa del protocolo.


## Comprobacion

Para ver todos los campos distintos que han aparecido en una captura:

    python3 -c "import json; c=set();
    [c.update(json.loads(l)) for l in open('captured_data/ikasle.json')];
    print(sorted(c))"
